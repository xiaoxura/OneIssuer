package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// FindLoginSession resolves a server-side principal by session-token digest.
func (s *Store) FindLoginSession(ctx context.Context, tokenHash []byte) (session.Principal, error) {
	row, err := s.queries.GetLoginSessionByTokenHash(ctx, tokenHash)
	if isNoRows(err) {
		return session.Principal{}, session.ErrNotFound
	}
	if err != nil {
		return session.Principal{}, wrapError("find login session", ErrorKindQuery, err)
	}
	return mapPrincipal(row), nil
}

// TouchLoginSession advances bounded activity and idle expiry timestamps.
func (s *Store) TouchLoginSession(ctx context.Context, id uuid.UUID, lastSeen, idleExpires time.Time) error {
	if err := s.queries.TouchLoginSession(ctx, sqlcgen.TouchLoginSessionParams{
		LastSeenAt: timestamp(lastSeen), IdleExpiresAt: timestamp(idleExpires), ID: id,
	}); err != nil {
		return wrapError("touch login session", ErrorKindQuery, err)
	}
	return nil
}

// RotateSessionCSRF replaces a session's CSRF digest and expiry.
func (s *Store) RotateSessionCSRF(ctx context.Context, id uuid.UUID, hash []byte, expires time.Time) error {
	if err := s.queries.RotateLoginSessionCSRF(ctx, sqlcgen.RotateLoginSessionCSRFParams{
		CsrfHash: hash, CsrfExpiresAt: timestamp(expires), ID: id,
	}); err != nil {
		return wrapError("rotate session CSRF", ErrorKindQuery, err)
	}
	return nil
}

// ListUserSessions returns only a selected user's session summaries.
func (s *Store) ListUserSessions(ctx context.Context, userID uuid.UUID, cursor pagination.Cursor, limit int) ([]session.Summary, error) {
	rows, err := s.queries.ListUserLoginSessions(ctx, sqlcgen.ListUserLoginSessionsParams{
		UserID: userID, CursorTime: cursorTimestamp(cursor.Time), CursorID: cursor.ID, PageLimit: postgresPageLimit(limit),
	})
	if err != nil {
		return nil, wrapError("list user sessions", ErrorKindQuery, err)
	}
	result := make([]session.Summary, 0, len(rows))
	for _, row := range rows {
		result = append(result, session.Summary{
			ID: row.ID, UserID: row.UserID, CreatedAt: requiredTime(row.CreatedAt), LastSeenAt: requiredTime(row.LastSeenAt),
			AuthenticatedAt: requiredTime(row.AuthenticatedAt), ExpiresAt: requiredTime(row.ExpiresAt),
			IdleExpiresAt: requiredTime(row.IdleExpiresAt), RevokedAt: optionalTime(row.RevokedAt),
			RevokeReason: valueString(row.RevokeReason), IPPrefix: valueString(row.IpPrefix),
		})
	}
	return result, nil
}

// RevokeUserSession revokes an owned session and appends audit atomically.
func (s *Store) RevokeUserSession(ctx context.Context, userID, target uuid.UUID, now time.Time, event audit.Event) error {
	return s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		_, err := queries.RevokeLoginSessionForUser(ctx, sqlcgen.RevokeLoginSessionForUserParams{
			RevokedAt: timestamp(now), RevokeReason: pointerString("user"), ID: target, UserID: userID,
		})
		if isNoRows(err) {
			return session.ErrNotFound
		}
		if err != nil {
			return wrapError("revoke user session", ErrorKindQuery, err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// RevokeOtherUserSessions preserves the current session while revoking peers.
func (s *Store) RevokeOtherUserSessions(ctx context.Context, userID, currentSession uuid.UUID, now time.Time, event audit.Event) (int64, error) {
	var count int64
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		ids, err := queries.RevokeOtherLoginSessions(ctx, sqlcgen.RevokeOtherLoginSessionsParams{
			RevokedAt: timestamp(now), UserID: userID, CurrentSessionID: currentSession,
		})
		if err != nil {
			return wrapError("revoke other user sessions", ErrorKindQuery, err)
		}
		if err := insertAudit(ctx, queries, event); err != nil {
			return err
		}
		count = int64(len(ids))
		return nil
	})
	return count, err
}

// RevokeSessionByHash revokes the cookie-selected session and appends audit.
func (s *Store) RevokeSessionByHash(ctx context.Context, hash []byte, now time.Time, reason string, event audit.Event) error {
	return s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		_, err := queries.RevokeLoginSessionByHash(ctx, sqlcgen.RevokeLoginSessionByHashParams{
			RevokedAt: timestamp(now), RevokeReason: pointerString(reason), TokenHash: hash,
		})
		if isNoRows(err) {
			return session.ErrNotFound
		}
		if err != nil {
			return wrapError("revoke login session", ErrorKindQuery, err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// CleanupSessions removes expired pre-auth state and retired sessions beyond retention.
func (s *Store) CleanupSessions(ctx context.Context, preAuthCutoff, retiredCutoff time.Time) (int64, error) {
	var count int64
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		preauth, err := queries.DeleteExpiredPreAuthSessions(ctx, timestamp(preAuthCutoff))
		if err != nil {
			return wrapError("clean pre-auth sessions", ErrorKindQuery, err)
		}
		login, err := queries.DeleteRetiredLoginSessions(ctx, timestamp(retiredCutoff))
		if err != nil {
			return wrapError("clean login sessions", ErrorKindQuery, err)
		}
		count = preauth + login
		return nil
	})
	return count, err
}

// CountActiveSessions supports the low-cardinality active-session gauge.
func (s *Store) CountActiveSessions(ctx context.Context, now time.Time) (int64, error) {
	count, err := s.queries.CountActiveLoginSessions(ctx, timestamp(now))
	if err != nil {
		return 0, wrapError("count active login sessions", ErrorKindQuery, err)
	}
	return count, nil
}

func createLoginSession(ctx context.Context, queries *sqlcgen.Queries, record session.Record) error {
	var ipPrefix *string
	if record.IPPrefix != "" {
		ipPrefix = pointerString(record.IPPrefix)
	}
	if err := queries.CreateLoginSession(ctx, sqlcgen.CreateLoginSessionParams{
		ID: record.ID, UserID: record.UserID, TokenHash: record.TokenHash, CsrfHash: record.CSRFHash,
		CsrfExpiresAt: timestamp(record.CSRFExpiresAt), CreatedAt: timestamp(record.CreatedAt),
		LastSeenAt: timestamp(record.LastSeenAt), AuthenticatedAt: timestamp(record.AuthenticatedAt),
		ExpiresAt: timestamp(record.ExpiresAt), IdleExpiresAt: timestamp(record.IdleExpiresAt),
		UserAgentHash: record.UserAgentHash, IpPrefix: ipPrefix,
	}); err != nil {
		return wrapError("create login session", ErrorKindQuery, err)
	}
	return nil
}

func createPreAuthSession(ctx context.Context, queries *sqlcgen.Queries, record session.PreAuthRecord) error {
	if err := queries.CreatePreAuthSession(ctx, sqlcgen.CreatePreAuthSessionParams{
		ID: record.ID, TokenHash: record.TokenHash, CsrfHash: record.CSRFHash,
		AuthTransactionID: record.AuthTransactionID, CreatedAt: timestamp(record.CreatedAt), ExpiresAt: timestamp(record.ExpiresAt),
	}); err != nil {
		return wrapError("create pre-auth session", ErrorKindQuery, err)
	}
	return nil
}

func mapPrincipal(row sqlcgen.GetLoginSessionByTokenHashRow) session.Principal {
	return session.Principal{
		SessionID: row.ID,
		User: identity.User{
			ID: row.UserID, Subject: row.Subject, Username: row.Username, DisplayName: row.DisplayName,
			Email: row.Email, EmailVerified: row.EmailVerified, Status: identity.Status(row.UserStatus),
			Role: identity.Role(row.UserRole), CreatedAt: requiredTime(row.UserCreatedAt),
			UpdatedAt: requiredTime(row.UserUpdatedAt), Version: requiredTime(row.UserUpdatedAt), LastLoginAt: optionalTime(row.UserLastLoginAt),
		},
		CSRFHash: row.CsrfHash, CSRFExpiresAt: requiredTime(row.CsrfExpiresAt),
		CreatedAt: requiredTime(row.CreatedAt), LastSeenAt: requiredTime(row.LastSeenAt),
		AuthenticatedAt: requiredTime(row.AuthenticatedAt), ExpiresAt: requiredTime(row.ExpiresAt),
		IdleExpiresAt: requiredTime(row.IdleExpiresAt), RevokedAt: optionalTime(row.RevokedAt),
	}
}
