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
	return s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		sessionRow, err := queries.LockLoginSessionByID(ctx, target)
		if isNoRows(err) {
			return session.ErrNotFound
		}
		if err != nil {
			return wrapError("lock user session for revocation", ErrorKindQuery, err)
		}
		if sessionRow.UserID != userID || sessionRow.RevokedAt.Valid {
			return session.ErrNotFound
		}
		if err := revokeSessionBindingCascade(ctx, queries, sessionRow.SessionBindingID, now, "session_revoked"); err != nil {
			return err
		}
		if _, err := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
			RevokedAt: timestamp(now), RevokeReason: pointerString("user"), ID: target,
		}); isNoRows(err) {
			return session.ErrNotFound
		} else if err != nil {
			return wrapError("revoke user session", ErrorKindQuery, err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// RevokeOtherUserSessions preserves the current session while revoking peers.
func (s *Store) RevokeOtherUserSessions(ctx context.Context, userID, currentSession uuid.UUID, now time.Time, event audit.Event) (int64, error) {
	var count int64
	err := s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		rows, err := queries.LockActiveLoginSessionsByUser(ctx, userID)
		if err != nil {
			return wrapError("lock other user sessions", ErrorKindQuery, err)
		}
		bindingIDs := make([]uuid.UUID, 0, len(rows))
		for _, row := range rows {
			if row.ID == currentSession {
				continue
			}
			bindingIDs = append(bindingIDs, row.SessionBindingID)
		}
		if err := revokeSessionBindingsCascade(ctx, queries, bindingIDs, now, "session_revoked"); err != nil {
			return err
		}
		for _, row := range rows {
			if row.ID == currentSession {
				continue
			}
			if _, err := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
				RevokedAt: timestamp(now), RevokeReason: pointerString("others"), ID: row.ID,
			}); err != nil {
				return wrapError("revoke other user session", ErrorKindQuery, err)
			}
			count++
		}
		if err := insertAudit(ctx, queries, event); err != nil {
			return err
		}
		return nil
	}, func() { count = 0 })
	return count, err
}

// RevokeSessionByHash revokes the cookie-selected session and appends audit.
func (s *Store) RevokeSessionByHash(ctx context.Context, hash []byte, now time.Time, reason string, event audit.Event) error {
	return s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		row, err := queries.LockLoginSessionByTokenHash(ctx, hash)
		if isNoRows(err) {
			return session.ErrNotFound
		}
		if err != nil {
			return wrapError("lock login session", ErrorKindQuery, err)
		}
		if row.RevokedAt.Valid {
			return session.ErrNotFound
		}
		if err := revokeSessionBindingCascade(ctx, queries, row.SessionBindingID, now, "session_revoked"); err != nil {
			return err
		}
		if _, err := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
			RevokedAt: timestamp(now), RevokeReason: pointerString(reason), ID: row.ID,
		}); isNoRows(err) {
			return session.ErrNotFound
		} else if err != nil {
			return wrapError("revoke login session", ErrorKindQuery, err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// revokeSessionBindingCascade is the shared explicit-session authority boundary.
// Callers must already hold every target Session row lock; this helper then locks
// families and live Access metadata in UUID order before changing either table.
func revokeSessionBindingCascade(ctx context.Context, queries *sqlcgen.Queries, bindingID uuid.UUID, now time.Time, familyReason string) error {
	if bindingID == uuid.Nil || now.IsZero() {
		return session.ErrNotFound
	}
	return revokeSessionBindingsCascade(ctx, queries, []uuid.UUID{bindingID}, now, familyReason)
}

// revokeSessionBindingsCascade globally orders token locks across all bindings.
// Callers must hold every target Session row lock before entering this helper.
func revokeSessionBindingsCascade(ctx context.Context, queries *sqlcgen.Queries, bindingIDs []uuid.UUID, now time.Time, familyReason string) error {
	unique := make([]uuid.UUID, 0, len(bindingIDs))
	seen := make(map[uuid.UUID]struct{}, len(bindingIDs))
	for _, bindingID := range bindingIDs {
		if bindingID == uuid.Nil {
			continue
		}
		if _, exists := seen[bindingID]; exists {
			continue
		}
		seen[bindingID] = struct{}{}
		unique = append(unique, bindingID)
	}
	if len(unique) == 0 {
		return nil
	}
	if now.IsZero() {
		return session.ErrNotFound
	}
	if _, err := queries.LockUnrevokedRefreshTokenFamiliesByBindings(ctx, unique); err != nil {
		return wrapError("lock session refresh families", ErrorKindQuery, err)
	}
	if _, err := queries.LockLiveAccessTokensByBindings(ctx, sqlcgen.LockLiveAccessTokensByBindingsParams{
		SessionBindingIds: unique, Now: timestamp(now),
	}); err != nil {
		return wrapError("lock session access metadata", ErrorKindQuery, err)
	}
	if _, err := queries.RevokeRefreshTokenFamiliesByBindings(ctx, sqlcgen.RevokeRefreshTokenFamiliesByBindingsParams{
		RevokedAt: timestamp(now), RevokeReason: pointerString(familyReason), SessionBindingIds: unique,
	}); err != nil {
		return wrapError("revoke session refresh families", ErrorKindQuery, err)
	}
	if _, err := queries.RevokeLiveAccessTokensByBindings(ctx, sqlcgen.RevokeLiveAccessTokensByBindingsParams{
		RevokedAt: timestamp(now), RevokeReason: pointerString(familyReason), SessionBindingIds: unique,
	}); err != nil {
		return wrapError("revoke session access metadata", ErrorKindQuery, err)
	}
	return nil
}

// CleanupSessions removes expired pre-auth state and retired sessions beyond retention.
func (s *Store) CleanupSessions(ctx context.Context, preAuthCutoff, retiredCutoff time.Time) (int64, error) {
	var total int64
	for {
		var preauth, login int64
		err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
			var err error
			preauth, err = queries.DeleteExpiredPreAuthSessions(ctx, sqlcgen.DeleteExpiredPreAuthSessionsParams{
				Cutoff: timestamp(preAuthCutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean pre-auth sessions", ErrorKindQuery, err)
			}
			login, err = queries.DeleteRetiredLoginSessions(ctx, sqlcgen.DeleteRetiredLoginSessionsParams{
				Cutoff: timestamp(retiredCutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean login sessions", ErrorKindQuery, err)
			}
			return nil
		}, func() {
			preauth = 0
			login = 0
		})
		if err != nil {
			return total, err
		}
		total += preauth + login
		if preauth < int64(cleanupBatchSize) && login < int64(cleanupBatchSize) {
			return total, nil
		}
	}
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
		ID: record.ID, UserID: record.UserID, SessionBindingID: record.SessionBindingID,
		TokenHash: record.TokenHash, CsrfHash: record.CSRFHash,
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
		SessionID: row.ID, SessionBindingID: row.SessionBindingID,
		User: identity.User{
			ID: row.UserID, Subject: row.Subject, Username: row.Username, DisplayName: row.DisplayName,
			Email: row.Email, EmailVerified: row.EmailVerified, Status: identity.Status(row.UserStatus),
			Role: identity.Role(row.UserRole), CreatedAt: requiredTime(row.UserCreatedAt),
			UpdatedAt: requiredTime(row.UserUpdatedAt), Version: row.UserVersion, LastLoginAt: optionalTime(row.UserLastLoginAt),
		},
		CSRFHash: row.CsrfHash, CSRFExpiresAt: requiredTime(row.CsrfExpiresAt),
		CreatedAt: requiredTime(row.CreatedAt), LastSeenAt: requiredTime(row.LastSeenAt),
		AuthenticatedAt: requiredTime(row.AuthenticatedAt), ExpiresAt: requiredTime(row.ExpiresAt),
		IdleExpiresAt: requiredTime(row.IdleExpiresAt), RevokedAt: optionalTime(row.RevokedAt),
	}
}
