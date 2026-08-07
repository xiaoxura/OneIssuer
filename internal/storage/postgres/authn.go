package postgres

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// CreatePreAuth persists a digest-only pre-authentication session.
func (s *Store) CreatePreAuth(ctx context.Context, record session.PreAuthRecord) error {
	return createPreAuthSession(ctx, s.queries, record)
}

// FindPreAuth resolves a pre-authentication session by token digest.
func (s *Store) FindPreAuth(ctx context.Context, tokenHash []byte) (session.PreAuthRecord, error) {
	row, err := s.queries.GetPreAuthSessionByTokenHash(ctx, tokenHash)
	if isNoRows(err) {
		return session.PreAuthRecord{}, session.ErrNotFound
	}
	if err != nil {
		return session.PreAuthRecord{}, wrapError("find pre-auth session", ErrorKindQuery, err)
	}
	return session.PreAuthRecord{
		ID: row.ID, TokenHash: row.TokenHash, CSRFHash: row.CsrfHash, AuthTransactionID: row.AuthTransactionID,
		CreatedAt: requiredTime(row.CreatedAt), ExpiresAt: requiredTime(row.ExpiresAt), ConsumedAt: optionalTime(row.ConsumedAt),
		AttemptCount: row.AttemptCount,
	}, nil
}

// ReservePreAuthAttempt atomically enforces a small per-form submission budget
// before credential lookup or Argon2 work begins.
func (s *Store) ReservePreAuthAttempt(ctx context.Context, id uuid.UUID, now time.Time, maximum int16) error {
	_, err := s.queries.ReservePreAuthAttempt(ctx, sqlcgen.ReservePreAuthAttemptParams{
		ID: id, Now: timestamp(now), MaxAttempts: maximum,
	})
	if isNoRows(err) {
		return session.ErrConsumed
	}
	if err != nil {
		return wrapError("reserve pre-authentication attempt", ErrorKindQuery, err)
	}
	return nil
}

// FindLoginRecord returns the narrow credential projection for login verification.
func (s *Store) FindLoginRecord(ctx context.Context, identifier string) (identity.LoginRecord, error) {
	row, err := s.queries.FindCredentialForLogin(ctx, identifier)
	if isNoRows(err) {
		return identity.LoginRecord{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.LoginRecord{}, wrapError("find credential for login", ErrorKindQuery, err)
	}
	return identity.LoginRecord{
		User: identity.User{
			ID: row.ID, Subject: row.Subject, Username: row.Username, UsernameNormalized: row.UsernameNormalized,
			DisplayName: row.DisplayName, Email: row.Email, EmailNormalized: row.EmailNormalized,
			EmailVerified: row.EmailVerified, Status: identity.Status(row.Status), Role: identity.Role(row.Role),
			CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: requiredTime(row.UpdatedAt), LastLoginAt: optionalTime(row.LastLoginAt),
			Version: row.Version,
		},
		PasswordHash: row.PasswordHash,
	}, nil
}

// CommitRegistration atomically creates identity, credential, session, and audit rows.
func (s *Store) CommitRegistration(ctx context.Context, commit authn.RegisterCommit) error {
	if commit.Session.ID == uuid.Nil || commit.Session.UserID != commit.User.User.ID || commit.Session.SessionBindingID != commit.Session.ID {
		return authn.ErrInvalidFlow
	}
	events := append([]audit.Event(nil), commit.Events...)
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		identifiers := []string{commit.User.User.UsernameNormalized, commit.User.User.EmailNormalized}
		sort.Strings(identifiers)
		for _, identifier := range identifiers {
			if err := queries.LockLoginIdentifier(ctx, identifier); err != nil {
				return wrapError("lock login identifier", ErrorKindQuery, err)
			}
		}
		for _, identifier := range identifiers {
			exists, err := queries.LoginIdentifierExists(ctx, identifier)
			if err != nil {
				return wrapError("check login identifier", ErrorKindQuery, err)
			}
			if exists {
				return identity.ErrDuplicate
			}
		}
		if _, err := queries.CreateUser(ctx, createUserParams(commit.User.User)); err != nil {
			return mapIdentityWriteError("create registered user", err)
		}
		if err := queries.CreateCredential(ctx, sqlcgen.CreateCredentialParams{
			UserID: commit.User.User.ID, PasswordHash: commit.User.PasswordHash,
			CreatedAt: timestamp(commit.User.User.CreatedAt), UpdatedAt: timestamp(commit.User.User.UpdatedAt),
		}); err != nil {
			return mapIdentityWriteError("create registered credential", err)
		}
		if len(commit.ExistingSessionHash) > 0 {
			existing, lockErr := queries.LockLoginSessionByTokenHash(ctx, commit.ExistingSessionHash)
			if lockErr != nil && !isNoRows(lockErr) {
				return wrapError("lock existing registration session", ErrorKindQuery, lockErr)
			}
			active := lockErr == nil && !existing.RevokedAt.Valid &&
				requiredTime(existing.ExpiresAt).After(commit.Session.CreatedAt) &&
				requiredTime(existing.IdleExpiresAt).After(commit.Session.CreatedAt)
			if active && existing.UserID != commit.User.User.ID {
				if err := revokeSessionBindingCascade(ctx, queries, existing.SessionBindingID, commit.Session.CreatedAt, "account_switch"); err != nil {
					return err
				}
				revoked, revokeErr := queries.RevokeLoginSessionByID(ctx, sqlcgen.RevokeLoginSessionByIDParams{
					RevokedAt: timestamp(commit.Session.CreatedAt), RevokeReason: pointerString("account_switch"), ID: existing.ID,
				})
				if revokeErr != nil {
					return wrapError("revoke existing registration session", ErrorKindQuery, revokeErr)
				}
				event, eventErr := audit.New(audit.SessionRevoked, audit.ResultSuccess, &existing.UserID, audit.TargetSession, &revoked.ID, commit.RequestID, []string{"revoked"}, commit.Session.CreatedAt)
				if eventErr != nil {
					return eventErr
				}
				if err := insertAudit(ctx, queries, event); err != nil {
					return err
				}
				events = append(events, event)
			}
		}
		if err := createLoginSession(ctx, queries, commit.Session); err != nil {
			return err
		}
		if _, err := queries.ConsumePreAuthSession(ctx, sqlcgen.ConsumePreAuthSessionParams{
			ConsumedAt: timestamp(commit.Session.CreatedAt), ID: commit.PreAuthID,
		}); isNoRows(err) {
			return session.ErrConsumed
		} else if err != nil {
			return wrapError("consume registration pre-auth", ErrorKindQuery, err)
		}
		if commit.ConsumeTransaction {
			if _, err := queries.ConsumeAuthTransaction(ctx, sqlcgen.ConsumeAuthTransactionParams{
				ConsumedAt: timestamp(commit.Session.CreatedAt), ID: commit.TransactionID,
			}); isNoRows(err) {
				return authflow.ErrConsumed
			} else if err != nil {
				return wrapError("consume registration transaction", ErrorKindQuery, err)
			}
		}
		for _, event := range commit.Events {
			if err := insertAudit(ctx, queries, event); err != nil {
				return err
			}
		}
		return nil
	}, func() { events = append(events[:0], commit.Events...) })
	if err == nil {
		s.observeAuditEvents(events)
	}
	return err
}

// CommitLogin atomically consumes flow state, rotates sessions, and appends audit.
func (s *Store) CommitLogin(ctx context.Context, commit authn.LoginCommit) (uuid.UUID, error) {
	if commit.Session.ID == uuid.Nil || commit.Session.UserID != commit.UserID || commit.Session.SessionBindingID != commit.Session.ID || commit.Now.IsZero() {
		return uuid.Nil, authn.ErrInvalidFlow
	}
	events := append([]audit.Event(nil), commit.Events...)
	initialBindingID := commit.Session.SessionBindingID
	bindingID := initialBindingID
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		userRow, err := queries.LockUserByID(ctx, commit.UserID)
		if isNoRows(err) {
			return identity.ErrInvalidCredentials
		}
		if err != nil {
			return wrapError("lock login user", ErrorKindQuery, err)
		}
		if identity.Status(userRow.Status) != identity.StatusActive {
			return identity.ErrInvalidCredentials
		}
		if _, err := queries.ConsumePreAuthSession(ctx, sqlcgen.ConsumePreAuthSessionParams{
			ConsumedAt: timestamp(commit.Now), ID: commit.PreAuthID,
		}); isNoRows(err) {
			return session.ErrConsumed
		} else if err != nil {
			return wrapError("consume login pre-auth", ErrorKindQuery, err)
		}
		if commit.ConsumeTransaction {
			if _, err := queries.ConsumeAuthTransaction(ctx, sqlcgen.ConsumeAuthTransactionParams{
				ConsumedAt: timestamp(commit.Now), ID: commit.TransactionID,
			}); isNoRows(err) {
				return authflow.ErrConsumed
			} else if err != nil {
				return wrapError("consume login transaction", ErrorKindQuery, err)
			}
		}
		if len(commit.ExistingSessionHash) > 0 {
			existing, lockErr := queries.LockLoginSessionByTokenHash(ctx, commit.ExistingSessionHash)
			if lockErr != nil && !isNoRows(lockErr) {
				return wrapError("lock existing login session", ErrorKindQuery, lockErr)
			}
			active := lockErr == nil && !existing.RevokedAt.Valid &&
				requiredTime(existing.ExpiresAt).After(commit.Now) && requiredTime(existing.IdleExpiresAt).After(commit.Now)
			if active {
				reason := "account_switch"
				if existing.UserID == commit.UserID {
					reason = "rotation"
					bindingID = existing.SessionBindingID
				} else if err := revokeSessionBindingCascade(ctx, queries, existing.SessionBindingID, commit.Now, reason); err != nil {
					return err
				}
				revoked, revokeErr := queries.RevokeLoginSessionByID(ctx, sqlcgen.RevokeLoginSessionByIDParams{
					RevokedAt: timestamp(commit.Now), RevokeReason: pointerString(reason), ID: existing.ID,
				})
				if revokeErr != nil {
					return wrapError("rotate existing login session", ErrorKindQuery, revokeErr)
				}
				actor := commit.UserID
				if reason == "account_switch" {
					actor = existing.UserID
				}
				event, eventErr := audit.New(audit.SessionRevoked, audit.ResultSuccess, &actor, audit.TargetSession, &revoked.ID, commit.RequestID, []string{"revoked"}, commit.Now)
				if eventErr != nil {
					return eventErr
				}
				if err := insertAudit(ctx, queries, event); err != nil {
					return err
				}
				events = append(events, event)
			}
		}
		if commit.ReplacementHash != "" {
			if err := queries.UpdateCredentialHash(ctx, sqlcgen.UpdateCredentialHashParams{
				PasswordHash: commit.ReplacementHash, UpdatedAt: timestamp(commit.Now), UserID: commit.UserID,
			}); err != nil {
				return wrapError("rehash login credential", ErrorKindQuery, err)
			}
		}
		if err := queries.UpdateLastLogin(ctx, sqlcgen.UpdateLastLoginParams{LastLoginAt: timestamp(commit.Now), ID: commit.UserID}); err != nil {
			return wrapError("update last login", ErrorKindQuery, err)
		}
		commit.Session.SessionBindingID = bindingID
		if err := createLoginSession(ctx, queries, commit.Session); err != nil {
			return err
		}
		for _, event := range commit.Events {
			if err := insertAudit(ctx, queries, event); err != nil {
				return err
			}
		}
		return nil
	}, func() {
		events = append(events[:0], commit.Events...)
		bindingID = initialBindingID
		commit.Session.SessionBindingID = initialBindingID
	})
	if err == nil {
		s.observeAuditEvents(events)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return bindingID, nil
}

// AppendAudit inserts one validated append-only event.
func (s *Store) AppendAudit(ctx context.Context, event audit.Event) error {
	err := insertAudit(ctx, s.queries, event)
	if err == nil {
		s.observeAuditEvents([]audit.Event{event})
	} else {
		s.observeAuditWriteFailure(err)
	}
	return err
}

func createUserParams(user identity.User) sqlcgen.CreateUserParams {
	return sqlcgen.CreateUserParams{
		ID: user.ID, Subject: user.Subject, Username: user.Username, UsernameNormalized: user.UsernameNormalized,
		DisplayName: user.DisplayName, Email: user.Email, EmailNormalized: user.EmailNormalized,
		EmailVerified: user.EmailVerified, Status: string(user.Status), Role: string(user.Role),
		CreatedAt: timestamp(user.CreatedAt), UpdatedAt: timestamp(user.UpdatedAt),
	}
}

func mapIdentityWriteError(operation string, err error) error {
	if isConstraint(err, "23505") {
		return identity.ErrDuplicate
	}
	if isConstraint(err, "23514") || isConstraint(err, "23503") {
		return identity.ErrInvalidInput
	}
	return wrapError(operation, ErrorKindQuery, err)
}
