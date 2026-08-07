package postgres

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// HasAdmin reports whether an administrator exists.
func (s *Store) HasAdmin(ctx context.Context) (bool, error) {
	value, err := s.queries.HasAdmin(ctx)
	if err != nil {
		return false, wrapError("check administrator existence", ErrorKindQuery, err)
	}
	return value, nil
}

// BootstrapAdmin atomically creates the first administrator and audit event.
func (s *Store) BootstrapAdmin(ctx context.Context, prepared identity.PreparedUser, event audit.Event) error {
	return s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		if err := queries.LockAdminSet(ctx); err != nil {
			return wrapError("lock administrator bootstrap", ErrorKindQuery, err)
		}
		exists, err := queries.HasAdmin(ctx)
		if err != nil {
			return wrapError("recheck administrator existence", ErrorKindQuery, err)
		}
		if exists {
			return identity.ErrBootstrapExists
		}
		if err := lockAndCheckIdentifiers(ctx, queries, prepared.User, uuid.Nil); err != nil {
			return err
		}
		if _, err := queries.CreateUser(ctx, createUserParams(prepared.User)); err != nil {
			return mapIdentityWriteError("create bootstrap administrator", err)
		}
		if err := queries.CreateCredential(ctx, sqlcgen.CreateCredentialParams{
			UserID: prepared.User.ID, PasswordHash: prepared.PasswordHash,
			CreatedAt: timestamp(prepared.User.CreatedAt), UpdatedAt: timestamp(prepared.User.UpdatedAt),
		}); err != nil {
			return mapIdentityWriteError("create bootstrap credential", err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// GetUser returns one credential-free user.
func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (identity.User, error) {
	row, err := s.queries.GetUserByID(ctx, id)
	if isNoRows(err) {
		return identity.User{}, identity.ErrNotFound
	}
	if err != nil {
		return identity.User{}, wrapError("get user", ErrorKindQuery, err)
	}
	return mapUser(row), nil
}

// ListUsers returns users using stable keyset pagination.
func (s *Store) ListUsers(ctx context.Context, search string, cursor pagination.Cursor, limit int) ([]identity.User, error) {
	rows, err := s.queries.ListUsers(ctx, sqlcgen.ListUsersParams{
		Search: search, CursorTime: cursorTimestamp(cursor.Time), CursorID: cursor.ID, PageLimit: postgresPageLimit(limit),
	})
	if err != nil {
		return nil, wrapError("list users", ErrorKindQuery, err)
	}
	result := make([]identity.User, 0, len(rows))
	for _, row := range rows {
		result = append(result, mapUser(row))
	}
	return result, nil
}

// CreateManagedUser atomically creates a managed identity and audit event.
func (s *Store) CreateManagedUser(ctx context.Context, prepared identity.PreparedUser, event audit.Event) error {
	return s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		if err := lockAndCheckIdentifiers(ctx, queries, prepared.User, uuid.Nil); err != nil {
			return err
		}
		if _, err := queries.CreateUser(ctx, createUserParams(prepared.User)); err != nil {
			return mapIdentityWriteError("create managed user", err)
		}
		if err := queries.CreateCredential(ctx, sqlcgen.CreateCredentialParams{
			UserID: prepared.User.ID, PasswordHash: prepared.PasswordHash,
			CreatedAt: timestamp(prepared.User.CreatedAt), UpdatedAt: timestamp(prepared.User.UpdatedAt),
		}); err != nil {
			return mapIdentityWriteError("create managed credential", err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// UpdateManagedUser atomically applies an optimistic user update, revocations, and audit.
func (s *Store) UpdateManagedUser(ctx context.Context, commit admin.UpdateUserCommit) (identity.User, error) {
	var result identity.User
	events := []audit.Event{commit.Event}
	if commit.RevokeSessions && commit.SessionEvent != nil {
		events = append(events, *commit.SessionEvent)
	}
	err := s.inTxWithAudit(ctx, pgx.TxOptions{}, events, func(queries *sqlcgen.Queries) error {
		if err := queries.LockAdminSet(ctx); err != nil {
			return wrapError("lock administrator set", ErrorKindQuery, err)
		}
		currentRow, err := queries.LockUserByID(ctx, commit.Updated.ID)
		if isNoRows(err) {
			return identity.ErrNotFound
		}
		if err != nil {
			return wrapError("lock managed user", ErrorKindQuery, err)
		}
		current := mapUser(currentRow)
		if current.Role == identity.RoleAdmin && current.Status == identity.StatusActive &&
			(commit.Updated.Role != identity.RoleAdmin || commit.Updated.Status != identity.StatusActive) {
			count, countErr := queries.CountActiveAdmins(ctx)
			if countErr != nil {
				return wrapError("count active administrators", ErrorKindQuery, countErr)
			}
			if count <= 1 {
				return identity.ErrLastAdmin
			}
		}
		if err := lockAndCheckIdentifiers(ctx, queries, commit.Updated, commit.Updated.ID); err != nil {
			return err
		}
		row, err := queries.UpdateUser(ctx, sqlcgen.UpdateUserParams{
			Username: commit.Updated.Username, UsernameNormalized: commit.Updated.UsernameNormalized,
			DisplayName: commit.Updated.DisplayName, Email: commit.Updated.Email,
			EmailNormalized: commit.Updated.EmailNormalized, Status: string(commit.Updated.Status),
			Role: string(commit.Updated.Role), UpdatedAt: timestamp(commit.Updated.UpdatedAt),
			ID: commit.Updated.ID, ExpectedVersion: commit.Updated.Version,
		})
		if isNoRows(err) {
			return identity.ErrConflict
		}
		if err != nil {
			return mapIdentityWriteError("update managed user", err)
		}
		var sessionRows []sqlcgen.LoginSession
		if commit.RevokeSessions {
			var lockErr error
			sessionRows, lockErr = queries.LockActiveLoginSessionsByUser(ctx, commit.Updated.ID)
			if lockErr != nil {
				return wrapError("lock sessions after user change", ErrorKindQuery, lockErr)
			}
		}
		if commit.Updated.Status == identity.StatusDisabled {
			if _, err := queries.LockUnrevokedRefreshTokenFamiliesByUser(ctx, commit.Updated.ID); err != nil {
				return wrapError("lock disabled user refresh families", ErrorKindQuery, err)
			}
			if _, err := queries.LockLiveAccessTokensByUser(ctx, sqlcgen.LockLiveAccessTokensByUserParams{
				UserID: commit.Updated.ID, Now: timestamp(commit.Updated.UpdatedAt),
			}); err != nil {
				return wrapError("lock disabled user access metadata", ErrorKindQuery, err)
			}
			if _, err := queries.RevokeRefreshTokenFamiliesByUser(ctx, sqlcgen.RevokeRefreshTokenFamiliesByUserParams{
				RevokedAt: timestamp(commit.Updated.UpdatedAt), RevokeReason: pointerString("user_disabled"), UserID: commit.Updated.ID,
			}); err != nil {
				return wrapError("revoke disabled user refresh families", ErrorKindQuery, err)
			}
			if _, err := queries.RevokeLiveAccessTokensByUser(ctx, sqlcgen.RevokeLiveAccessTokensByUserParams{
				RevokedAt: timestamp(commit.Updated.UpdatedAt), RevokeReason: pointerString("user_disabled"), UserID: commit.Updated.ID,
			}); err != nil {
				return wrapError("revoke disabled user access metadata", ErrorKindQuery, err)
			}
		}
		if commit.RevokeSessions {
			reason := "role_changed"
			familyReason := "session_revoked"
			if commit.Updated.Status == identity.StatusDisabled {
				reason = "user_disabled"
				familyReason = reason
			}
			bindingIDs := make([]uuid.UUID, 0, len(sessionRows))
			for _, sessionRow := range sessionRows {
				bindingIDs = append(bindingIDs, sessionRow.SessionBindingID)
			}
			if err := revokeSessionBindingsCascade(ctx, queries, bindingIDs, commit.Updated.UpdatedAt, familyReason); err != nil {
				return err
			}
			for _, sessionRow := range sessionRows {
				if _, revokeErr := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
					RevokedAt: timestamp(commit.Updated.UpdatedAt), RevokeReason: pointerString(reason), ID: sessionRow.ID,
				}); revokeErr != nil {
					return wrapError("revoke session after user change", ErrorKindQuery, revokeErr)
				}
			}
			if commit.SessionEvent != nil {
				if err := insertAudit(ctx, queries, *commit.SessionEvent); err != nil {
					return err
				}
			}
		}
		if err := insertAudit(ctx, queries, commit.Event); err != nil {
			return err
		}
		result = mapUser(row)
		return nil
	}, func() { result = identity.User{} })
	return result, err
}

// RevokeAllManagedUserSessions revokes a user's sessions and appends audit atomically.
func (s *Store) RevokeAllManagedUserSessions(ctx context.Context, userID uuid.UUID, now time.Time, event audit.Event) (int64, error) {
	var count int64
	err := s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		if _, err := queries.GetUserByID(ctx, userID); isNoRows(err) {
			return identity.ErrNotFound
		} else if err != nil {
			return wrapError("find user for session revocation", ErrorKindQuery, err)
		}
		rows, err := queries.LockActiveLoginSessionsByUser(ctx, userID)
		if err != nil {
			return wrapError("lock all managed user sessions", ErrorKindQuery, err)
		}
		bindingIDs := make([]uuid.UUID, 0, len(rows))
		for _, row := range rows {
			bindingIDs = append(bindingIDs, row.SessionBindingID)
		}
		if err := revokeSessionBindingsCascade(ctx, queries, bindingIDs, now, "session_revoked"); err != nil {
			return err
		}
		for _, row := range rows {
			if _, revokeErr := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
				RevokedAt: timestamp(now), RevokeReason: pointerString("admin"), ID: row.ID,
			}); revokeErr != nil {
				return wrapError("revoke managed user session", ErrorKindQuery, revokeErr)
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

// ListManagedSessions returns all session summaries using keyset pagination.
func (s *Store) ListManagedSessions(ctx context.Context, cursor pagination.Cursor, limit int) ([]session.Summary, error) {
	rows, err := s.queries.ListLoginSessionsAdmin(ctx, sqlcgen.ListLoginSessionsAdminParams{
		CursorTime: cursorTimestamp(cursor.Time), CursorID: cursor.ID, PageLimit: postgresPageLimit(limit),
	})
	if err != nil {
		return nil, wrapError("list managed sessions", ErrorKindQuery, err)
	}
	result := make([]session.Summary, 0, len(rows))
	for _, row := range rows {
		result = append(result, session.Summary{
			ID: row.ID, UserID: row.UserID, Username: row.Username, UserStatus: row.UserStatus,
			CreatedAt: requiredTime(row.CreatedAt), LastSeenAt: requiredTime(row.LastSeenAt),
			AuthenticatedAt: requiredTime(row.AuthenticatedAt), ExpiresAt: requiredTime(row.ExpiresAt),
			IdleExpiresAt: requiredTime(row.IdleExpiresAt), RevokedAt: optionalTime(row.RevokedAt),
			RevokeReason: valueString(row.RevokeReason), IPPrefix: valueString(row.IpPrefix),
		})
	}
	return result, nil
}

// RevokeManagedSession revokes one session and appends audit atomically.
func (s *Store) RevokeManagedSession(ctx context.Context, id uuid.UUID, now time.Time, event audit.Event) error {
	return s.inTxWithAudit(ctx, pgx.TxOptions{}, []audit.Event{event}, func(queries *sqlcgen.Queries) error {
		row, err := queries.LockLoginSessionByID(ctx, id)
		if isNoRows(err) {
			return session.ErrNotFound
		}
		if err != nil {
			return wrapError("lock managed session", ErrorKindQuery, err)
		}
		if row.RevokedAt.Valid {
			return session.ErrNotFound
		}
		if err := revokeSessionBindingCascade(ctx, queries, row.SessionBindingID, now, "session_revoked"); err != nil {
			return err
		}
		if _, err := queries.RevokeLoginSessionBindingByID(ctx, sqlcgen.RevokeLoginSessionBindingByIDParams{
			RevokedAt: timestamp(now), RevokeReason: pointerString("admin"), ID: id,
		}); err != nil {
			return wrapError("revoke managed session", ErrorKindQuery, err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// ListAuditEvents returns append-only events using keyset pagination.
func (s *Store) ListAuditEvents(ctx context.Context, eventType string, cursor pagination.Cursor, limit int) ([]audit.Event, error) {
	rows, err := s.queries.ListAuditEvents(ctx, sqlcgen.ListAuditEventsParams{
		EventType: eventType, CursorTime: cursorTimestamp(cursor.Time), CursorID: cursor.ID, PageLimit: postgresPageLimit(limit),
	})
	if err != nil {
		return nil, wrapError("list audit events", ErrorKindQuery, err)
	}
	result := make([]audit.Event, 0, len(rows))
	for _, row := range rows {
		event := audit.Event{
			ID: row.ID, Type: audit.EventType(row.EventType), Result: audit.Result(row.Result),
			ActorUserID: row.ActorUserID, TargetID: row.TargetID, RequestID: valueString(row.RequestID),
			ChangedFields: row.ChangedFields, OccurredAt: requiredTime(row.OccurredAt),
		}
		if row.TargetType != nil {
			value := audit.TargetType(*row.TargetType)
			event.TargetType = &value
		}
		result = append(result, event)
	}
	return result, nil
}

func lockAndCheckIdentifiers(ctx context.Context, queries *sqlcgen.Queries, user identity.User, excludeID uuid.UUID) error {
	identifiers := []string{user.UsernameNormalized, user.EmailNormalized}
	sort.Strings(identifiers)
	for _, identifier := range identifiers {
		if err := queries.LockLoginIdentifier(ctx, identifier); err != nil {
			return wrapError("lock login identifier", ErrorKindQuery, err)
		}
	}
	for _, identifier := range identifiers {
		var exists bool
		var err error
		if excludeID == uuid.Nil {
			exists, err = queries.LoginIdentifierExists(ctx, identifier)
		} else {
			exists, err = queries.LoginIdentifierOwnedByOther(ctx, sqlcgen.LoginIdentifierOwnedByOtherParams{ID: excludeID, Identifier: identifier})
		}
		if err != nil {
			return wrapError("check login identifier ownership", ErrorKindQuery, err)
		}
		if exists {
			return identity.ErrDuplicate
		}
	}
	return nil
}

func postgresPageLimit(limit int) int32 {
	bounded := pagination.Limit(limit)
	// #nosec G115 -- pagination.Limit always returns a value in the range 1..100.
	return int32(bounded)
}
