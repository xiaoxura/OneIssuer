package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// GetConsentGrant returns the persistent grant for one User/Client pair. The
// authorization commit path locks and rechecks this row before issuing a Code.
func (s *Store) GetConsentGrant(ctx context.Context, userID, clientID uuid.UUID) (consent.Grant, error) {
	row, err := s.queries.GetConsentGrantByUserClient(ctx, sqlcgen.GetConsentGrantByUserClientParams{
		UserID: userID, ClientID: clientID,
	})
	if isNoRows(err) {
		return consent.Grant{}, consent.ErrNotFound
	}
	if err != nil {
		return consent.Grant{}, wrapError("get consent grant", ErrorKindQuery, err)
	}
	return mapConsentGrant(row), nil
}

// ListCurrentUserGrants returns only the owner-safe Grant projection. The
// keyset consists of updated_at and the public protocol client_id; no internal
// Grant identifier crosses this repository boundary.
func (s *Store) ListCurrentUserGrants(ctx context.Context, userID uuid.UUID, cursor consent.GrantCursor, limit int, now time.Time) ([]consent.ManagedGrant, error) {
	rows, err := s.queries.ListCurrentUserConsentGrants(ctx, sqlcgen.ListCurrentUserConsentGrantsParams{
		Now: timestamp(now), UserID: userID, CursorTime: cursorTimestamp(cursor.UpdatedAt),
		CursorClientID: cursor.ClientID, PageLimit: boundedRepositoryPageLimit(limit),
	})
	if err != nil {
		return nil, wrapError("list current user consent grants", ErrorKindQuery, err)
	}
	result := make([]consent.ManagedGrant, 0, len(rows))
	for _, row := range rows {
		result = append(result, consent.ManagedGrant{
			ClientID: row.PublicClientID, ClientName: row.ClientName,
			ClientStatus: clientdomain.Status(row.ClientStatus), Scopes: append([]string(nil), row.Scopes...),
			CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: requiredTime(row.UpdatedAt),
			RevokedAt: optionalTime(row.RevokedAt), HasActiveOfflineFamily: row.HasActiveOfflineFamily,
		})
	}
	return result, nil
}

// RevokeCurrentUserGrant locks authority in the frozen phase-four order
// User -> Client -> Grant -> ordered families -> ordered Access metadata, then
// atomically revokes the Grant and all dependent live authority with one Audit
// event. Unknown Clients and wrong-owner selectors deliberately share ErrNotFound.
func (s *Store) RevokeCurrentUserGrant(ctx context.Context, input consent.RevokeInput) (consent.ManagedGrant, error) {
	var result consent.ManagedGrant
	var events []audit.Event
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		if _, err := queries.LockUserByID(ctx, input.UserID); isNoRows(err) {
			return consent.ErrNotFound
		} else if err != nil {
			return wrapError("lock consent grant owner", ErrorKindQuery, err)
		}

		clientRow, err := queries.LockOIDCClientByClientID(ctx, input.PublicClientID)
		if isNoRows(err) {
			return consent.ErrNotFound
		}
		if err != nil {
			return wrapError("lock consent grant client", ErrorKindQuery, err)
		}

		grantRow, err := queries.LockConsentGrantByUserClient(ctx, sqlcgen.LockConsentGrantByUserClientParams{
			UserID: input.UserID, ClientID: clientRow.ID,
		})
		if isNoRows(err) {
			return consent.ErrNotFound
		}
		if err != nil {
			return wrapError("lock current user consent grant", ErrorKindQuery, err)
		}

		grant := mapConsentGrant(grantRow)
		result = managedGrantFromRows(grant, clientRow, false)
		if grant.RevokedAt != nil {
			return nil
		}

		if _, err := queries.LockUnrevokedRefreshTokenFamiliesByGrant(ctx, grant.ID); err != nil {
			return wrapError("lock consent grant refresh families", ErrorKindQuery, err)
		}
		if _, err := queries.LockLiveAccessTokensByGrant(ctx, sqlcgen.LockLiveAccessTokensByGrantParams{
			ConsentGrantID: grant.ID, Now: timestamp(input.Now),
		}); err != nil {
			return wrapError("lock consent grant access tokens", ErrorKindQuery, err)
		}

		revokedRow, err := queries.RevokeConsentGrant(ctx, sqlcgen.RevokeConsentGrantParams{
			RevokedAt: timestamp(input.Now), ID: grant.ID,
		})
		if isNoRows(err) {
			return consent.ErrNotFound
		}
		if err != nil {
			return wrapError("revoke current user consent grant", ErrorKindQuery, err)
		}
		if _, err := queries.RevokeRefreshTokenFamiliesByGrant(ctx, sqlcgen.RevokeRefreshTokenFamiliesByGrantParams{
			RevokedAt: timestamp(input.Now), ConsentGrantID: grant.ID,
		}); err != nil {
			return wrapError("revoke consent grant refresh families", ErrorKindQuery, err)
		}
		if _, err := queries.RevokeLiveAccessTokensByGrant(ctx, sqlcgen.RevokeLiveAccessTokensByGrantParams{
			RevokedAt: timestamp(input.Now), ConsentGrantID: grant.ID,
		}); err != nil {
			return wrapError("revoke consent grant access tokens", ErrorKindQuery, err)
		}

		event, err := audit.New(
			audit.ConsentGrantRevoked, audit.ResultSuccess, &input.UserID,
			audit.TargetConsentGrant, &grant.ID, input.RequestID, []string{"revoked"}, input.Now,
		)
		if err != nil {
			return err
		}
		if err := insertAudit(ctx, queries, event); err != nil {
			return err
		}
		events = append(events, event)
		result = managedGrantFromRows(mapConsentGrant(revokedRow), clientRow, false)
		return nil
	}, func() {
		result = consent.ManagedGrant{}
		events = nil
	})
	if err == nil {
		s.observeAuditEvents(events)
	}
	return result, err
}

func managedGrantFromRows(grant consent.Grant, clientRow sqlcgen.OidcClient, hasActiveOfflineFamily bool) consent.ManagedGrant {
	return consent.ManagedGrant{
		ClientID: clientRow.ClientID, ClientName: clientRow.Name,
		ClientStatus: clientdomain.Status(clientRow.Status), Scopes: append([]string(nil), grant.Scopes...),
		CreatedAt: grant.CreatedAt, UpdatedAt: grant.UpdatedAt, RevokedAt: grant.RevokedAt,
		HasActiveOfflineFamily: hasActiveOfflineFamily,
	}
}

func boundedRepositoryPageLimit(limit int) int32 {
	if limit < 1 {
		return 1
	}
	// Public pages are capped at 100; repositories are intentionally allowed one
	// sentinel row so services can issue a next cursor without exposing 101 items.
	if limit > 101 {
		return 101
	}
	// #nosec G115 -- the value is bounded to 1..101 above.
	return int32(limit)
}

func mapConsentGrant(row sqlcgen.ConsentGrant) consent.Grant {
	return consent.Grant{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID,
		Scopes:    append([]string(nil), row.Scopes...),
		CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: requiredTime(row.UpdatedAt),
		RevokedAt: optionalTime(row.RevokedAt), Version: row.Version,
	}
}
