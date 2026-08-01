package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// CreateClient atomically inserts client metadata, an optional secret digest, and audit.
func (s *Store) CreateClient(ctx context.Context, value clientdomain.Client, secret *clientdomain.SecretRecord, event audit.Event) error {
	return s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		if _, err := queries.CreateOIDCClient(ctx, createClientParams(value)); err != nil {
			return mapClientWriteError("create client", err)
		}
		if err := replaceClientChildren(ctx, queries, value, false); err != nil {
			return err
		}
		if secret != nil {
			if err := queries.CreateOIDCClientSecret(ctx, sqlcgen.CreateOIDCClientSecretParams{
				ID: secret.ID, ClientID: secret.ClientID, SecretHash: secret.SecretHash, CreatedAt: timestamp(secret.CreatedAt),
			}); err != nil {
				return mapClientWriteError("create client secret", err)
			}
		}
		return insertAudit(ctx, queries, event)
	})
}

// GetClient returns one credential-free client.
func (s *Store) GetClient(ctx context.Context, id uuid.UUID) (clientdomain.Client, error) {
	var result clientdomain.Client
	err := s.inTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(queries *sqlcgen.Queries) error {
		value, err := loadClient(ctx, queries, id)
		if err != nil {
			return err
		}
		result = value
		return nil
	})
	return result, err
}

// GetClientByPublicID returns one credential-free Client by protocol client_id.
func (s *Store) GetClientByPublicID(ctx context.Context, publicID string) (clientdomain.Client, error) {
	var result clientdomain.Client
	err := s.inTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(queries *sqlcgen.Queries) error {
		row, err := queries.GetOIDCClientByClientID(ctx, publicID)
		if isNoRows(err) {
			return clientdomain.ErrNotFound
		}
		if err != nil {
			return wrapError("get client by public identifier", ErrorKindQuery, err)
		}
		value := mapClient(row)
		if err := loadClientChildren(ctx, queries, &value); err != nil {
			return err
		}
		result = value
		return nil
	})
	return result, err
}

// ListClients returns credential-free clients using keyset pagination.
func (s *Store) ListClients(ctx context.Context, cursor pagination.Cursor, limit int) ([]clientdomain.Client, error) {
	result := make([]clientdomain.Client, 0)
	err := s.inTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(queries *sqlcgen.Queries) error {
		rows, err := queries.ListOIDCClients(ctx, sqlcgen.ListOIDCClientsParams{
			CursorTime: cursorTimestamp(cursor.Time), CursorID: cursor.ID, PageLimit: postgresPageLimit(limit),
		})
		if err != nil {
			return wrapError("list clients", ErrorKindQuery, err)
		}
		result = make([]clientdomain.Client, 0, len(rows))
		for _, row := range rows {
			value := mapClient(row)
			if err := loadClientChildren(ctx, queries, &value); err != nil {
				return err
			}
			result = append(result, value)
		}
		return nil
	})
	return result, err
}

// UpdateClient atomically applies an optimistic metadata update and audit event.
func (s *Store) UpdateClient(ctx context.Context, value clientdomain.Client, event audit.Event) error {
	return s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		if _, err := queries.LockOIDCClientByID(ctx, value.ID); isNoRows(err) {
			return clientdomain.ErrNotFound
		} else if err != nil {
			return wrapError("lock client", ErrorKindQuery, err)
		}
		_, err := queries.UpdateOIDCClient(ctx, sqlcgen.UpdateOIDCClientParams{
			Name: value.Name, Description: value.Description, LogoUri: pointerString(value.LogoURI),
			Status: string(value.Status), RegistrationEnabled: value.RegistrationEnabled,
			UpdatedAt: timestamp(value.UpdatedAt), ID: value.ID, ExpectedUpdatedAt: timestamp(value.Version),
		})
		if isNoRows(err) {
			return clientdomain.ErrConflict
		}
		if err != nil {
			return mapClientWriteError("update client", err)
		}
		if err := replaceClientChildren(ctx, queries, value, true); err != nil {
			return err
		}
		return insertAudit(ctx, queries, event)
	})
}

// RotateClientSecret atomically revokes old digests, inserts a replacement, and audits.
func (s *Store) RotateClientSecret(ctx context.Context, id uuid.UUID, secret clientdomain.SecretRecord, now time.Time, event audit.Event) error {
	return s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		row, err := queries.LockOIDCClientByID(ctx, id)
		if isNoRows(err) {
			return clientdomain.ErrNotFound
		}
		if err != nil {
			return wrapError("lock client for secret rotation", ErrorKindQuery, err)
		}
		if clientdomain.Type(row.ClientType) != clientdomain.TypeConfidential {
			return clientdomain.ErrPublicSecret
		}
		if _, err := queries.RevokeActiveOIDCClientSecrets(ctx, sqlcgen.RevokeActiveOIDCClientSecretsParams{
			RevokedAt: timestamp(now), ClientID: id,
		}); err != nil {
			return wrapError("revoke old client secrets", ErrorKindQuery, err)
		}
		if err := queries.CreateOIDCClientSecret(ctx, sqlcgen.CreateOIDCClientSecretParams{
			ID: secret.ID, ClientID: id, SecretHash: secret.SecretHash, CreatedAt: timestamp(secret.CreatedAt),
		}); err != nil {
			return mapClientWriteError("create rotated client secret", err)
		}
		return insertAudit(ctx, queries, event)
	})
}

// GetClientSecretHashes returns internal active digests for constant-time validation.
func (s *Store) GetClientSecretHashes(ctx context.Context, clientID string) (clientdomain.Client, [][]byte, error) {
	row, err := s.queries.GetOIDCClientByClientID(ctx, clientID)
	if isNoRows(err) {
		return clientdomain.Client{}, nil, clientdomain.ErrNotFound
	}
	if err != nil {
		return clientdomain.Client{}, nil, wrapError("find client for secret validation", ErrorKindQuery, err)
	}
	hashes, err := s.queries.ListActiveOIDCClientSecretHashes(ctx, row.ID)
	if err != nil {
		return clientdomain.Client{}, nil, wrapError("list active client secret digests", ErrorKindQuery, err)
	}
	value, err := s.GetClient(ctx, row.ID)
	return value, hashes, err
}

func loadClient(ctx context.Context, queries *sqlcgen.Queries, id uuid.UUID) (clientdomain.Client, error) {
	row, err := queries.GetOIDCClientByID(ctx, id)
	if isNoRows(err) {
		return clientdomain.Client{}, clientdomain.ErrNotFound
	}
	if err != nil {
		return clientdomain.Client{}, wrapError("get client", ErrorKindQuery, err)
	}
	value := mapClient(row)
	if err := loadClientChildren(ctx, queries, &value); err != nil {
		return clientdomain.Client{}, err
	}
	return value, nil
}

func loadClientChildren(ctx context.Context, queries *sqlcgen.Queries, value *clientdomain.Client) error {
	redirects, err := queries.ListOIDCClientRedirectURIs(ctx, value.ID)
	if err != nil {
		return wrapError("list client redirect URIs", ErrorKindQuery, err)
	}
	logouts, err := queries.ListOIDCClientLogoutURIs(ctx, value.ID)
	if err != nil {
		return wrapError("list client logout URIs", ErrorKindQuery, err)
	}
	scopes, err := queries.ListOIDCClientScopes(ctx, value.ID)
	if err != nil {
		return wrapError("list client scopes", ErrorKindQuery, err)
	}
	value.RedirectURIs, value.LogoutURIs, value.Scopes = redirects, logouts, scopes
	return nil
}

func replaceClientChildren(ctx context.Context, queries *sqlcgen.Queries, value clientdomain.Client, replace bool) error {
	if replace {
		if err := queries.DeleteOIDCClientRedirectURIs(ctx, value.ID); err != nil {
			return wrapError("replace client redirect URIs", ErrorKindQuery, err)
		}
		if err := queries.DeleteOIDCClientLogoutURIs(ctx, value.ID); err != nil {
			return wrapError("replace client logout URIs", ErrorKindQuery, err)
		}
		if err := queries.DeleteOIDCClientScopes(ctx, value.ID); err != nil {
			return wrapError("replace client scopes", ErrorKindQuery, err)
		}
	}
	for _, uri := range value.RedirectURIs {
		if err := queries.CreateOIDCClientRedirectURI(ctx, sqlcgen.CreateOIDCClientRedirectURIParams{ClientID: value.ID, Uri: uri, CreatedAt: timestamp(value.UpdatedAt)}); err != nil {
			return mapClientWriteError("create client redirect URI", err)
		}
	}
	for _, uri := range value.LogoutURIs {
		if err := queries.CreateOIDCClientLogoutURI(ctx, sqlcgen.CreateOIDCClientLogoutURIParams{ClientID: value.ID, Uri: uri, CreatedAt: timestamp(value.UpdatedAt)}); err != nil {
			return mapClientWriteError("create client logout URI", err)
		}
	}
	for _, scope := range value.Scopes {
		if err := queries.CreateOIDCClientScope(ctx, sqlcgen.CreateOIDCClientScopeParams{ClientID: value.ID, Scope: scope, CreatedAt: timestamp(value.UpdatedAt)}); err != nil {
			return mapClientWriteError("create client scope", err)
		}
	}
	return nil
}

func createClientParams(value clientdomain.Client) sqlcgen.CreateOIDCClientParams {
	return sqlcgen.CreateOIDCClientParams{
		ID: value.ID, ClientID: value.ClientID, ClientType: string(value.Type),
		TokenEndpointAuthMethod: string(value.TokenEndpointAuthMethod), Name: value.Name,
		Description: value.Description, LogoUri: pointerString(value.LogoURI), Status: string(value.Status),
		RegistrationEnabled: value.RegistrationEnabled, CreatedAt: timestamp(value.CreatedAt), UpdatedAt: timestamp(value.UpdatedAt),
	}
}

func mapClient(row sqlcgen.OidcClient) clientdomain.Client {
	updated := requiredTime(row.UpdatedAt)
	return clientdomain.Client{
		ID: row.ID, ClientID: row.ClientID, Type: clientdomain.Type(row.ClientType),
		TokenEndpointAuthMethod: clientdomain.AuthMethod(row.TokenEndpointAuthMethod), Name: row.Name,
		Description: row.Description, LogoURI: valueString(row.LogoUri), Status: clientdomain.Status(row.Status),
		RegistrationEnabled: row.RegistrationEnabled, RedirectURIs: []string{}, LogoutURIs: []string{}, Scopes: []string{},
		CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: updated, Version: updated,
	}
}

func mapClientWriteError(operation string, err error) error {
	if isConstraint(err, "23505") {
		return clientdomain.ErrConflict
	}
	if isConstraint(err, "23514") || isConstraint(err, "23503") {
		return clientdomain.ErrInvalid
	}
	return wrapError(operation, ErrorKindQuery, err)
}
