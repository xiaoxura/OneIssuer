package postgres

import (
	"context"

	"github.com/google/uuid"
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

func mapConsentGrant(row sqlcgen.ConsentGrant) consent.Grant {
	return consent.Grant{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID,
		Scopes:    append([]string(nil), row.Scopes...),
		CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: requiredTime(row.UpdatedAt),
	}
}
