package postgres

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// IssueAuthorizationCode atomically revalidates all mutable authority, updates
// Consent when interactive, inserts a Code digest, consumes the browser
// transaction, and appends fixed audit events.
func (s *Store) IssueAuthorizationCode(ctx context.Context, commit authorization.IssueCommit) (consent.Grant, error) {
	if err := validateIssueCommit(commit); err != nil {
		return consent.Grant{}, err
	}
	var result consent.Grant
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		transactionRow, err := queries.LockAuthTransactionByID(ctx, commit.Transaction.ID)
		if isNoRows(err) {
			return authorization.ErrNotFound
		}
		if err != nil {
			return wrapError("lock authorization transaction for code issue", ErrorKindQuery, err)
		}
		if err := validateLockedAuthorizationTransaction(transactionRow, commit.Transaction, commit.CreatedAt); err != nil {
			return err
		}

		userRow, err := queries.LockUserByID(ctx, commit.UserID)
		if isNoRows(err) {
			return authorization.ErrInactive
		}
		if err != nil {
			return wrapError("lock authorization user", ErrorKindQuery, err)
		}
		if identity.Status(userRow.Status) != identity.StatusActive {
			return authorization.ErrInactive
		}

		clientValue, err := lockAndValidateAuthorizationClient(ctx, queries, transactionRow)
		if err != nil {
			return err
		}

		requested, err := consent.CanonicalScopes(transactionRow.Scopes)
		if err != nil {
			return authorization.ErrInvalid
		}
		grant, grantChanged, err := lockAndApplyConsent(ctx, queries, commit, clientValue, requested)
		if err != nil {
			return err
		}

		if err := queries.CreateAuthorizationCode(ctx, sqlcgen.CreateAuthorizationCodeParams{
			ID: commit.CodeID, CodeHash: append([]byte(nil), commit.CodeHash...),
			AuthTransactionID: transactionRow.ID, ConsentGrantID: grant.ID,
			UserID: commit.UserID, ClientID: clientValue.ID,
			RedirectUri: transactionRowRedirect(transactionRow), Scopes: requested,
			PkceChallenge: transactionRowPKCE(transactionRow), PkceMethod: "S256",
			NonceValue: transactionRow.NonceValue, AuthTime: timestamp(commit.AuthenticatedAt),
			CreatedAt: timestamp(commit.CreatedAt), ExpiresAt: timestamp(commit.ExpiresAt),
		}); err != nil {
			return wrapError("create authorization code", ErrorKindQuery, err)
		}

		if _, err := queries.ConsumeAuthTransaction(ctx, sqlcgen.ConsumeAuthTransactionParams{
			ConsumedAt: timestamp(commit.CreatedAt), ID: transactionRow.ID,
		}); isNoRows(err) {
			return authorization.ErrConsumed
		} else if err != nil {
			return wrapError("consume transaction while issuing authorization code", ErrorKindQuery, err)
		}

		if grantChanged != "" {
			eventType, changed := audit.ConsentGrantCreated, []string{"created"}
			if grantChanged == "expanded" {
				eventType, changed = audit.ConsentGrantExpanded, []string{"expanded"}
			}
			if err := insertProtocolAudit(ctx, queries, eventType, audit.ResultSuccess, commit.UserID, audit.TargetConsentGrant, grant.ID, commit.RequestID, changed, commit.CreatedAt); err != nil {
				return err
			}
		}
		if err := insertProtocolAudit(ctx, queries, audit.AuthorizationTransactionConsumed, audit.ResultSuccess, commit.UserID, audit.TargetAuthTransaction, transactionRow.ID, commit.RequestID, nil, commit.CreatedAt); err != nil {
			return err
		}
		if err := insertProtocolAudit(ctx, queries, audit.AuthorizationGranted, audit.ResultSuccess, commit.UserID, audit.TargetAuthTransaction, transactionRow.ID, commit.RequestID, nil, commit.CreatedAt); err != nil {
			return err
		}
		if err := insertProtocolAudit(ctx, queries, audit.AuthorizationCodeIssued, audit.ResultSuccess, commit.UserID, audit.TargetAuthorizationCode, commit.CodeID, commit.RequestID, []string{"issued"}, commit.CreatedAt); err != nil {
			return err
		}
		result = grant
		return nil
	})
	return result, err
}

// DenyAuthorization atomically consumes one live transaction and appends the
// fixed denied/rejected audit events. Existing Consent is intentionally intact.
func (s *Store) DenyAuthorization(ctx context.Context, commit authorization.DenyCommit) error {
	if commit.UserID == uuid.Nil || commit.Transaction.ID == uuid.Nil || commit.DeniedAt.IsZero() {
		return authorization.ErrInvalid
	}
	return s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		transactionRow, err := queries.LockAuthTransactionByID(ctx, commit.Transaction.ID)
		if isNoRows(err) {
			return authorization.ErrNotFound
		}
		if err != nil {
			return wrapError("lock authorization transaction for denial", ErrorKindQuery, err)
		}
		if err := validateLockedAuthorizationTransaction(transactionRow, commit.Transaction, commit.DeniedAt); err != nil {
			return err
		}
		userRow, err := queries.LockUserByID(ctx, commit.UserID)
		if isNoRows(err) || err == nil && identity.Status(userRow.Status) != identity.StatusActive {
			return authorization.ErrInactive
		}
		if err != nil {
			return wrapError("lock authorization user for denial", ErrorKindQuery, err)
		}
		if _, err := lockAndValidateAuthorizationClient(ctx, queries, transactionRow); err != nil {
			return err
		}
		if _, err := queries.RejectAuthTransaction(ctx, sqlcgen.RejectAuthTransactionParams{
			ConsumedAt: timestamp(commit.DeniedAt), FailureReason: pointerString("access_denied"), ID: transactionRow.ID,
		}); isNoRows(err) {
			return authorization.ErrConsumed
		} else if err != nil {
			return wrapError("consume denied authorization transaction", ErrorKindQuery, err)
		}
		if err := insertProtocolAudit(ctx, queries, audit.AuthorizationTransactionRejected, audit.ResultRejected, commit.UserID, audit.TargetAuthTransaction, transactionRow.ID, commit.RequestID, nil, commit.DeniedAt); err != nil {
			return err
		}
		return insertProtocolAudit(ctx, queries, audit.AuthorizationDenied, audit.ResultRejected, commit.UserID, audit.TargetAuthTransaction, transactionRow.ID, commit.RequestID, nil, commit.DeniedAt)
	})
}

func validateIssueCommit(commit authorization.IssueCommit) error {
	if commit.UserID == uuid.Nil || commit.CodeID == uuid.Nil || commit.ProposedGrantID == uuid.Nil || len(commit.CodeHash) != 32 ||
		commit.CreatedAt.IsZero() || commit.AuthenticatedAt.IsZero() || commit.AuthenticatedAt.After(commit.CreatedAt) ||
		!commit.ExpiresAt.After(commit.CreatedAt) || commit.ExpiresAt.After(commit.CreatedAt.Add(5*time.Minute)) {
		return authorization.ErrInvalid
	}
	return nil
}

func validateLockedAuthorizationTransaction(row sqlcgen.AuthTransaction, expected authflow.Transaction, now time.Time) error {
	if !row.ConsumedAt.Valid && !requiredTime(row.ExpiresAt).After(now.UTC()) {
		return authorization.ErrExpired
	}
	if row.ConsumedAt.Valid {
		if valueString(row.FailureReason) == "expired" {
			return authorization.ErrExpired
		}
		return authorization.ErrConsumed
	}
	actual := mapAuthTransaction(row)
	if actual.Kind != authflow.KindAuthorization || actual.ClientID == nil || expected.ClientID == nil ||
		actual.ID != expected.ID || *actual.ClientID != *expected.ClientID ||
		!bytes.Equal(actual.TokenHash, expected.TokenHash) || actual.RedirectURI != expected.RedirectURI ||
		!slices.Equal(actual.Scopes, expected.Scopes) || actual.PKCEChallenge != expected.PKCEChallenge ||
		actual.PKCEMethod != expected.PKCEMethod || actual.State != expected.State || actual.Nonce != expected.Nonce ||
		actual.ResponseType != expected.ResponseType || actual.ResponseMode != expected.ResponseMode ||
		!slices.Equal(actual.Prompts, expected.Prompts) || !sameOptionalUint32(actual.MaxAgeSeconds, expected.MaxAgeSeconds) {
		return authorization.ErrInvalid
	}
	return nil
}

func lockAndValidateAuthorizationClient(ctx context.Context, queries *sqlcgen.Queries, transaction sqlcgen.AuthTransaction) (clientdomain.Client, error) {
	if transaction.ClientID == nil {
		return clientdomain.Client{}, authorization.ErrInvalid
	}
	row, err := queries.LockOIDCClientByID(ctx, *transaction.ClientID)
	if isNoRows(err) {
		return clientdomain.Client{}, authorization.ErrInactive
	}
	if err != nil {
		return clientdomain.Client{}, wrapError("lock authorization client", ErrorKindQuery, err)
	}
	value := mapClient(row)
	if err := loadClientChildren(ctx, queries, &value); err != nil {
		return clientdomain.Client{}, err
	}
	validAuthenticationProfile := false
	switch value.Type {
	case clientdomain.TypePublic:
		validAuthenticationProfile = value.TokenEndpointAuthMethod == clientdomain.AuthMethodNone
	case clientdomain.TypeConfidential:
		validAuthenticationProfile = value.TokenEndpointAuthMethod == clientdomain.AuthMethodClientSecretBasic
	}
	if value.Status != clientdomain.StatusActive || !validAuthenticationProfile ||
		!slices.Contains(value.RedirectURIs, transactionRowRedirect(transaction)) || !scopeSubset(transaction.Scopes, value.Scopes) {
		return clientdomain.Client{}, authorization.ErrInactive
	}
	return value, nil
}

func lockAndApplyConsent(ctx context.Context, queries *sqlcgen.Queries, commit authorization.IssueCommit, clientValue clientdomain.Client, requested []string) (consent.Grant, string, error) {
	row, err := queries.LockConsentGrantByUserClient(ctx, sqlcgen.LockConsentGrantByUserClientParams{
		UserID: commit.UserID, ClientID: clientValue.ID,
	})
	if isNoRows(err) {
		if !commit.InteractiveConsent {
			return consent.Grant{}, "", authorization.ErrConsentRequired
		}
		created, createErr := queries.CreateConsentGrant(ctx, sqlcgen.CreateConsentGrantParams{
			ID: commit.ProposedGrantID, UserID: commit.UserID, ClientID: clientValue.ID,
			Scopes: requested, CreatedAt: timestamp(commit.CreatedAt), UpdatedAt: timestamp(commit.CreatedAt),
		})
		if createErr != nil {
			return consent.Grant{}, "", wrapError("create consent grant", ErrorKindQuery, createErr)
		}
		return mapConsentGrant(created), "created", nil
	}
	if err != nil {
		return consent.Grant{}, "", wrapError("lock consent grant", ErrorKindQuery, err)
	}
	grant := mapConsentGrant(row)
	stored, validationErr := consent.CanonicalScopes(grant.Scopes)
	if validationErr != nil || grant.ID == uuid.Nil || grant.UserID != commit.UserID || grant.ClientID != clientValue.ID {
		return consent.Grant{}, "", authorization.ErrInvalid
	}
	effective := consent.Intersection(stored, clientValue.Scopes)
	if !commit.InteractiveConsent {
		if len(consent.Difference(requested, effective)) != 0 {
			return consent.Grant{}, "", authorization.ErrConsentRequired
		}
		grant.Scopes = stored
		return grant, "", nil
	}
	// Persisted Consent follows monotonic union semantics. Current Client policy
	// is always intersected on use, so an administrator scope reduction takes
	// effect immediately without misclassifying a later prune as an expansion.
	updatedScopes := consent.Union(stored, requested)
	if slices.Equal(updatedScopes, stored) {
		grant.Scopes = stored
		return grant, "", nil
	}
	updated, updateErr := queries.UpdateConsentGrantScopes(ctx, sqlcgen.UpdateConsentGrantScopesParams{
		Scopes: updatedScopes, UpdatedAt: timestamp(commit.CreatedAt), ID: grant.ID,
	})
	if updateErr != nil {
		return consent.Grant{}, "", wrapError("expand consent grant", ErrorKindQuery, updateErr)
	}
	return mapConsentGrant(updated), "expanded", nil
}

func insertProtocolAudit(ctx context.Context, queries *sqlcgen.Queries, eventType audit.EventType, result audit.Result, actor uuid.UUID, targetType audit.TargetType, target uuid.UUID, requestID string, changed []string, now time.Time) error {
	event, err := audit.New(eventType, result, &actor, targetType, &target, requestID, changed, now)
	if err != nil {
		return err
	}
	return insertAudit(ctx, queries, event)
}

func transactionRowRedirect(row sqlcgen.AuthTransaction) string { return valueString(row.RedirectUri) }
func transactionRowPKCE(row sqlcgen.AuthTransaction) string     { return valueString(row.PkceChallenge) }

func scopeSubset(requested, allowed []string) bool {
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}

func sameOptionalUint32(left, right *uint32) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
