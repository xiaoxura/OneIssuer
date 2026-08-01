package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
	"github.com/oneissuer/oneissuer/internal/token"
)

// ExchangeAuthorizationCode locks a Code and all mutable authority, invokes the
// bounded local mint callback, inserts Access metadata, consumes the Code, and
// appends audit events in one PostgreSQL transaction.
func (s *Store) ExchangeAuthorizationCode(ctx context.Context, input token.ExchangeInput, mint token.MintFunc) (token.Response, error) {
	if len(input.CodeHash) != sha256.Size || input.Client.ID == uuid.Nil || input.RedirectURI == "" || input.CodeVerifier == "" || input.Now.IsZero() || mint == nil {
		return token.Response{}, token.ErrInvalidGrant
	}
	var response token.Response
	replayRejected := false
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		codeRow, err := queries.LockAuthorizationCodeByHash(ctx, input.CodeHash)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock authorization code for exchange", ErrorKindQuery, err)
		}
		if codeRow.ConsumedAt.Valid {
			alreadyRecorded, auditErr := queries.HasAuthorizationCodeExchangeRejection(ctx, &codeRow.ID)
			if auditErr != nil {
				return wrapError("check authorization code replay audit", ErrorKindQuery, auditErr)
			}
			if !alreadyRecorded {
				if auditErr := insertProtocolAudit(ctx, queries, audit.AuthorizationCodeExchangeRejected, audit.ResultRejected, codeRow.UserID, audit.TargetAuthorizationCode, codeRow.ID, input.RequestID, nil, input.Now); auditErr != nil {
					return auditErr
				}
			}
			replayRejected = true
			return nil
		}
		if !requiredTime(codeRow.ExpiresAt).After(input.Now) {
			return token.ErrInvalidGrant
		}
		if codeRow.ClientID != input.Client.ID || codeRow.RedirectUri != input.RedirectURI || codeRow.PkceMethod != "S256" ||
			authorization.VerifyS256(input.CodeVerifier, codeRow.PkceChallenge) != nil {
			return token.ErrInvalidGrant
		}

		userRow, err := queries.LockUserByID(ctx, codeRow.UserID)
		if isNoRows(err) || err == nil && identity.Status(userRow.Status) != identity.StatusActive {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock code exchange user", ErrorKindQuery, err)
		}
		clientRow, err := queries.LockOIDCClientByID(ctx, codeRow.ClientID)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock code exchange client", ErrorKindQuery, err)
		}
		clientValue := mapClient(clientRow)
		if err := loadClientChildren(ctx, queries, &clientValue); err != nil {
			return err
		}
		if !sameAuthenticatedClient(clientValue, input.Client) || !slices.Contains(clientValue.RedirectURIs, codeRow.RedirectUri) {
			return token.ErrInvalidGrant
		}
		scopes, err := consent.CanonicalScopes(codeRow.Scopes)
		if err != nil || !scopeSubset(scopes, clientValue.Scopes) {
			return token.ErrInvalidGrant
		}

		grantRow, err := queries.LockConsentGrantByUserClient(ctx, sqlcgen.LockConsentGrantByUserClientParams{
			UserID: codeRow.UserID, ClientID: codeRow.ClientID,
		})
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock code exchange consent grant", ErrorKindQuery, err)
		}
		grant := mapConsentGrant(grantRow)
		if grant.ID != codeRow.ConsentGrantID || len(consent.Difference(scopes, consent.Intersection(grant.Scopes, clientValue.Scopes))) != 0 {
			return token.ErrInvalidGrant
		}

		minted, err := mint(ctx, token.Authority{
			CodeID: codeRow.ID, GrantID: grant.ID, User: mapUser(userRow), Client: clientValue,
			Scopes: scopes, Nonce: valueString(codeRow.NonceValue),
			AuthenticatedAt: requiredTime(codeRow.AuthTime), IssuedAt: input.Now,
		})
		if err != nil {
			return err
		}
		if !validMintedTokens(minted, input.Now) {
			return token.ErrInvalid
		}
		if err := queries.CreateAccessToken(ctx, sqlcgen.CreateAccessTokenParams{
			ID: minted.AccessTokenID, JtiHash: append([]byte(nil), minted.JTIHash...),
			AuthorizationCodeID: codeRow.ID, ConsentGrantID: grant.ID,
			UserID: codeRow.UserID, ClientID: codeRow.ClientID, Scopes: scopes,
			IssuedAt: timestamp(minted.IssuedAt), ExpiresAt: timestamp(minted.AccessExpiresAt),
		}); err != nil {
			return wrapError("create access token metadata", ErrorKindQuery, err)
		}
		if _, err := queries.ConsumeAuthorizationCode(ctx, sqlcgen.ConsumeAuthorizationCodeParams{
			ConsumedAt: timestamp(input.Now), ID: codeRow.ID,
		}); isNoRows(err) {
			return token.ErrInvalidGrant
		} else if err != nil {
			return wrapError("consume authorization code", ErrorKindQuery, err)
		}
		if err := insertProtocolAudit(ctx, queries, audit.AuthorizationCodeExchangeSucceeded, audit.ResultSuccess, codeRow.UserID, audit.TargetAuthorizationCode, codeRow.ID, input.RequestID, []string{"consumed"}, input.Now); err != nil {
			return err
		}
		if err := insertProtocolAudit(ctx, queries, audit.AccessTokenIssued, audit.ResultSuccess, codeRow.UserID, audit.TargetAccessToken, minted.AccessTokenID, input.RequestID, []string{"issued"}, input.Now); err != nil {
			return err
		}
		response = token.Response{
			AccessToken: minted.AccessToken, TokenType: "Bearer",
			ExpiresIn: int64(minted.AccessExpiresAt.Sub(minted.IssuedAt) / time.Second),
			IDToken:   minted.IDToken, Scope: strings.Join(scopes, " "),
		}
		return nil
	})
	if err == nil && replayRejected {
		return token.Response{}, token.ErrInvalidGrant
	}
	return response, err
}

// GetAccessTokenAuthority requires committed, unexpired Access metadata and
// returns a consistent current User/Client/Grant snapshot for UserInfo.
func (s *Store) GetAccessTokenAuthority(ctx context.Context, jtiHash []byte, now time.Time) (token.AccessAuthority, error) {
	if len(jtiHash) != sha256.Size || now.IsZero() {
		return token.AccessAuthority{}, token.ErrInvalidToken
	}
	var result token.AccessAuthority
	err := s.inTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(queries *sqlcgen.Queries) error {
		row, err := queries.GetAccessTokenByJTIHash(ctx, jtiHash)
		if isNoRows(err) {
			return token.ErrInvalidToken
		}
		if err != nil {
			return wrapError("get access token metadata", ErrorKindQuery, err)
		}
		metadata := mapAccessMetadata(row)
		if !now.UTC().Before(metadata.ExpiresAt) || !bytes.Equal(metadata.JTIHash, jtiHash) {
			return token.ErrInvalidToken
		}
		userRow, err := queries.GetUserByID(ctx, metadata.UserID)
		if isNoRows(err) || err == nil && identity.Status(userRow.Status) != identity.StatusActive {
			return token.ErrInvalidToken
		}
		if err != nil {
			return wrapError("get access token user", ErrorKindQuery, err)
		}
		clientValue, err := loadClient(ctx, queries, metadata.ClientID)
		if err != nil {
			if errorsIsClientNotFound(err) {
				return token.ErrInvalidToken
			}
			return err
		}
		if clientValue.Status != clientdomain.StatusActive {
			return token.ErrInvalidToken
		}
		grantRow, err := queries.GetConsentGrantByUserClient(ctx, sqlcgen.GetConsentGrantByUserClientParams{
			UserID: metadata.UserID, ClientID: metadata.ClientID,
		})
		if isNoRows(err) || err == nil && grantRow.ID != metadata.ConsentGrantID {
			return token.ErrInvalidToken
		}
		if err != nil {
			return wrapError("get access token consent grant", ErrorKindQuery, err)
		}
		result = token.AccessAuthority{
			Metadata: metadata, Grant: mapConsentGrant(grantRow), User: mapUser(userRow), Client: clientValue,
		}
		return nil
	})
	return result, err
}

// CleanupProtocolArtifacts deletes expired metadata only after an additional
// retention window chosen by the caller. Read paths never depend on cleanup.
func (s *Store) CleanupProtocolArtifacts(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		// access_tokens references authorization_codes with ON DELETE RESTRICT,
		// so dependent Access metadata must be retired first.
		access, err := queries.DeleteRetiredAccessTokens(ctx, timestamp(cutoff))
		if err != nil {
			return wrapError("clean access token metadata", ErrorKindQuery, err)
		}
		codes, err := queries.DeleteRetiredAuthorizationCodes(ctx, timestamp(cutoff))
		if err != nil {
			return wrapError("clean authorization code metadata", ErrorKindQuery, err)
		}
		total = codes + access
		return nil
	})
	return total, err
}

func validMintedTokens(value token.Minted, now time.Time) bool {
	return value.AccessTokenID != uuid.Nil && len(value.JTIHash) == sha256.Size && value.AccessToken != "" && value.IDToken != "" &&
		value.IssuedAt.Equal(now.UTC()) && value.AccessExpiresAt.After(value.IssuedAt) && value.IDExpiresAt.After(value.IssuedAt) &&
		!value.AccessExpiresAt.After(value.IssuedAt.Add(30*time.Minute)) && !value.IDExpiresAt.After(value.IssuedAt.Add(15*time.Minute))
}

func sameAuthenticatedClient(current, authenticated clientdomain.Client) bool {
	return current.ID == authenticated.ID && current.ClientID == authenticated.ClientID && current.Status == clientdomain.StatusActive &&
		current.Type == authenticated.Type && current.TokenEndpointAuthMethod == authenticated.TokenEndpointAuthMethod &&
		((current.Type == clientdomain.TypePublic && current.TokenEndpointAuthMethod == clientdomain.AuthMethodNone) ||
			(current.Type == clientdomain.TypeConfidential && current.TokenEndpointAuthMethod == clientdomain.AuthMethodClientSecretBasic))
}

func mapAccessMetadata(row sqlcgen.AccessToken) token.AccessMetadata {
	return token.AccessMetadata{
		ID: row.ID, JTIHash: append([]byte(nil), row.JtiHash...), AuthorizationCodeID: row.AuthorizationCodeID,
		ConsentGrantID: row.ConsentGrantID, UserID: row.UserID, ClientID: row.ClientID,
		Scopes: append([]string(nil), row.Scopes...), IssuedAt: requiredTime(row.IssuedAt), ExpiresAt: requiredTime(row.ExpiresAt),
	}
}

func errorsIsClientNotFound(err error) bool {
	return errors.Is(err, clientdomain.ErrNotFound)
}
