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
	var events []audit.Event
	resetAttempt := func() {
		response = token.Response{}
		replayRejected = false
		events = nil
	}
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
				if auditErr := insertProtocolAudit(ctx, queries, audit.AuthorizationCodeExchangeRejected, audit.ResultRejected, codeRow.UserID, audit.TargetAuthorizationCode, codeRow.ID, input.RequestID, nil, input.Now, &events); auditErr != nil {
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
		if grant.ID != codeRow.ConsentGrantID || grant.Version != codeRow.ConsentGrantVersion || grant.RevokedAt != nil ||
			len(consent.Difference(scopes, consent.Intersection(grant.Scopes, clientValue.Scopes))) != 0 {
			return token.ErrInvalidGrant
		}

		minted, err := mint(ctx, token.Authority{
			CodeID: codeRow.ID, GrantID: grant.ID, User: mapUser(userRow), Client: clientValue,
			OriginSessionID: codeRow.OriginSessionID, SessionBindingID: codeRow.SessionBindingID,
			Scopes: scopes, Nonce: valueString(codeRow.NonceValue),
			AuthenticatedAt: requiredTime(codeRow.AuthTime), IssuedAt: input.Now,
		})
		if err != nil {
			return err
		}
		offline := slices.Contains(scopes, "offline_access")
		if !validMintedTokens(minted, input.Now, offline) {
			return token.ErrInvalid
		}
		var refreshFamilyID *uuid.UUID
		if minted.InitialRefresh != nil {
			initial := minted.InitialRefresh
			if codeRow.OriginSessionID == nil || codeRow.SessionBindingID == nil {
				return token.ErrInvalidGrant
			}
			if _, err := queries.CreateRefreshTokenFamily(ctx, sqlcgen.CreateRefreshTokenFamilyParams{
				ID: initial.FamilyID, OriginAuthorizationCodeID: &codeRow.ID,
				ConsentGrantID: grant.ID, UserID: codeRow.UserID, ClientID: codeRow.ClientID,
				OriginSessionID: codeRow.OriginSessionID, SessionBindingID: *codeRow.SessionBindingID,
				Scopes: scopes, CreatedAt: timestamp(minted.IssuedAt),
				AbsoluteExpiresAt: timestamp(initial.AbsoluteExpiresAt),
			}); err != nil {
				return wrapError("create refresh token family", ErrorKindQuery, err)
			}
			if _, err := queries.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
				ID: initial.TokenID, FamilyID: initial.FamilyID,
				TokenHash: append([]byte(nil), initial.TokenHash...), Generation: 0,
				IssuedAt: timestamp(minted.IssuedAt), ExpiresAt: timestamp(initial.ExpiresAt),
			}); err != nil {
				return wrapError("create initial refresh token", ErrorKindQuery, err)
			}
			familyID := initial.FamilyID
			refreshFamilyID = &familyID
		}
		if err := queries.CreateAccessToken(ctx, sqlcgen.CreateAccessTokenParams{
			ID: minted.AccessTokenID, JtiHash: append([]byte(nil), minted.JTIHash...),
			AuthorizationCodeID: &codeRow.ID, ConsentGrantID: grant.ID,
			UserID: codeRow.UserID, ClientID: codeRow.ClientID, Scopes: scopes,
			IssuedAt: timestamp(minted.IssuedAt), ExpiresAt: timestamp(minted.AccessExpiresAt),
			RefreshFamilyID: refreshFamilyID,
			OriginSessionID: codeRow.OriginSessionID, SessionBindingID: codeRow.SessionBindingID,
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
		if err := insertProtocolAudit(ctx, queries, audit.AuthorizationCodeExchangeSucceeded, audit.ResultSuccess, codeRow.UserID, audit.TargetAuthorizationCode, codeRow.ID, input.RequestID, []string{"consumed"}, input.Now, &events); err != nil {
			return err
		}
		if err := insertProtocolAudit(ctx, queries, audit.AccessTokenIssued, audit.ResultSuccess, codeRow.UserID, audit.TargetAccessToken, minted.AccessTokenID, input.RequestID, []string{"issued"}, input.Now, &events); err != nil {
			return err
		}
		if minted.InitialRefresh != nil {
			if err := insertProtocolAudit(ctx, queries, audit.RefreshTokenIssued, audit.ResultSuccess, codeRow.UserID, audit.TargetRefreshToken, minted.InitialRefresh.TokenID, input.RequestID, []string{"issued"}, input.Now, &events); err != nil {
				return err
			}
		}
		response = token.Response{
			AccessToken: minted.AccessToken, TokenType: "Bearer",
			ExpiresIn: int64(minted.AccessExpiresAt.Sub(minted.IssuedAt) / time.Second),
			IDToken:   minted.IDToken, Scope: strings.Join(scopes, " "),
		}
		if minted.InitialRefresh != nil {
			response.RefreshToken = minted.InitialRefresh.ClearToken
		}
		return nil
	}, resetAttempt)
	if err == nil {
		s.observeAuditEvents(events)
	}
	if err == nil && replayRejected {
		return token.Response{}, token.ErrInvalidGrant
	}
	return response, err
}

// ExchangeRefreshToken enforces single-use rotation and fail-closed reuse
// detection in the frozen User→Client→Grant→Family→Generation→Access order.
func (s *Store) ExchangeRefreshToken(ctx context.Context, input token.RefreshInput, mint token.RefreshMintFunc) (token.Response, error) {
	if len(input.TokenHash) != sha256.Size || input.Client.ID == uuid.Nil || input.Now.IsZero() || mint == nil {
		return token.Response{}, token.ErrInvalidGrant
	}
	candidate, err := s.queries.GetRefreshTokenByHash(ctx, input.TokenHash)
	if isNoRows(err) {
		return token.Response{}, token.ErrInvalidGrant
	}
	if err != nil {
		return token.Response{}, wrapError("find refresh token candidate", ErrorKindQuery, err)
	}
	candidateFamily, err := s.queries.GetRefreshTokenFamilyByID(ctx, candidate.FamilyID)
	if isNoRows(err) {
		return token.Response{}, token.ErrInvalidGrant
	}
	if err != nil {
		return token.Response{}, wrapError("find refresh token family candidate", ErrorKindQuery, err)
	}

	var response token.Response
	var events []audit.Event
	reuseDetected := false
	resetAttempt := func() {
		response = token.Response{}
		events = nil
		reuseDetected = false
	}
	err = s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		userRow, err := queries.LockUserByID(ctx, candidateFamily.UserID)
		if isNoRows(err) || err == nil && identity.Status(userRow.Status) != identity.StatusActive {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock refresh user", ErrorKindQuery, err)
		}

		clientRow, err := queries.LockOIDCClientByID(ctx, candidateFamily.ClientID)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock refresh client", ErrorKindQuery, err)
		}
		clientValue := mapClient(clientRow)
		if err := loadClientChildren(ctx, queries, &clientValue); err != nil {
			return err
		}
		if !sameAuthenticatedClient(clientValue, input.Client) {
			return token.ErrInvalidGrant
		}

		grantRow, err := queries.LockConsentGrantByUserClient(ctx, sqlcgen.LockConsentGrantByUserClientParams{
			UserID: candidateFamily.UserID, ClientID: candidateFamily.ClientID,
		})
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock refresh consent grant", ErrorKindQuery, err)
		}
		grant := mapConsentGrant(grantRow)
		if grant.ID != candidateFamily.ConsentGrantID || grant.RevokedAt != nil || grant.Version < 1 {
			return token.ErrInvalidGrant
		}

		familyRow, err := queries.LockRefreshTokenFamilyByID(ctx, candidate.FamilyID)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock refresh token family", ErrorKindQuery, err)
		}
		family := mapRefreshFamily(familyRow)
		if family.ID != candidateFamily.ID || family.UserID != userRow.ID || family.ClientID != clientValue.ID ||
			family.ConsentGrantID != grant.ID || family.RevokedAt != nil || !input.Now.UTC().Before(family.AbsoluteExpiresAt) {
			return token.ErrInvalidGrant
		}

		presentedRow, err := queries.LockRefreshTokenByID(ctx, candidate.ID)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("lock refresh token generation", ErrorKindQuery, err)
		}
		presented := mapRefreshGeneration(presentedRow)
		if presented.FamilyID != family.ID || !bytes.Equal(presented.TokenHash, input.TokenHash) {
			return token.ErrInvalidGrant
		}
		if presented.ConsumedAt != nil {
			if _, err := queries.RevokeRefreshTokenFamily(ctx, sqlcgen.RevokeRefreshTokenFamilyParams{
				RevokedAt: timestamp(input.Now), RevokeReason: pointerString("reuse"), ID: family.ID,
			}); err != nil {
				return wrapError("revoke reused refresh token family", ErrorKindQuery, err)
			}
			familyID := family.ID
			if _, err := queries.RevokeLiveAccessTokensByFamily(ctx, sqlcgen.RevokeLiveAccessTokensByFamilyParams{
				RevokedAt: timestamp(input.Now), RefreshFamilyID: &familyID,
			}); err != nil {
				return wrapError("revoke access tokens after refresh reuse", ErrorKindQuery, err)
			}
			if err := insertProtocolAudit(ctx, queries, audit.RefreshTokenReuseDetected, audit.ResultRejected, family.UserID, audit.TargetRefreshToken, presented.ID, input.RequestID, []string{"reused"}, input.Now, &events); err != nil {
				return err
			}
			if err := insertProtocolAudit(ctx, queries, audit.RefreshTokenFamilyRevoked, audit.ResultSuccess, family.UserID, audit.TargetRefreshFamily, family.ID, input.RequestID, []string{"revoked"}, input.Now, &events); err != nil {
				return err
			}
			reuseDetected = true
			return nil
		}
		if !input.Now.UTC().Before(presented.ExpiresAt) {
			return token.ErrInvalidGrant
		}

		accessScopes, err := token.SelectRefreshAccessScopes(input.RequestedScopes, family.Scopes, grant.Scopes, clientValue.Scopes)
		if err != nil {
			return err
		}
		minted, err := mint(ctx, token.RefreshAuthority{
			Presented: presented, Family: family, Grant: grant, User: mapUser(userRow),
			Client: clientValue, AccessScopes: accessScopes, IssuedAt: input.Now,
		})
		if err != nil {
			return err
		}
		if !validRefreshMinted(minted, presented, family, input.Now) {
			return token.ErrInvalid
		}
		if _, err := queries.ConsumeRefreshToken(ctx, sqlcgen.ConsumeRefreshTokenParams{
			ConsumedAt: timestamp(input.Now), ID: presented.ID,
		}); isNoRows(err) {
			return token.ErrInvalidGrant
		} else if err != nil {
			return wrapError("consume refresh token generation", ErrorKindQuery, err)
		}
		if _, err := queries.CreateRefreshToken(ctx, sqlcgen.CreateRefreshTokenParams{
			ID: minted.ReplacementTokenID, FamilyID: family.ID,
			TokenHash: append([]byte(nil), minted.ReplacementTokenHash...), Generation: presented.Generation + 1,
			IssuedAt: timestamp(minted.IssuedAt), ExpiresAt: timestamp(minted.ReplacementExpiresAt),
		}); err != nil {
			return wrapError("create replacement refresh token", ErrorKindQuery, err)
		}
		familyID, sourceID, bindingID := family.ID, presented.ID, family.SessionBindingID
		if err := queries.CreateRefreshAccessToken(ctx, sqlcgen.CreateRefreshAccessTokenParams{
			ID: minted.AccessTokenID, JtiHash: append([]byte(nil), minted.JTIHash...),
			ConsentGrantID: grant.ID, UserID: family.UserID, ClientID: family.ClientID,
			Scopes: accessScopes, IssuedAt: timestamp(minted.IssuedAt), ExpiresAt: timestamp(minted.AccessExpiresAt),
			SourceRefreshTokenID: &sourceID, RefreshFamilyID: &familyID,
			OriginSessionID: family.OriginSessionID, SessionBindingID: &bindingID,
		}); err != nil {
			return wrapError("create refresh-sourced access token", ErrorKindQuery, err)
		}
		if err := insertProtocolAudit(ctx, queries, audit.RefreshTokenRotated, audit.ResultSuccess, family.UserID, audit.TargetRefreshToken, presented.ID, input.RequestID, []string{"consumed", "rotated"}, input.Now, &events); err != nil {
			return err
		}
		if err := insertProtocolAudit(ctx, queries, audit.AccessTokenIssued, audit.ResultSuccess, family.UserID, audit.TargetAccessToken, minted.AccessTokenID, input.RequestID, []string{"issued"}, input.Now, &events); err != nil {
			return err
		}
		response = token.Response{
			AccessToken: minted.AccessToken, TokenType: "Bearer",
			ExpiresIn:    int64(minted.AccessExpiresAt.Sub(minted.IssuedAt) / time.Second),
			RefreshToken: minted.ReplacementClearToken, Scope: strings.Join(accessScopes, " "),
		}
		return nil
	}, resetAttempt)
	if err == nil {
		s.observeAuditEvents(events)
	}
	if err == nil && reuseDetected {
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
		var family *token.RefreshFamily
		if metadata.RefreshFamilyID != nil {
			familyRow, familyErr := queries.GetRefreshTokenFamilyByID(ctx, *metadata.RefreshFamilyID)
			if isNoRows(familyErr) {
				return token.ErrInvalidToken
			}
			if familyErr != nil {
				return wrapError("get access token refresh family", ErrorKindQuery, familyErr)
			}
			mapped := mapRefreshFamily(familyRow)
			family = &mapped
		}
		result = token.AccessAuthority{
			Metadata: metadata, Grant: mapConsentGrant(grantRow), User: mapUser(userRow), Client: clientValue, Family: family,
		}
		return nil
	}, func() { result = token.AccessAuthority{} })
	return result, err
}

// CleanupProtocolArtifacts deletes expired metadata only after an additional
// retention window chosen by the caller. Read paths never depend on cleanup.
func (s *Store) CleanupProtocolArtifacts(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for {
		var access, codes int64
		err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
			var err error
			// Code retirement detaches any retained Code-sourced Access metadata
			// through ON DELETE SET NULL; each artifact remains independently bounded.
			codes, err = queries.DeleteRetiredAuthorizationCodes(ctx, sqlcgen.DeleteRetiredAuthorizationCodesParams{
				Cutoff: timestamp(cutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean authorization code metadata", ErrorKindQuery, err)
			}
			access, err = queries.DeleteRetiredAccessTokens(ctx, sqlcgen.DeleteRetiredAccessTokensParams{
				Cutoff: timestamp(cutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean access token metadata", ErrorKindQuery, err)
			}
			return nil
		}, func() {
			access = 0
			codes = 0
		})
		if err != nil {
			return total, err
		}
		total += codes + access
		if access < int64(cleanupBatchSize) && codes < int64(cleanupBatchSize) {
			return total, nil
		}
	}
}

// CleanupRefreshArtifacts retires generations only after the family evidence
// window closes, then removes now-unreferenced families. Access metadata is
// cleaned by CleanupProtocolArtifacts first; the family query still checks for
// remaining Access references so FK retention cannot turn into a failed batch.
func (s *Store) CleanupRefreshArtifacts(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for {
		var generations, families int64
		err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
			var err error
			generations, err = queries.DeleteRetiredRefreshTokens(ctx, sqlcgen.DeleteRetiredRefreshTokensParams{
				Cutoff: timestamp(cutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean refresh token generations", ErrorKindQuery, err)
			}
			families, err = queries.DeleteRetiredRefreshTokenFamilies(ctx, sqlcgen.DeleteRetiredRefreshTokenFamiliesParams{
				Cutoff: timestamp(cutoff), BatchLimit: cleanupBatchSize,
			})
			if err != nil {
				return wrapError("clean refresh token families", ErrorKindQuery, err)
			}
			return nil
		}, func() {
			generations = 0
			families = 0
		})
		if err != nil {
			return total, err
		}
		total += generations + families
		if generations < int64(cleanupBatchSize) && families < int64(cleanupBatchSize) {
			return total, nil
		}
	}
}

func validMintedTokens(value token.Minted, now time.Time, offline bool) bool {
	if value.AccessTokenID == uuid.Nil || len(value.JTIHash) != sha256.Size || value.AccessToken == "" || value.IDToken == "" ||
		!value.IssuedAt.Equal(now.UTC()) || !value.AccessExpiresAt.After(value.IssuedAt) || !value.IDExpiresAt.After(value.IssuedAt) ||
		value.AccessExpiresAt.After(value.IssuedAt.Add(30*time.Minute)) || value.IDExpiresAt.After(value.IssuedAt.Add(15*time.Minute)) {
		return false
	}
	if !offline {
		return value.InitialRefresh == nil
	}
	initial := value.InitialRefresh
	if initial == nil || initial.FamilyID == uuid.Nil || initial.TokenID == uuid.Nil || len(initial.TokenHash) != sha256.Size ||
		initial.ClearToken == "" || !initial.ExpiresAt.After(value.IssuedAt) || initial.ExpiresAt.After(initial.AbsoluteExpiresAt) ||
		!initial.AbsoluteExpiresAt.After(value.IssuedAt) || initial.ExpiresAt.After(value.IssuedAt.Add(30*24*time.Hour)) ||
		initial.AbsoluteExpiresAt.After(value.IssuedAt.Add(365*24*time.Hour)) {
		return false
	}
	digest, err := token.DigestPresentedRefreshToken(initial.ClearToken)
	return err == nil && bytes.Equal(digest, initial.TokenHash)
}

func validRefreshMinted(value token.RefreshMinted, presented token.RefreshGeneration, family token.RefreshFamily, now time.Time) bool {
	if value.AccessTokenID == uuid.Nil || value.ReplacementTokenID == uuid.Nil || value.ReplacementTokenID == presented.ID ||
		len(value.JTIHash) != sha256.Size || len(value.ReplacementTokenHash) != sha256.Size || value.AccessToken == "" || value.ReplacementClearToken == "" ||
		!value.IssuedAt.Equal(now.UTC()) || !value.AccessExpiresAt.After(value.IssuedAt) || value.AccessExpiresAt.After(value.IssuedAt.Add(30*time.Minute)) ||
		!value.ReplacementExpiresAt.After(value.IssuedAt) || value.ReplacementExpiresAt.After(value.IssuedAt.Add(30*24*time.Hour)) ||
		value.ReplacementExpiresAt.After(family.AbsoluteExpiresAt) || presented.Generation == int64(^uint64(0)>>1) {
		return false
	}
	digest, err := token.DigestPresentedRefreshToken(value.ReplacementClearToken)
	return err == nil && bytes.Equal(digest, value.ReplacementTokenHash)
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
		IssuanceSource: token.IssuanceSource(row.IssuanceSource), SourceRefreshTokenID: row.SourceRefreshTokenID,
		RefreshFamilyID: row.RefreshFamilyID, OriginSessionID: row.OriginSessionID, SessionBindingID: row.SessionBindingID,
		RevokedAt: optionalTime(row.RevokedAt), RevokeReason: valueString(row.RevokeReason),
	}
}

func mapRefreshFamily(row sqlcgen.RefreshTokenFamily) token.RefreshFamily {
	return token.RefreshFamily{
		ID: row.ID, OriginAuthorizationCodeID: row.OriginAuthorizationCodeID,
		ConsentGrantID: row.ConsentGrantID, UserID: row.UserID, ClientID: row.ClientID,
		OriginSessionID: row.OriginSessionID, SessionBindingID: row.SessionBindingID,
		Scopes: append([]string(nil), row.Scopes...), CreatedAt: requiredTime(row.CreatedAt),
		AbsoluteExpiresAt: requiredTime(row.AbsoluteExpiresAt), RevokedAt: optionalTime(row.RevokedAt),
		RevokeReason: valueString(row.RevokeReason),
	}
}

func mapRefreshGeneration(row sqlcgen.RefreshToken) token.RefreshGeneration {
	return token.RefreshGeneration{
		ID: row.ID, FamilyID: row.FamilyID, TokenHash: append([]byte(nil), row.TokenHash...),
		Generation: row.Generation, IssuedAt: requiredTime(row.IssuedAt), ExpiresAt: requiredTime(row.ExpiresAt),
		ConsumedAt: optionalTime(row.ConsumedAt),
	}
}

func errorsIsClientNotFound(err error) bool {
	return errors.Is(err, clientdomain.ErrNotFound)
}

// RevokeToken applies an authenticated, uniform RFC 7009 mutation. Unknown,
// inactive, malformed, and wrong-owner candidates commit no authority or Audit.
func (s *Store) RevokeToken(ctx context.Context, lookup token.RevocationLookup) error {
	if lookup.Client.ID == uuid.Nil || lookup.Now.IsZero() {
		return nil
	}
	if validLifecycleHash(lookup.AccessJTIHash) {
		candidate, err := s.queries.GetAccessTokenByJTIHash(ctx, lookup.AccessJTIHash)
		if err == nil {
			return s.revokeAccessCandidate(ctx, lookup, candidate)
		}
		if !isNoRows(err) {
			return wrapError("find access revocation candidate", ErrorKindQuery, err)
		}
	}
	if validLifecycleHash(lookup.RefreshTokenHash) {
		candidate, err := s.queries.GetRefreshTokenByHash(ctx, lookup.RefreshTokenHash)
		if err == nil {
			return s.revokeRefreshCandidate(ctx, lookup, candidate)
		}
		if !isNoRows(err) {
			return wrapError("find refresh revocation candidate", ErrorKindQuery, err)
		}
	}
	return nil
}

func (s *Store) revokeAccessCandidate(ctx context.Context, lookup token.RevocationLookup, candidate sqlcgen.AccessToken) error {
	var events []audit.Event
	err := s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		userRow, err := queries.LockUserByID(ctx, candidate.UserID)
		if isNoRows(err) || err == nil && identity.Status(userRow.Status) != identity.StatusActive {
			return nil
		}
		if err != nil {
			return wrapError("lock access revocation user", ErrorKindQuery, err)
		}
		clientRow, err := queries.LockOIDCClientByID(ctx, candidate.ClientID)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock access revocation client", ErrorKindQuery, err)
		}
		clientValue := mapClient(clientRow)
		if err := loadClientChildren(ctx, queries, &clientValue); err != nil {
			return err
		}
		if !sameAuthenticatedClient(clientValue, lookup.Client) {
			return nil
		}
		grantRow, err := queries.LockConsentGrantByUserClient(ctx, sqlcgen.LockConsentGrantByUserClientParams{
			UserID: candidate.UserID, ClientID: candidate.ClientID,
		})
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock access revocation grant", ErrorKindQuery, err)
		}
		grant := mapConsentGrant(grantRow)
		if grant.ID != candidate.ConsentGrantID || grant.RevokedAt != nil ||
			len(consent.Difference(candidate.Scopes, consent.Intersection(grant.Scopes, clientValue.Scopes))) != 0 {
			return nil
		}
		if candidate.RefreshFamilyID != nil {
			familyRow, familyErr := queries.LockRefreshTokenFamilyByID(ctx, *candidate.RefreshFamilyID)
			if isNoRows(familyErr) {
				return nil
			}
			if familyErr != nil {
				return wrapError("lock access revocation family", ErrorKindQuery, familyErr)
			}
			family := mapRefreshFamily(familyRow)
			if family.RevokedAt != nil || !lookup.Now.Before(family.AbsoluteExpiresAt) ||
				family.UserID != candidate.UserID || family.ClientID != candidate.ClientID || family.ConsentGrantID != candidate.ConsentGrantID ||
				len(consent.Difference(candidate.Scopes, family.Scopes)) != 0 {
				return nil
			}
		}
		locked, err := queries.LockAccessTokenByID(ctx, candidate.ID)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock access revocation token", ErrorKindQuery, err)
		}
		metadata := mapAccessMetadata(locked)
		if metadata.ClientID != lookup.Client.ID || metadata.RevokedAt != nil || !lookup.Now.Before(metadata.ExpiresAt) ||
			!bytes.Equal(metadata.JTIHash, lookup.AccessJTIHash) {
			return nil
		}
		if _, err := queries.RevokeAccessToken(ctx, sqlcgen.RevokeAccessTokenParams{
			RevokedAt: timestamp(lookup.Now), RevokeReason: pointerString("client_revocation"), ID: metadata.ID,
		}); err != nil {
			return wrapError("revoke access token", ErrorKindQuery, err)
		}
		if err := insertProtocolAudit(ctx, queries, audit.AccessTokenRevoked, audit.ResultSuccess, metadata.UserID, audit.TargetAccessToken, metadata.ID, lookup.RequestID, []string{"revoked"}, lookup.Now, &events); err != nil {
			return err
		}
		return nil
	}, func() { events = nil })
	if err == nil {
		s.observeAuditEvents(events)
	}
	return err
}

func (s *Store) revokeRefreshCandidate(ctx context.Context, lookup token.RevocationLookup, candidate sqlcgen.RefreshToken) error {
	candidateFamily, err := s.queries.GetRefreshTokenFamilyByID(ctx, candidate.FamilyID)
	if isNoRows(err) {
		return nil
	}
	if err != nil {
		return wrapError("find refresh revocation family", ErrorKindQuery, err)
	}
	var events []audit.Event
	err = s.inTx(ctx, pgx.TxOptions{}, func(queries *sqlcgen.Queries) error {
		userRow, err := queries.LockUserByID(ctx, candidateFamily.UserID)
		if isNoRows(err) || err == nil && identity.Status(userRow.Status) != identity.StatusActive {
			return nil
		}
		if err != nil {
			return wrapError("lock refresh revocation user", ErrorKindQuery, err)
		}
		clientRow, err := queries.LockOIDCClientByID(ctx, candidateFamily.ClientID)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock refresh revocation client", ErrorKindQuery, err)
		}
		clientValue := mapClient(clientRow)
		if err := loadClientChildren(ctx, queries, &clientValue); err != nil {
			return err
		}
		if !sameAuthenticatedClient(clientValue, lookup.Client) {
			return nil
		}
		grantRow, err := queries.LockConsentGrantByUserClient(ctx, sqlcgen.LockConsentGrantByUserClientParams{
			UserID: candidateFamily.UserID, ClientID: candidateFamily.ClientID,
		})
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock refresh revocation grant", ErrorKindQuery, err)
		}
		grant := mapConsentGrant(grantRow)
		if grant.ID != candidateFamily.ConsentGrantID || grant.RevokedAt != nil {
			return nil
		}
		familyRow, err := queries.LockRefreshTokenFamilyByID(ctx, candidate.FamilyID)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock refresh revocation family", ErrorKindQuery, err)
		}
		family := mapRefreshFamily(familyRow)
		if family.RevokedAt != nil || !lookup.Now.Before(family.AbsoluteExpiresAt) ||
			family.UserID != userRow.ID || family.ClientID != clientValue.ID || family.ConsentGrantID != grant.ID {
			return nil
		}
		presentedRow, err := queries.LockRefreshTokenByID(ctx, candidate.ID)
		if isNoRows(err) {
			return nil
		}
		if err != nil {
			return wrapError("lock refresh revocation generation", ErrorKindQuery, err)
		}
		presented := mapRefreshGeneration(presentedRow)
		if presented.FamilyID != family.ID || !bytes.Equal(presented.TokenHash, lookup.RefreshTokenHash) {
			return nil
		}
		if _, err := queries.RevokeRefreshTokenFamily(ctx, sqlcgen.RevokeRefreshTokenFamilyParams{
			RevokedAt: timestamp(lookup.Now), RevokeReason: pointerString("client_revocation"), ID: family.ID,
		}); err != nil {
			return wrapError("revoke refresh token family by client", ErrorKindQuery, err)
		}
		familyID := family.ID
		if _, err := queries.RevokeLiveAccessTokensByFamily(ctx, sqlcgen.RevokeLiveAccessTokensByFamilyParams{
			RevokedAt: timestamp(lookup.Now), RefreshFamilyID: &familyID,
		}); err != nil {
			return wrapError("revoke family access tokens by client", ErrorKindQuery, err)
		}
		if err := insertProtocolAudit(ctx, queries, audit.RefreshTokenFamilyRevoked, audit.ResultSuccess, family.UserID, audit.TargetRefreshFamily, family.ID, lookup.RequestID, []string{"revoked"}, lookup.Now, &events); err != nil {
			return err
		}
		return nil
	}, func() { events = nil })
	if err == nil {
		s.observeAuditEvents(events)
	}
	return err
}

// GetRefreshTokenAuthority returns one repeatable-read, digest-only snapshot for
// restricted introspection. Policy evaluation remains in the token service.
func (s *Store) GetRefreshTokenAuthority(ctx context.Context, hash []byte) (token.RefreshTokenAuthority, error) {
	if !validLifecycleHash(hash) {
		return token.RefreshTokenAuthority{}, token.ErrInvalidGrant
	}
	var result token.RefreshTokenAuthority
	err := s.inTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(queries *sqlcgen.Queries) error {
		generationRow, err := queries.GetRefreshTokenByHash(ctx, hash)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("get refresh token for introspection", ErrorKindQuery, err)
		}
		familyRow, err := queries.GetRefreshTokenFamilyByID(ctx, generationRow.FamilyID)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("get refresh family for introspection", ErrorKindQuery, err)
		}
		userRow, err := queries.GetUserByID(ctx, familyRow.UserID)
		if isNoRows(err) {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("get refresh user for introspection", ErrorKindQuery, err)
		}
		clientValue, err := loadClient(ctx, queries, familyRow.ClientID)
		if err != nil {
			if errorsIsClientNotFound(err) {
				return token.ErrInvalidGrant
			}
			return err
		}
		grantRow, err := queries.GetConsentGrantByUserClient(ctx, sqlcgen.GetConsentGrantByUserClientParams{
			UserID: familyRow.UserID, ClientID: familyRow.ClientID,
		})
		if isNoRows(err) || err == nil && grantRow.ID != familyRow.ConsentGrantID {
			return token.ErrInvalidGrant
		}
		if err != nil {
			return wrapError("get refresh grant for introspection", ErrorKindQuery, err)
		}
		result = token.RefreshTokenAuthority{
			Generation: mapRefreshGeneration(generationRow), Family: mapRefreshFamily(familyRow),
			Grant: mapConsentGrant(grantRow), User: mapUser(userRow), Client: clientValue,
		}
		return nil
	}, func() { result = token.RefreshTokenAuthority{} })
	return result, err
}

func validLifecycleHash(value []byte) bool { return len(value) == sha256.Size }
