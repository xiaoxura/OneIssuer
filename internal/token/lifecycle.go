package token

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
)

const maxPresentedLifecycleTokenBytes = 16 << 10

// RevocationInput carries one authenticated caller and a transient clear Token.
// Token and Hint must never be persisted, audited, logged, or returned.
type RevocationInput struct {
	Client    clientdomain.Client
	Token     string
	Hint      string
	RequestID string
	Now       time.Time
}

// RevocationLookup is the digest-only storage boundary. At most one candidate
// digest is normally populated because the Access and Refresh grammars are
// deliberately disjoint.
type RevocationLookup struct {
	Client           clientdomain.Client
	AccessJTIHash    []byte
	RefreshTokenHash []byte
	RequestID        string
	Now              time.Time
}

// RefreshTokenAuthority is a consistent snapshot used by restricted
// introspection. It contains no clear Token or Client secret.
type RefreshTokenAuthority struct {
	Generation RefreshGeneration
	Family     RefreshFamily
	Grant      consent.Grant
	User       identity.User
	Client     clientdomain.Client
}

// IntrospectionInput carries a transient clear value and an already
// authenticated Confidential Client.
type IntrospectionInput struct {
	Client clientdomain.Client
	Token  string
	Hint   string
	Now    time.Time
}

// IntrospectionResponse is the exact Phase 4 field union. Inactive responses
// serialize to only {"active":false}; fields irrelevant to a token type remain
// omitted.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Audience  string `json:"aud,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// Revoke applies RFC 7009's uniform authenticated success semantics. Malformed,
// unknown, expired, and wrong-owner values are deliberately successful no-ops.
func (s *Service) Revoke(ctx context.Context, input RevocationInput) error {
	input.Now = input.Now.UTC()
	if !activeClient(input.Client) || input.Now.IsZero() || input.Token == "" ||
		len(input.Token) > maxPresentedLifecycleTokenBytes || strings.TrimSpace(input.Token) != input.Token {
		s.observe("revoke", "success")
		return nil
	}
	lookup := RevocationLookup{Client: input.Client, RequestID: input.RequestID, Now: input.Now}
	if claims, err := s.verifyAccessToken(input.Token, input.Now); err == nil {
		lookup.AccessJTIHash = HashJTI(claims.JWTID)
	}
	if digest, err := DigestPresentedRefreshToken(input.Token); err == nil {
		lookup.RefreshTokenHash = digest
	}
	if len(lookup.AccessJTIHash) == 0 && len(lookup.RefreshTokenHash) == 0 {
		s.observe("revoke", "success")
		return nil
	}
	if err := s.repository.RevokeToken(ctx, lookup); err != nil {
		s.observe("revoke", "failure")
		return err
	}
	s.observe("revoke", "success")
	return nil
}

// Introspect implements the restricted Confidential-owning-Client profile.
// Every authority failure is the same minimal inactive response; infrastructure
// failures remain errors so handlers cannot turn them into false success.
func (s *Service) Introspect(ctx context.Context, input IntrospectionInput) (IntrospectionResponse, error) {
	input.Now = input.Now.UTC()
	if input.Client.Type != clientdomain.TypeConfidential || input.Client.TokenEndpointAuthMethod != clientdomain.AuthMethodClientSecretBasic ||
		!activeClient(input.Client) || input.Now.IsZero() || input.Token == "" || len(input.Token) > maxPresentedLifecycleTokenBytes ||
		strings.TrimSpace(input.Token) != input.Token {
		s.observe("introspect", "rejected")
		return IntrospectionResponse{Active: false}, nil
	}

	tryRefreshFirst := input.Hint == "refresh_token"
	if tryRefreshFirst {
		if response, found, err := s.introspectRefresh(ctx, input); err != nil || found {
			return s.observeIntrospection(response, err)
		}
		if response, found, err := s.introspectAccess(ctx, input); err != nil || found {
			return s.observeIntrospection(response, err)
		}
	} else {
		if response, found, err := s.introspectAccess(ctx, input); err != nil || found {
			return s.observeIntrospection(response, err)
		}
		if response, found, err := s.introspectRefresh(ctx, input); err != nil || found {
			return s.observeIntrospection(response, err)
		}
	}
	return s.observeIntrospection(IntrospectionResponse{Active: false}, nil)
}

func (s *Service) introspectAccess(ctx context.Context, input IntrospectionInput) (IntrospectionResponse, bool, error) {
	claims, err := s.verifyAccessToken(input.Token, input.Now)
	if err != nil {
		return IntrospectionResponse{}, false, nil
	}
	authority, err := s.repository.GetAccessTokenAuthority(ctx, HashJTI(claims.JWTID), input.Now)
	if errors.Is(err, ErrInvalidToken) {
		return IntrospectionResponse{Active: false}, true, nil
	}
	if err != nil {
		return IntrospectionResponse{}, true, err
	}
	if authority.Client.ID != input.Client.ID || authority.Client.ClientID != input.Client.ClientID ||
		!s.accessAuthorityMatches(authority, claims, input.Now) {
		return IntrospectionResponse{Active: false}, true, nil
	}
	effective := consent.Intersection(authority.Metadata.Scopes, consent.Intersection(authority.Grant.Scopes, authority.Client.Scopes))
	if authority.Family != nil {
		effective = consent.Intersection(effective, authority.Family.Scopes)
	}
	if len(effective) == 0 || !slices.Contains(effective, "openid") {
		return IntrospectionResponse{Active: false}, true, nil
	}
	return IntrospectionResponse{
		Active: true, TokenType: "Bearer", ClientID: authority.Client.ClientID,
		Scope: strings.Join(effective, " "), Subject: authority.User.Subject,
		Issuer: s.issuer, Audience: s.userinfoAudience,
		IssuedAt: authority.Metadata.IssuedAt.Unix(), ExpiresAt: authority.Metadata.ExpiresAt.Unix(),
	}, true, nil
}

func (s *Service) introspectRefresh(ctx context.Context, input IntrospectionInput) (IntrospectionResponse, bool, error) {
	digest, err := DigestPresentedRefreshToken(input.Token)
	if err != nil {
		return IntrospectionResponse{}, false, nil
	}
	authority, err := s.repository.GetRefreshTokenAuthority(ctx, digest)
	if errors.Is(err, ErrInvalidGrant) {
		return IntrospectionResponse{Active: false}, true, nil
	}
	if err != nil {
		return IntrospectionResponse{}, true, err
	}
	generation, family := authority.Generation, authority.Family
	if authority.Client.ID != input.Client.ID || authority.Client.ClientID != input.Client.ClientID ||
		generation.ID == uuid.Nil || generation.FamilyID != family.ID || !bytes.Equal(generation.TokenHash, digest) ||
		generation.ConsumedAt != nil || !input.Now.Before(generation.ExpiresAt) || family.RevokedAt != nil || !input.Now.Before(family.AbsoluteExpiresAt) ||
		authority.User.ID != family.UserID || authority.User.Status != identity.StatusActive ||
		authority.Client.ID != family.ClientID || !activeClient(authority.Client) ||
		authority.Grant.ID != family.ConsentGrantID || authority.Grant.UserID != family.UserID || authority.Grant.ClientID != family.ClientID ||
		authority.Grant.RevokedAt != nil || authority.Grant.Version < 1 {
		return IntrospectionResponse{Active: false}, true, nil
	}
	effective, scopeErr := SelectRefreshAccessScopes(nil, family.Scopes, authority.Grant.Scopes, authority.Client.Scopes)
	if scopeErr != nil {
		return IntrospectionResponse{Active: false}, true, nil
	}
	return IntrospectionResponse{
		Active: true, ClientID: authority.Client.ClientID, Scope: strings.Join(effective, " "),
		Subject: authority.User.Subject, Issuer: s.issuer,
		IssuedAt: generation.IssuedAt.Unix(), ExpiresAt: generation.ExpiresAt.Unix(),
	}, true, nil
}

func (s *Service) observeIntrospection(response IntrospectionResponse, err error) (IntrospectionResponse, error) {
	if err != nil {
		s.observe("introspect", "failure")
		return IntrospectionResponse{}, err
	}
	result := "inactive"
	if response.Active {
		result = "active"
	}
	s.observe("introspect", result)
	return response, nil
}
