// Package token owns the phase-three JWT claim profile, bounded local signing,
// atomic Authorization Code exchange contract, Access Token metadata checks,
// and scope-minimized UserInfo projection.
package token

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
)

const (
	maxCompactTokenBytes = 16 << 10
	jtiPrefix            = "jti_"
)

var (
	// ErrInvalid identifies invalid internal configuration or use-case input.
	ErrInvalid = errors.New("token operation is invalid")
	// ErrInvalidGrant deliberately merges all Code binding/replay failures.
	ErrInvalidGrant = errors.New("authorization grant is invalid")
	// ErrInvalidToken deliberately merges all Bearer validation failures.
	ErrInvalidToken = errors.New("access token is invalid")
)

// KeyStore is the restricted signing/verification view required by the Token
// service. Private JWK material cannot be returned through this interface.
type KeyStore interface {
	Sign([]byte, string) (string, error)
	PublicKeys() []jose.JSONWebKey
}

// ExchangeInput contains a validated Code digest and authenticated Client. The
// clear Code is absent; verifier remains transient and must never be persisted.
type ExchangeInput struct {
	CodeHash     []byte
	Client       clientdomain.Client
	RedirectURI  string
	CodeVerifier string
	RequestID    string
	Now          time.Time
}

// Authority is built by the repository only after locking/revalidating Code,
// User, Client, Grant, Redirect URI, Scope, and PKCE.
type Authority struct {
	CodeID          uuid.UUID
	GrantID         uuid.UUID
	User            identity.User
	Client          clientdomain.Client
	Scopes          []string
	Nonce           string
	AuthenticatedAt time.Time
	IssuedAt        time.Time
}

// Minted is generated inside the repository transaction. JWTs remain transient;
// only AccessTokenID/JTIHash and lifecycle metadata may be persisted.
type Minted struct {
	AccessTokenID   uuid.UUID
	JTIHash         []byte
	AccessToken     string
	IDToken         string
	IssuedAt        time.Time
	AccessExpiresAt time.Time
	IDExpiresAt     time.Time
}

// Response is emitted only after the repository commit succeeds.
type Response struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// AccessMetadata is the database authority required for UserInfo acceptance.
type AccessMetadata struct {
	ID                  uuid.UUID
	JTIHash             []byte
	AuthorizationCodeID uuid.UUID
	ConsentGrantID      uuid.UUID
	UserID              uuid.UUID
	ClientID            uuid.UUID
	Scopes              []string
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

// AccessAuthority joins metadata with current credential-free domain views.
type AccessAuthority struct {
	Metadata AccessMetadata
	Grant    consent.Grant
	User     identity.User
	Client   clientdomain.Client
}

// MintFunc runs after the repository has locked and validated all authority.
type MintFunc func(context.Context, Authority) (Minted, error)

// Repository owns Code consumption + Access metadata atomicity and the
// server-authoritative UserInfo metadata lookup.
type Repository interface {
	ExchangeAuthorizationCode(context.Context, ExchangeInput, MintFunc) (Response, error)
	GetAccessTokenAuthority(context.Context, []byte, time.Time) (AccessAuthority, error)
}

// Metrics records only bounded token operation/result labels.
type Metrics interface {
	Token(operation, result string)
}

// Service implements the fixed RS256 claim and lifecycle profile.
type Service struct {
	repository       Repository
	keys             KeyStore
	random           io.Reader
	issuer           string
	userinfoAudience string
	idTokenTTL       time.Duration
	accessTokenTTL   time.Duration
	clockSkew        time.Duration
	metrics          Metrics
}

// NewService creates a token service from a canonical origin Issuer.
func NewService(repository Repository, keys KeyStore, randomSource io.Reader, issuer string, idTokenTTL, accessTokenTTL, clockSkew time.Duration, metrics Metrics) (*Service, error) {
	parsed, err := url.Parse(issuer)
	if repository == nil || keys == nil || err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil ||
		idTokenTTL < time.Minute || idTokenTTL > 15*time.Minute || accessTokenTTL < time.Minute || accessTokenTTL > 30*time.Minute || clockSkew < 0 || clockSkew > 2*time.Minute {
		return nil, ErrInvalid
	}
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &Service{
		repository: repository, keys: keys, random: randomSource, issuer: issuer,
		userinfoAudience: issuer + "/oauth2/userinfo", idTokenTTL: idTokenTTL,
		accessTokenTTL: accessTokenTTL, clockSkew: clockSkew, metrics: metrics,
	}, nil
}

// Exchange delegates validation and atomic consumption to the repository. The
// mint callback signs only after all database authority has been locked.
func (s *Service) Exchange(ctx context.Context, input ExchangeInput) (Response, error) {
	input.Now = input.Now.UTC()
	if len(input.CodeHash) != sha256.Size || input.RedirectURI == "" || input.Now.IsZero() || !activeClient(input.Client) ||
		authorization.ValidateVerifier(input.CodeVerifier) != nil {
		s.observe("exchange", "rejected")
		return Response{}, ErrInvalidGrant
	}
	mintAttempted := false
	response, err := s.repository.ExchangeAuthorizationCode(ctx, input, func(mintCtx context.Context, authority Authority) (Minted, error) {
		mintAttempted = true
		return s.mint(mintCtx, authority)
	})
	if err != nil {
		result := "failure"
		if errors.Is(err, ErrInvalidGrant) {
			result = "rejected"
		}
		s.observe("exchange", result)
		if mintAttempted {
			s.observe("issuance", "failure")
		}
		return Response{}, err
	}
	s.observe("exchange", "success")
	s.observe("issuance", "success")
	return response, nil
}

func (s *Service) mint(_ context.Context, authority Authority) (Minted, error) {
	issuedAt := authority.IssuedAt.UTC()
	authenticatedAt := authority.AuthenticatedAt.UTC()
	scopes, err := consent.CanonicalScopes(authority.Scopes)
	if err != nil || authority.CodeID == uuid.Nil || authority.GrantID == uuid.Nil || authority.User.ID == uuid.Nil ||
		authority.User.Status != identity.StatusActive || !activeClient(authority.Client) ||
		authenticatedAt.IsZero() || authenticatedAt.After(issuedAt) || !scopeSubset(scopes, authority.Client.Scopes) {
		return Minted{}, ErrInvalidGrant
	}

	jti, err := newJTI(s.random)
	if err != nil {
		return Minted{}, err
	}
	accessTokenID, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return Minted{}, errors.New("access token identifier generation failed")
	}
	idExpires := issuedAt.Add(s.idTokenTTL)
	accessExpires := issuedAt.Add(s.accessTokenTTL)
	idClaims := IDTokenClaims{
		Issuer: s.issuer, Subject: authority.User.Subject, Audience: authority.Client.ClientID,
		AuthorizedParty: authority.Client.ClientID, ExpiresAt: idExpires.Unix(), IssuedAt: issuedAt.Unix(),
		AuthTime: authenticatedAt.Unix(), Nonce: authority.Nonce,
	}
	applyProfileClaims(scopes, authority.User, &idClaims)
	idPayload, err := json.Marshal(idClaims)
	if err != nil {
		return Minted{}, errors.New("ID token claim serialization failed")
	}
	idToken, err := s.keys.Sign(idPayload, "JWT")
	if err != nil {
		return Minted{}, errors.New("ID token signing failed")
	}
	accessClaims := AccessTokenClaims{
		Issuer: s.issuer, Subject: authority.User.Subject, Audience: s.userinfoAudience,
		ClientID: authority.Client.ClientID, Scope: strings.Join(scopes, " "),
		IssuedAt: issuedAt.Unix(), ExpiresAt: accessExpires.Unix(), JWTID: jti,
	}
	accessPayload, err := json.Marshal(accessClaims)
	if err != nil {
		return Minted{}, errors.New("access token claim serialization failed")
	}
	accessToken, err := s.keys.Sign(accessPayload, "at+jwt")
	if err != nil {
		return Minted{}, errors.New("access token signing failed")
	}
	return Minted{
		AccessTokenID: accessTokenID, JTIHash: HashJTI(jti), AccessToken: accessToken, IDToken: idToken,
		IssuedAt: issuedAt, AccessExpiresAt: accessExpires, IDExpiresAt: idExpires,
	}, nil
}

// IDTokenClaims is the exact phase-three ID Token profile.
type IDTokenClaims struct {
	Issuer            string  `json:"iss"`
	Subject           string  `json:"sub"`
	Audience          string  `json:"aud"`
	AuthorizedParty   string  `json:"azp"`
	ExpiresAt         int64   `json:"exp"`
	IssuedAt          int64   `json:"iat"`
	AuthTime          int64   `json:"auth_time"`
	Nonce             string  `json:"nonce,omitempty"`
	Name              *string `json:"name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Email             *string `json:"email,omitempty"`
	EmailVerified     *bool   `json:"email_verified,omitempty"`
}

// AccessTokenClaims is the exact phase-three RFC 9068 JWT profile.
type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JWTID     string `json:"jti"`
}

// UserInfo is the only public projection returned for an Access Token.
type UserInfo struct {
	Subject           string  `json:"sub"`
	Name              *string `json:"name,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Email             *string `json:"email,omitempty"`
	EmailVerified     *bool   `json:"email_verified,omitempty"`
}

// UserInfoForAccessToken verifies JWS/header/claims, requires committed Access
// metadata, rechecks active User/Client/Grant policy, and returns minimal claims.
func (s *Service) UserInfoForAccessToken(ctx context.Context, compact string, now time.Time) (UserInfo, error) {
	claims, err := s.verifyAccessToken(compact, now.UTC())
	if err != nil {
		s.observe("userinfo", "rejected")
		return UserInfo{}, ErrInvalidToken
	}
	authority, err := s.repository.GetAccessTokenAuthority(ctx, HashJTI(claims.JWTID), now.UTC())
	if err != nil || !s.accessAuthorityMatches(authority, claims, now.UTC()) {
		s.observe("userinfo", "rejected")
		return UserInfo{}, ErrInvalidToken
	}
	result := UserInfo{Subject: authority.User.Subject}
	applyUserInfoClaims(authority.Metadata.Scopes, authority.User, &result)
	s.observe("userinfo", "success")
	return result, nil
}

func (s *Service) verifyAccessToken(compact string, now time.Time) (AccessTokenClaims, error) {
	if compact == "" || len(compact) > maxCompactTokenBytes || strings.TrimSpace(compact) != compact || strings.Count(compact, ".") != 2 {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	object, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(object.Signatures) != 1 {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	header := object.Signatures[0].Header
	typ, typeOK := header.ExtraHeaders[jose.HeaderKey("typ")].(string)
	if header.Algorithm != string(jose.RS256) || header.KeyID == "" || header.JSONWebKey != nil || header.Nonce != "" ||
		!typeOK || typ != "at+jwt" || len(header.ExtraHeaders) != 1 {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	var key *rsa.PublicKey
	for _, candidate := range s.keys.PublicKeys() {
		public, ok := candidate.Key.(*rsa.PublicKey)
		if candidate.KeyID == header.KeyID && candidate.Algorithm == string(jose.RS256) && candidate.Use == "sig" && candidate.IsPublic() && ok && public != nil && public.N != nil && public.N.BitLen() >= 2048 {
			if key != nil {
				return AccessTokenClaims{}, ErrInvalidToken
			}
			key = public
		}
	}
	if key == nil {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	payload, err := object.Verify(key)
	if err != nil {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	var claims AccessTokenClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	if claims.Issuer != s.issuer || claims.Audience != s.userinfoAudience || claims.Subject == "" || claims.ClientID == "" ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || time.Unix(claims.ExpiresAt, 0).Before(now.Add(-s.clockSkew)) ||
		time.Unix(claims.IssuedAt, 0).After(now.Add(s.clockSkew)) || time.Duration(claims.ExpiresAt-claims.IssuedAt)*time.Second > 30*time.Minute ||
		!validJTI(claims.JWTID) {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	scopes, err := parseScopeClaim(claims.Scope)
	if err != nil || !slices.Contains(scopes, "openid") {
		return AccessTokenClaims{}, ErrInvalidToken
	}
	return claims, nil
}

func (s *Service) accessAuthorityMatches(authority AccessAuthority, claims AccessTokenClaims, now time.Time) bool {
	metadata := authority.Metadata
	scopes, err := consent.CanonicalScopes(metadata.Scopes)
	if err != nil || metadata.ID == uuid.Nil || metadata.AuthorizationCodeID == uuid.Nil || metadata.ConsentGrantID == uuid.Nil ||
		metadata.UserID == uuid.Nil || metadata.ClientID == uuid.Nil || len(metadata.JTIHash) != sha256.Size ||
		!now.Before(metadata.ExpiresAt) || metadata.IssuedAt.IsZero() || !metadata.ExpiresAt.After(metadata.IssuedAt) ||
		authority.User.ID != metadata.UserID || authority.User.Status != identity.StatusActive ||
		authority.Client.ID != metadata.ClientID || !activeClient(authority.Client) ||
		authority.Grant.ID != metadata.ConsentGrantID || authority.Grant.UserID != metadata.UserID || authority.Grant.ClientID != metadata.ClientID {
		return false
	}
	claimScopes, err := parseScopeClaim(claims.Scope)
	if err != nil || !slices.Equal(scopes, claimScopes) || !scopeSubset(scopes, authority.Client.Scopes) ||
		len(consent.Difference(scopes, consent.Intersection(authority.Grant.Scopes, authority.Client.Scopes))) != 0 {
		return false
	}
	return claims.Issuer == s.issuer && claims.Audience == s.userinfoAudience && claims.Subject == authority.User.Subject &&
		claims.ClientID == authority.Client.ClientID && claims.IssuedAt == metadata.IssuedAt.Unix() && claims.ExpiresAt == metadata.ExpiresAt.Unix() &&
		bytes.Equal(HashJTI(claims.JWTID), metadata.JTIHash)
}

// HashJTI returns the domain-separated digest stored as Access metadata.
func HashJTI(jti string) []byte {
	digest := sha256.Sum256([]byte("oneissuer:access-token-jti:v1:" + jti))
	return digest[:]
}

func newJTI(source io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", errors.New("secure access token identifier generation failed")
	}
	return jtiPrefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func validJTI(value string) bool {
	if !strings.HasPrefix(value, jtiPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, jtiPrefix))
	return err == nil && len(decoded) == 16
}

func applyProfileClaims(scopes []string, user identity.User, claims *IDTokenClaims) {
	if slices.Contains(scopes, "profile") {
		claims.Name = stringPointer(user.DisplayName)
		claims.PreferredUsername = stringPointer(user.Username)
	}
	if slices.Contains(scopes, "email") {
		claims.Email = stringPointer(user.Email)
		claims.EmailVerified = boolPointer(user.EmailVerified)
	}
}

func applyUserInfoClaims(scopes []string, user identity.User, claims *UserInfo) {
	if slices.Contains(scopes, "profile") {
		claims.Name = stringPointer(user.DisplayName)
		claims.PreferredUsername = stringPointer(user.Username)
	}
	if slices.Contains(scopes, "email") {
		claims.Email = stringPointer(user.Email)
		claims.EmailVerified = boolPointer(user.EmailVerified)
	}
}

func parseScopeClaim(raw string) ([]string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\t\r\n") {
		return nil, ErrInvalidToken
	}
	parts := strings.Split(raw, " ")
	canonical, err := consent.CanonicalScopes(parts)
	if err != nil || strings.Join(canonical, " ") != raw {
		return nil, ErrInvalidToken
	}
	return canonical, nil
}

func activeClient(value clientdomain.Client) bool {
	return value.ID != uuid.Nil && value.ClientID != "" && value.Status == clientdomain.StatusActive &&
		((value.Type == clientdomain.TypePublic && value.TokenEndpointAuthMethod == clientdomain.AuthMethodNone) ||
			(value.Type == clientdomain.TypeConfidential && value.TokenEndpointAuthMethod == clientdomain.AuthMethodClientSecretBasic))
}

func scopeSubset(requested, allowed []string) bool {
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}

func stringPointer(value string) *string { return &value }
func boolPointer(value bool) *bool       { return &value }

func (s *Service) observe(operation, result string) {
	if s.metrics != nil {
		s.metrics.Token(operation, result)
	}
}
