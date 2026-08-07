package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/identity"
)

const (
	refreshTokenPrefix = "r1_"
	refreshTokenBytes  = 32
	maxRefreshRolling  = 30 * 24 * time.Hour
	maxRefreshAbsolute = 365 * 24 * time.Hour
	defaultRefreshTTL  = 30 * 24 * time.Hour
	defaultAbsoluteTTL = 90 * 24 * time.Hour
)

// IssuanceSource is the immutable source discriminator for Access metadata.
type IssuanceSource string

const (
	// IssuanceAuthorizationCode identifies an Access Token created by Code exchange.
	IssuanceAuthorizationCode IssuanceSource = "authorization_code"
	// IssuanceRefreshToken identifies an Access Token created by Refresh exchange.
	IssuanceRefreshToken IssuanceSource = "refresh_token"
)

// RefreshFamily is the immutable offline authority plus its terminal state.
type RefreshFamily struct {
	ID                        uuid.UUID
	OriginAuthorizationCodeID *uuid.UUID
	ConsentGrantID            uuid.UUID
	UserID                    uuid.UUID
	ClientID                  uuid.UUID
	OriginSessionID           *uuid.UUID
	SessionBindingID          uuid.UUID
	Scopes                    []string
	CreatedAt                 time.Time
	AbsoluteExpiresAt         time.Time
	RevokedAt                 *time.Time
	RevokeReason              string
}

// RefreshGeneration is one digest-only, single-use member of a family.
type RefreshGeneration struct {
	ID         uuid.UUID
	FamilyID   uuid.UUID
	TokenHash  []byte
	Generation int64
	IssuedAt   time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// RefreshInput contains only a validated presented digest, authenticated Client,
// and optional canonical Access-scope narrowing. A nil slice means scope was
// omitted; an empty explicit scope is rejected by the wire parser.
type RefreshInput struct {
	TokenHash       []byte
	Client          clientdomain.Client
	RequestedScopes []string
	RequestID       string
	Now             time.Time
}

// RefreshAuthority is assembled only after storage re-locks every mutable
// authority in the frozen lifecycle order.
type RefreshAuthority struct {
	Presented    RefreshGeneration
	Family       RefreshFamily
	Grant        consent.Grant
	User         identity.User
	Client       clientdomain.Client
	AccessScopes []string
	IssuedAt     time.Time
}

// RefreshMinted contains transient output plus digest-only replacement metadata.
type RefreshMinted struct {
	AccessTokenID         uuid.UUID
	JTIHash               []byte
	AccessToken           string
	IssuedAt              time.Time
	AccessExpiresAt       time.Time
	ReplacementTokenID    uuid.UUID
	ReplacementTokenHash  []byte
	ReplacementClearToken string
	ReplacementExpiresAt  time.Time
}

// RefreshMintFunc signs and generates a replacement while the repository holds
// all relevant locks. The clear replacement must be discarded on rollback.
type RefreshMintFunc func(context.Context, RefreshAuthority) (RefreshMinted, error)

// InitialRefresh is generated transiently while an offline Authorization Code
// exchange is inside its database transaction. Storage receives only TokenHash;
// ClearToken may leave the service only after the transaction commits.
type InitialRefresh struct {
	FamilyID          uuid.UUID
	TokenID           uuid.UUID
	TokenHash         []byte
	ClearToken        string
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
}

// ServiceOption applies a validated lifecycle option without breaking the
// phase-three constructor call sites.
type ServiceOption func(*Service) error

// WithRefreshLifetimes configures rolling generation and immutable family
// lifetimes. Values use the same hard bounds enforced by the schema.
func WithRefreshLifetimes(rollingTTL, absoluteTTL time.Duration) ServiceOption {
	return func(service *Service) error {
		if service == nil {
			return ErrInvalid
		}
		if _, _, err := RefreshDeadlines(time.Unix(1, 0), rollingTTL, absoluteTTL); err != nil {
			return err
		}
		service.refreshTokenTTL = rollingTTL
		service.refreshAbsoluteTTL = absoluteTTL
		return nil
	}
}

// GenerateRefreshToken returns a 256-bit opaque value and its domain-separated
// digest. The caller must discard the clear value unless the containing database
// transaction commits successfully.
func GenerateRefreshToken(source io.Reader) (string, []byte, error) {
	if source == nil {
		source = rand.Reader
	}
	raw := make([]byte, refreshTokenBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", nil, errors.New("secure refresh token generation failed")
	}
	tokenValue := refreshTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return tokenValue, HashRefreshToken(tokenValue), nil
}

// HashRefreshToken returns the only clear-Token derivative accepted by storage.
func HashRefreshToken(tokenValue string) []byte {
	digest := sha256.Sum256([]byte("oneissuer:refresh-token:v1:" + tokenValue))
	return digest[:]
}

// DigestPresentedRefreshToken enforces exact type/version/entropy grammar before
// deriving a storage lookup digest.
func DigestPresentedRefreshToken(tokenValue string) ([]byte, error) {
	if len(tokenValue) != len(refreshTokenPrefix)+43 || !strings.HasPrefix(tokenValue, refreshTokenPrefix) {
		return nil, ErrInvalidGrant
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(tokenValue, refreshTokenPrefix))
	if err != nil || len(raw) != refreshTokenBytes {
		return nil, ErrInvalidGrant
	}
	return HashRefreshToken(tokenValue), nil
}

// RefreshDeadlines validates configured lifetimes and returns the immutable family
// deadline plus generation-zero rolling deadline.
func RefreshDeadlines(issuedAt time.Time, rollingTTL, absoluteTTL time.Duration) (time.Time, time.Time, error) {
	issuedAt = issuedAt.UTC()
	if issuedAt.IsZero() || rollingTTL < time.Hour || rollingTTL > maxRefreshRolling ||
		absoluteTTL < 24*time.Hour || absoluteTTL > maxRefreshAbsolute || absoluteTTL < rollingTTL {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	absolute := issuedAt.Add(absoluteTTL)
	rolling := issuedAt.Add(rollingTTL)
	if rolling.After(absolute) {
		rolling = absolute
	}
	return rolling, absolute, nil
}

// ReplacementRefreshExpiry applies the rolling deadline without crossing the
// family's immutable absolute deadline.
func ReplacementRefreshExpiry(issuedAt time.Time, rollingTTL time.Duration, absolute time.Time) (time.Time, error) {
	issuedAt, absolute = issuedAt.UTC(), absolute.UTC()
	if issuedAt.IsZero() || absolute.IsZero() || !issuedAt.Before(absolute) || rollingTTL < time.Hour || rollingTTL > maxRefreshRolling {
		return time.Time{}, ErrInvalidGrant
	}
	expires := issuedAt.Add(rollingTTL)
	if expires.After(absolute) {
		expires = absolute
	}
	return expires, nil
}

// CanonicalRefreshScopes validates the single family Scope source of truth.
func CanonicalRefreshScopes(scopes []string) ([]string, error) {
	canonical, err := consent.CanonicalScopes(scopes)
	if err != nil || !slices.Contains(canonical, "openid") || !slices.Contains(canonical, "offline_access") {
		return nil, ErrInvalidGrant
	}
	return canonical, nil
}

// SelectRefreshAccessScopes computes the current effective authority and applies
// optional per-request narrowing without changing the family Scope.
func SelectRefreshAccessScopes(requested, familyScopes, grantScopes, clientScopes []string) ([]string, error) {
	family, err := CanonicalRefreshScopes(familyScopes)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	effective := consent.Intersection(consent.Intersection(family, grantScopes), clientScopes)
	if !slices.Contains(effective, "openid") || !slices.Contains(effective, "offline_access") {
		return nil, ErrInvalidGrant
	}
	if requested == nil {
		return effective, nil
	}
	canonical, err := consent.CanonicalScopes(requested)
	if err != nil || !slices.Equal(canonical, requested) || !scopeSubset(canonical, effective) {
		return nil, ErrInvalidScope
	}
	return canonical, nil
}
