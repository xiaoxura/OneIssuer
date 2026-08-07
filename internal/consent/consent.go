// Package consent owns the persistent OIDC scope-grant model and the rules for
// deciding whether a current request is already covered. It never accepts
// redirect URIs, state, nonce, PKCE material, or browser-provided client data.
package consent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

var (
	// ErrInvalid identifies malformed or internally inconsistent grant input.
	ErrInvalid = errors.New("consent grant is invalid")
	// ErrNotFound indicates that no grant exists for the user/client pair.
	ErrNotFound = errors.New("consent grant not found")
)

// Grant is the only persistent consent authority. It deliberately contains no
// token, redirect URI, state, nonce, PKCE material, or client secret.
type Grant struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ClientID  uuid.UUID
	Scopes    []string
	CreatedAt time.Time
	UpdatedAt time.Time
	RevokedAt *time.Time
	Version   int64
}

// Evaluation describes the request-relative view of a persisted grant. The
// effective scope set is always intersected with the client's current policy.
type Evaluation struct {
	Grant          *Grant
	Effective      []string
	AlreadyGranted []string
	NewScopes      []string
	Covers         bool
}

// ManagedGrant is the owner-safe current-user projection. It intentionally has
// no internal Grant/Client/family/Session identifier.
type ManagedGrant struct {
	ClientID               string              `json:"client_id"`
	ClientName             string              `json:"client_name"`
	ClientStatus           clientdomain.Status `json:"client_status"`
	Scopes                 []string            `json:"scopes"`
	CreatedAt              time.Time           `json:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at"`
	RevokedAt              *time.Time          `json:"revoked_at,omitempty"`
	HasActiveOfflineFamily bool                `json:"has_active_offline_family"`
}

// GrantCursor uses only the public list ordering keys.
type GrantCursor struct {
	UpdatedAt time.Time
	ClientID  string
}

// GrantPage is a bounded owner-only list response.
type GrantPage struct {
	Items      []ManagedGrant `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

// RevokeInput carries only the current owner and a public protocol Client ID.
type RevokeInput struct {
	UserID         uuid.UUID
	PublicClientID string
	RequestID      string
	Now            time.Time
}

// Repository is the read boundary used before the final atomic authorization
// commit. The commit path rechecks the grant under a PostgreSQL lock.
type Repository interface {
	GetConsentGrant(context.Context, uuid.UUID, uuid.UUID) (Grant, error)
	ListCurrentUserGrants(context.Context, uuid.UUID, GrantCursor, int, time.Time) ([]ManagedGrant, error)
	RevokeCurrentUserGrant(context.Context, RevokeInput) (ManagedGrant, error)
}

// ListMine returns a keyset page whose opaque cursor never embeds an internal UUID.
func (s *Service) ListMine(ctx context.Context, userID uuid.UUID, rawCursor string, limit int, now time.Time) (GrantPage, error) {
	if userID == uuid.Nil || limit < 1 || limit > 100 || now.IsZero() {
		return GrantPage{}, ErrInvalid
	}
	cursor, err := DecodeGrantCursor(rawCursor)
	if err != nil {
		return GrantPage{}, ErrInvalid
	}
	items, err := s.repository.ListCurrentUserGrants(ctx, userID, cursor, limit+1, now.UTC())
	if err != nil {
		return GrantPage{}, err
	}
	page := GrantPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = EncodeGrantCursor(GrantCursor{UpdatedAt: last.UpdatedAt, ClientID: last.ClientID})
	}
	return page, nil
}

// RevokeMine atomically revokes the owner-selected Grant and all dependent live
// offline authority. Wrong-owner and unknown Client selectors share ErrNotFound.
func (s *Service) RevokeMine(ctx context.Context, userID uuid.UUID, publicClientID, requestID string, now time.Time) (ManagedGrant, error) {
	if userID == uuid.Nil || !validPublicClientID(publicClientID) || now.IsZero() {
		return ManagedGrant{}, ErrNotFound
	}
	return s.repository.RevokeCurrentUserGrant(ctx, RevokeInput{
		UserID: userID, PublicClientID: publicClientID, RequestID: requestID, Now: now.UTC(),
	})
}

type grantCursorWire struct {
	Version   int    `json:"v"`
	UpdatedAt string `json:"u"`
	ClientID  string `json:"c"`
}

// EncodeGrantCursor emits a versioned opaque cursor containing only safe keys.
func EncodeGrantCursor(cursor GrantCursor) string {
	if cursor.UpdatedAt.IsZero() || !validPublicClientID(cursor.ClientID) {
		return ""
	}
	payload, _ := json.Marshal(grantCursorWire{Version: 1, UpdatedAt: cursor.UpdatedAt.UTC().Format(time.RFC3339Nano), ClientID: cursor.ClientID})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeGrantCursor strictly decodes the owner-list cursor.
func DecodeGrantCursor(raw string) (GrantCursor, error) {
	if raw == "" {
		return GrantCursor{}, nil
	}
	if len(raw) > 1024 || strings.TrimSpace(raw) != raw {
		return GrantCursor{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return GrantCursor{}, ErrInvalid
	}
	var wire grantCursorWire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != 1 || !validPublicClientID(wire.ClientID) {
		return GrantCursor{}, ErrInvalid
	}
	updated, err := time.Parse(time.RFC3339Nano, wire.UpdatedAt)
	if err != nil || updated.IsZero() || wire.UpdatedAt != updated.UTC().Format(time.RFC3339Nano) {
		return GrantCursor{}, ErrInvalid
	}
	return GrantCursor{UpdatedAt: updated.UTC(), ClientID: wire.ClientID}, nil
}

func validPublicClientID(value string) bool {
	if !strings.HasPrefix(value, "ois_cli_") || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, "ois_cli_"))
	return err == nil && len(decoded) == 24
}

// Service applies strict phase-three scope and active-client policy.
type Service struct {
	repository Repository
}

// NewService creates a consent evaluation service.
func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository}, nil
}

// Evaluate returns whether the current grant covers requested scopes after the
// current active Client scope policy is applied. Absence is a normal uncovered
// result rather than an error.
func (s *Service) Evaluate(ctx context.Context, userID uuid.UUID, clientValue clientdomain.Client, requested []string) (Evaluation, error) {
	requested, err := CanonicalScopes(requested)
	if err != nil || userID == uuid.Nil || !validActiveClient(clientValue) || !subset(requested, clientValue.Scopes) {
		return Evaluation{}, ErrInvalid
	}

	grant, err := s.repository.GetConsentGrant(ctx, userID, clientValue.ID)
	if errors.Is(err, ErrNotFound) {
		return Evaluation{NewScopes: append([]string(nil), requested...)}, nil
	}
	if err != nil {
		return Evaluation{}, err
	}
	if grant.ID == uuid.Nil || grant.UserID != userID || grant.ClientID != clientValue.ID || grant.Version < 1 ||
		grant.CreatedAt.IsZero() || grant.UpdatedAt.Before(grant.CreatedAt) ||
		(grant.RevokedAt != nil && grant.RevokedAt.Before(grant.CreatedAt)) {
		return Evaluation{}, ErrInvalid
	}
	grant.Scopes, err = CanonicalScopes(grant.Scopes)
	if err != nil {
		return Evaluation{}, ErrInvalid
	}

	effective := Intersection(grant.Scopes, clientValue.Scopes)
	if grant.RevokedAt != nil {
		effective = nil
	}
	already := Intersection(requested, effective)
	newScopes := Difference(requested, effective)
	grantCopy := grant
	return Evaluation{
		Grant: &grantCopy, Effective: effective, AlreadyGranted: already,
		NewScopes: newScopes, Covers: len(newScopes) == 0,
	}, nil
}

// CanonicalScopes validates and returns the sorted, unique phase-four scope
// set. Callers do not get permissive trimming or duplicate normalization.
func CanonicalScopes(scopes []string) ([]string, error) {
	if len(scopes) < 1 || len(scopes) > 4 {
		return nil, ErrInvalid
	}
	result := append([]string(nil), scopes...)
	for _, scope := range result {
		if !supported(scope) {
			return nil, ErrInvalid
		}
	}
	sort.Strings(result)
	for index, scope := range result {
		if index > 0 && result[index-1] == scope {
			return nil, ErrInvalid
		}
	}
	if !contains(result, "openid") {
		return nil, ErrInvalid
	}
	return result, nil
}

// Union returns a canonical union of two already-valid phase-four scope sets.
func Union(left, right []string) []string {
	set := make(map[string]bool, len(left)+len(right))
	for _, scope := range left {
		if supported(scope) {
			set[scope] = true
		}
	}
	for _, scope := range right {
		if supported(scope) {
			set[scope] = true
		}
	}
	return sortedSet(set)
}

// Intersection returns the supported canonical intersection.
func Intersection(left, right []string) []string {
	allowed := make(map[string]bool, len(right))
	for _, scope := range right {
		allowed[scope] = true
	}
	set := make(map[string]bool, len(left))
	for _, scope := range left {
		if supported(scope) && allowed[scope] {
			set[scope] = true
		}
	}
	return sortedSet(set)
}

// Difference returns supported values in left that are absent from right.
func Difference(left, right []string) []string {
	present := make(map[string]bool, len(right))
	for _, scope := range right {
		present[scope] = true
	}
	set := make(map[string]bool, len(left))
	for _, scope := range left {
		if supported(scope) && !present[scope] {
			set[scope] = true
		}
	}
	return sortedSet(set)
}

func validActiveClient(value clientdomain.Client) bool {
	if value.ID == uuid.Nil || value.Status != clientdomain.StatusActive {
		return false
	}
	return (value.Type == clientdomain.TypePublic && value.TokenEndpointAuthMethod == clientdomain.AuthMethodNone) ||
		(value.Type == clientdomain.TypeConfidential && value.TokenEndpointAuthMethod == clientdomain.AuthMethodClientSecretBasic)
}

func subset(values, allowed []string) bool {
	set := make(map[string]bool, len(allowed))
	for _, value := range allowed {
		set[value] = true
	}
	for _, value := range values {
		if !set[value] {
			return false
		}
	}
	return true
}

func supported(scope string) bool {
	return scope == "openid" || scope == "profile" || scope == "email" || scope == "offline_access"
}

func contains(scopes []string, target string) bool {
	index := sort.SearchStrings(scopes, target)
	return index < len(scopes) && scopes[index] == target
}

func sortedSet(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
