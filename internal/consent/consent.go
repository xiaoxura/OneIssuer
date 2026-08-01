// Package consent owns the persistent OIDC scope-grant model and the rules for
// deciding whether a current request is already covered. It never accepts
// redirect URIs, state, nonce, PKCE material, or browser-provided client data.
package consent

import (
	"context"
	"errors"
	"sort"
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

// Repository is the read boundary used before the final atomic authorization
// commit. The commit path rechecks the grant under a PostgreSQL lock.
type Repository interface {
	GetConsentGrant(context.Context, uuid.UUID, uuid.UUID) (Grant, error)
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
	if grant.ID == uuid.Nil || grant.UserID != userID || grant.ClientID != clientValue.ID ||
		grant.CreatedAt.IsZero() || grant.UpdatedAt.Before(grant.CreatedAt) {
		return Evaluation{}, ErrInvalid
	}
	grant.Scopes, err = CanonicalScopes(grant.Scopes)
	if err != nil {
		return Evaluation{}, ErrInvalid
	}

	effective := Intersection(grant.Scopes, clientValue.Scopes)
	already := Intersection(requested, effective)
	newScopes := Difference(requested, effective)
	grantCopy := grant
	return Evaluation{
		Grant: &grantCopy, Effective: effective, AlreadyGranted: already,
		NewScopes: newScopes, Covers: len(newScopes) == 0,
	}, nil
}

// CanonicalScopes validates and returns the sorted, unique phase-three scope
// set. Callers do not get permissive trimming or duplicate normalization.
func CanonicalScopes(scopes []string) ([]string, error) {
	if len(scopes) < 1 || len(scopes) > 3 {
		return nil, ErrInvalid
	}
	result := append([]string(nil), scopes...)
	for _, scope := range result {
		if scope != "openid" && scope != "profile" && scope != "email" {
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

// Union returns a canonical union of two already-valid phase-three scope sets.
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

// Intersection returns the supported canonical intersection. The right-hand
// side may include future registry scopes such as offline_access; they are not
// admitted into a phase-three grant.
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
	return scope == "openid" || scope == "profile" || scope == "email"
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
