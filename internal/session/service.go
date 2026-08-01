package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/pagination"
)

// Repository is the narrow session persistence boundary. Revocation methods
// accept an audit event so adapters can commit state and audit atomically.
type Repository interface {
	FindLoginSession(context.Context, []byte) (Principal, error)
	TouchLoginSession(context.Context, uuid.UUID, time.Time, time.Time) error
	RotateSessionCSRF(context.Context, uuid.UUID, []byte, time.Time) error
	ListUserSessions(context.Context, uuid.UUID, pagination.Cursor, int) ([]Summary, error)
	RevokeUserSession(context.Context, uuid.UUID, uuid.UUID, time.Time, audit.Event) error
	RevokeOtherUserSessions(context.Context, uuid.UUID, uuid.UUID, time.Time, audit.Event) (int64, error)
	RevokeSessionByHash(context.Context, []byte, time.Time, string, audit.Event) error
	CleanupSessions(context.Context, time.Time, time.Time) (int64, error)
}

// Metrics records low-cardinality revocation outcomes.
type Metrics interface {
	SessionRevoked(reason string)
}

// Service validates every authenticated request against current server state.
type Service struct {
	repository Repository
	tokens     *TokenManager
	touchEvery time.Duration
	metrics    Metrics
}

// NewService creates a server-authoritative session service.
func NewService(repository Repository, tokens *TokenManager, observers ...Metrics) *Service {
	service := &Service{repository: repository, tokens: tokens, touchEvery: 5 * time.Minute}
	if len(observers) > 0 {
		service.metrics = observers[0]
	}
	return service
}

// Authenticate resolves a clear cookie and revalidates all server-side session state.
func (s *Service) Authenticate(ctx context.Context, token string, now time.Time) (Principal, error) {
	if !validToken(token, "s1_") {
		return Principal{}, ErrUnauthenticated
	}
	principal, err := s.repository.FindLoginSession(ctx, HashToken(token))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, err
	}
	now = now.UTC()
	if principal.RevokedAt != nil || !now.Before(principal.ExpiresAt) || !now.Before(principal.IdleExpiresAt) || principal.User.Status != identity.StatusActive {
		return Principal{}, ErrUnauthenticated
	}
	if now.Sub(principal.LastSeenAt) >= s.touchEvery {
		idle := s.tokens.NextIdleExpiry(now, principal.ExpiresAt)
		if err := s.repository.TouchLoginSession(ctx, principal.SessionID, now, idle); err != nil {
			return Principal{}, err
		}
		principal.LastSeenAt = now
		principal.IdleExpiresAt = idle
	}
	return principal, nil
}

// ValidateCSRF checks the presented value and its server-authoritative expiry.
func (s *Service) ValidateCSRF(principal Principal, token string, now time.Time) error {
	if !now.UTC().Before(principal.CSRFExpiresAt) || !csrfMatches(token, principal.CSRFHash) {
		return ErrInvalidCSRF
	}
	return nil
}

// EnsureCSRF reuses a valid clear cookie or rotates the digest when the browser
// lost/expired it. Rotation is safe on authenticated GET because no authority
// is granted and a cross-site caller cannot read the resulting token.
func (s *Service) EnsureCSRF(ctx context.Context, principal *Principal, presented string, now time.Time) (token string, rotated bool, err error) {
	if principal == nil {
		return "", false, ErrUnauthenticated
	}
	if s.ValidateCSRF(*principal, presented, now) == nil {
		return presented, false, nil
	}
	token, hash, expires, err := s.tokens.NewCSRF(now)
	if err != nil {
		return "", false, err
	}
	if err := s.repository.RotateSessionCSRF(ctx, principal.SessionID, hash, expires); err != nil {
		return "", false, err
	}
	principal.CSRFHash = hash
	principal.CSRFExpiresAt = expires
	return token, true, nil
}

// ListMine returns a bounded page containing only the principal's sessions.
func (s *Service) ListMine(ctx context.Context, principal Principal, cursor pagination.Cursor, limit int) ([]Summary, error) {
	items, err := s.repository.ListUserSessions(ctx, principal.User.ID, cursor, pagination.Limit(limit)+1)
	if err != nil {
		return nil, err
	}
	for index := range items {
		items[index].Current = items[index].ID == principal.SessionID
	}
	return items, nil
}

// RevokeMine revokes a session only when it belongs to the principal.
func (s *Service) RevokeMine(ctx context.Context, principal Principal, target uuid.UUID, requestID string, now time.Time) error {
	event, err := audit.New(audit.SessionRevoked, audit.ResultSuccess, &principal.User.ID, audit.TargetSession, &target, requestID, []string{"revoked"}, now)
	if err != nil {
		return err
	}
	err = s.repository.RevokeUserSession(ctx, principal.User.ID, target, now.UTC(), event)
	if err == nil && s.metrics != nil {
		s.metrics.SessionRevoked("user")
	}
	return err
}

// RevokeOthers revokes every session except the principal's current session.
func (s *Service) RevokeOthers(ctx context.Context, principal Principal, requestID string, now time.Time) (int64, error) {
	target := principal.User.ID
	event, err := audit.New(audit.SessionsRevokedAll, audit.ResultSuccess, &principal.User.ID, audit.TargetUser, &target, requestID, []string{"revoked"}, now)
	if err != nil {
		return 0, err
	}
	count, err := s.repository.RevokeOtherUserSessions(ctx, principal.User.ID, principal.SessionID, now.UTC(), event)
	if err == nil && s.metrics != nil {
		s.metrics.SessionRevoked("others")
	}
	return count, err
}

// Logout revokes the exact current session selected by the clear cookie digest.
func (s *Service) Logout(ctx context.Context, principal Principal, clearToken, requestID string, now time.Time) error {
	event, err := audit.New(audit.SessionRevoked, audit.ResultSuccess, &principal.User.ID, audit.TargetSession, &principal.SessionID, requestID, []string{"revoked"}, now)
	if err != nil {
		return err
	}
	err = s.repository.RevokeSessionByHash(ctx, HashToken(clearToken), now.UTC(), "logout", event)
	if err == nil && s.metrics != nil {
		s.metrics.SessionRevoked("logout")
	}
	return err
}

// Cleanup removes expired pre-auth records and retired sessions beyond retention.
func (s *Service) Cleanup(ctx context.Context, now time.Time) (int64, error) {
	// Keep retired authenticated records for audit/debug summaries for 30 days;
	// pre-auth records contain no authority and may be removed immediately.
	return s.repository.CleanupSessions(ctx, now.UTC(), now.UTC().Add(-30*24*time.Hour))
}
