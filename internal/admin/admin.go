// Package admin maps authenticated administrator principals onto the minimal
// phase-two management use cases. It is intentionally not a generic RBAC layer.
package admin

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/pagination"
	"github.com/oneissuer/oneissuer/internal/session"
)

var (
	// ErrForbidden indicates that the principal is not an active administrator.
	ErrForbidden = errors.New("administrator permission required")
	// ErrRecentAuth indicates that a sensitive operation requires reauthentication.
	ErrRecentAuth = errors.New("recent authentication required")
	// ErrInvalidFilter indicates an unsupported or oversized list filter.
	ErrInvalidFilter = errors.New("invalid administrative filter")
)

// UpdateUserCommit describes the atomic user, session, and audit mutation.
type UpdateUserCommit struct {
	Actor          uuid.UUID
	Updated        identity.User
	Changed        []string
	RevokeSessions bool
	Event          audit.Event
	SessionEvent   *audit.Event
}

// Repository is the persistence boundary required by administrative use cases.
type Repository interface {
	HasAdmin(context.Context) (bool, error)
	BootstrapAdmin(context.Context, identity.PreparedUser, audit.Event) error
	GetUser(context.Context, uuid.UUID) (identity.User, error)
	ListUsers(context.Context, string, pagination.Cursor, int) ([]identity.User, error)
	CreateManagedUser(context.Context, identity.PreparedUser, audit.Event) error
	UpdateManagedUser(context.Context, UpdateUserCommit) (identity.User, error)
	RevokeAllManagedUserSessions(context.Context, uuid.UUID, time.Time, audit.Event) (int64, error)
	ListManagedSessions(context.Context, pagination.Cursor, int) ([]session.Summary, error)
	RevokeManagedSession(context.Context, uuid.UUID, time.Time, audit.Event) error
	ListAuditEvents(context.Context, string, pagination.Cursor, int) ([]audit.Event, error)
	AppendAudit(context.Context, audit.Event) error
}

// Service enforces administrative authorization and recent-authentication policy.
type Service struct {
	repository   Repository
	identities   *identity.Service
	clients      *clientdomain.Service
	reauthWindow time.Duration
}

// NewService creates an administrative use-case service.
func NewService(repository Repository, identities *identity.Service, clients *clientdomain.Service, reauthWindow time.Duration) *Service {
	return &Service{repository: repository, identities: identities, clients: clients, reauthWindow: reauthWindow}
}

// HasAdmin reports whether bootstrap has already created an administrator.
func (s *Service) HasAdmin(ctx context.Context) (bool, error) { return s.repository.HasAdmin(ctx) }

// Bootstrap creates the first administrator and its audit event atomically.
func (s *Service) Bootstrap(ctx context.Context, input identity.CreateInput, requestID string, now time.Time) (identity.User, error) {
	prepared, err := s.identities.PrepareUser(ctx, input, identity.RoleAdmin, now)
	if err != nil {
		return identity.User{}, err
	}
	event, err := audit.New(audit.AdminBootstrapSucceeded, audit.ResultSuccess, nil, audit.TargetUser, &prepared.User.ID, requestID, []string{"created", "role"}, now)
	if err != nil {
		return identity.User{}, err
	}
	if err := s.repository.BootstrapAdmin(ctx, prepared, event); err != nil {
		if errors.Is(err, identity.ErrBootstrapExists) {
			s.RecordBootstrapRejected(ctx, requestID, now)
		}
		return identity.User{}, err
	}
	return prepared.User, nil
}

// RecordBootstrapRejected appends a value-free audit event for a rejected attempt.
func (s *Service) RecordBootstrapRejected(ctx context.Context, requestID string, now time.Time) {
	event, err := audit.New(audit.AdminBootstrapRejected, audit.ResultRejected, nil, "", nil, requestID, nil, now)
	if err == nil {
		_ = s.repository.AppendAudit(ctx, event)
	}
}

// Authorize requires an active user with the administrator role.
func (s *Service) Authorize(principal session.Principal) error {
	if principal.User.Status != identity.StatusActive || principal.User.Role != identity.RoleAdmin {
		return ErrForbidden
	}
	return nil
}

// RequireRecent additionally requires authentication within the configured window.
func (s *Service) RequireRecent(principal session.Principal, now time.Time) error {
	if err := s.Authorize(principal); err != nil {
		return err
	}
	if s.reauthWindow <= 0 || now.UTC().Sub(principal.AuthenticatedAt) > s.reauthWindow || now.Before(principal.AuthenticatedAt) {
		return ErrRecentAuth
	}
	return nil
}

// ListUsers returns a bounded page of users visible to an administrator.
func (s *Service) ListUsers(ctx context.Context, principal session.Principal, search string, cursor pagination.Cursor, limit int) ([]identity.User, error) {
	if err := s.Authorize(principal); err != nil {
		return nil, err
	}
	search = identity.NormalizeSearchPrefix(search)
	if len(search) > 320 {
		return nil, ErrInvalidFilter
	}
	return s.repository.ListUsers(ctx, search, cursor, pagination.Limit(limit)+1)
}

// GetUser returns one managed user after administrator authorization.
func (s *Service) GetUser(ctx context.Context, principal session.Principal, id uuid.UUID) (identity.User, error) {
	if err := s.Authorize(principal); err != nil {
		return identity.User{}, err
	}
	return s.repository.GetUser(ctx, id)
}

// CreateUser creates a managed user; administrator creation requires recent authentication.
func (s *Service) CreateUser(ctx context.Context, principal session.Principal, input identity.CreateInput, role identity.Role, requestID string, now time.Time) (identity.User, error) {
	if err := s.Authorize(principal); err != nil {
		return identity.User{}, err
	}
	if role == identity.RoleAdmin {
		if err := s.RequireRecent(principal, now); err != nil {
			return identity.User{}, err
		}
	}
	prepared, err := s.identities.PrepareUser(ctx, input, role, now)
	if err != nil {
		return identity.User{}, err
	}
	event, err := audit.New(audit.UserCreated, audit.ResultSuccess, &principal.User.ID, audit.TargetUser, &prepared.User.ID, requestID, []string{"created", "role"}, now)
	if err != nil {
		return identity.User{}, err
	}
	if err := s.repository.CreateManagedUser(ctx, prepared, event); err != nil {
		return identity.User{}, err
	}
	return prepared.User, nil
}

// UpdateUser applies a validated optimistic update and revokes sessions after role or status changes.
func (s *Service) UpdateUser(ctx context.Context, principal session.Principal, id uuid.UUID, input identity.UpdateInput, requestID string, now time.Time) (identity.User, error) {
	if err := s.Authorize(principal); err != nil {
		return identity.User{}, err
	}
	existing, err := s.repository.GetUser(ctx, id)
	if err != nil {
		return identity.User{}, err
	}
	updated, changed, err := s.identities.PrepareUpdate(existing, input, now)
	if err != nil {
		return identity.User{}, err
	}
	revoke := existing.Status != updated.Status || existing.Role != updated.Role
	if revoke {
		if err := s.RequireRecent(principal, now); err != nil {
			return identity.User{}, err
		}
	}
	eventType := audit.UserUpdated
	if existing.Status != updated.Status {
		eventType = audit.UserStatusChanged
	} else if existing.Role != updated.Role {
		eventType = audit.UserRoleChanged
	}
	event, err := audit.New(eventType, audit.ResultSuccess, &principal.User.ID, audit.TargetUser, &id, requestID, changed, now)
	if err != nil {
		return identity.User{}, err
	}
	commit := UpdateUserCommit{Actor: principal.User.ID, Updated: updated, Changed: changed, RevokeSessions: revoke, Event: event}
	if revoke {
		sessionEvent, eventErr := audit.New(audit.SessionsRevokedAll, audit.ResultSuccess, &principal.User.ID, audit.TargetUser, &id, requestID, []string{"revoked"}, now)
		if eventErr != nil {
			return identity.User{}, eventErr
		}
		commit.SessionEvent = &sessionEvent
	}
	return s.repository.UpdateManagedUser(ctx, commit)
}

// RevokeUserSessions revokes every active login session owned by a user.
func (s *Service) RevokeUserSessions(ctx context.Context, principal session.Principal, id uuid.UUID, requestID string, now time.Time) (int64, error) {
	if err := s.Authorize(principal); err != nil {
		return 0, err
	}
	event, err := audit.New(audit.SessionsRevokedAll, audit.ResultSuccess, &principal.User.ID, audit.TargetUser, &id, requestID, []string{"revoked"}, now)
	if err != nil {
		return 0, err
	}
	return s.repository.RevokeAllManagedUserSessions(ctx, id, now.UTC(), event)
}

// CreateClient creates a client and returns a confidential secret at most once.
func (s *Service) CreateClient(ctx context.Context, principal session.Principal, input clientdomain.CreateInput, requestID string, now time.Time) (clientdomain.Created, error) {
	if err := s.RequireRecent(principal, now); err != nil {
		return clientdomain.Created{}, err
	}
	return s.clients.Create(ctx, principal.User.ID, input, requestID, now)
}

// ListClients returns a bounded page of credential-free clients.
func (s *Service) ListClients(ctx context.Context, principal session.Principal, cursor pagination.Cursor, limit int) ([]clientdomain.Client, error) {
	if err := s.Authorize(principal); err != nil {
		return nil, err
	}
	return s.clients.List(ctx, cursor, limit)
}

// GetClient returns one credential-free client.
func (s *Service) GetClient(ctx context.Context, principal session.Principal, id uuid.UUID) (clientdomain.Client, error) {
	if err := s.Authorize(principal); err != nil {
		return clientdomain.Client{}, err
	}
	return s.clients.Get(ctx, id)
}

// UpdateClient applies a validated client update after recent authentication.
func (s *Service) UpdateClient(ctx context.Context, principal session.Principal, id uuid.UUID, input clientdomain.UpdateInput, requestID string, now time.Time) (clientdomain.Client, error) {
	if err := s.RequireRecent(principal, now); err != nil {
		return clientdomain.Client{}, err
	}
	value, _, err := s.clients.Update(ctx, principal.User.ID, id, input, requestID, now)
	return value, err
}

// RotateClientSecret replaces a confidential secret and returns its clear value once.
func (s *Service) RotateClientSecret(ctx context.Context, principal session.Principal, id uuid.UUID, requestID string, now time.Time) (string, error) {
	if err := s.RequireRecent(principal, now); err != nil {
		return "", err
	}
	return s.clients.RotateSecret(ctx, principal.User.ID, id, requestID, now)
}

// ListSessions returns a bounded administrative page of session summaries.
func (s *Service) ListSessions(ctx context.Context, principal session.Principal, cursor pagination.Cursor, limit int) ([]session.Summary, error) {
	if err := s.Authorize(principal); err != nil {
		return nil, err
	}
	return s.repository.ListManagedSessions(ctx, cursor, pagination.Limit(limit)+1)
}

// RevokeSession revokes one session and appends an audit event atomically.
func (s *Service) RevokeSession(ctx context.Context, principal session.Principal, id uuid.UUID, requestID string, now time.Time) error {
	if err := s.Authorize(principal); err != nil {
		return err
	}
	event, err := audit.New(audit.SessionRevoked, audit.ResultSuccess, &principal.User.ID, audit.TargetSession, &id, requestID, []string{"revoked"}, now)
	if err != nil {
		return err
	}
	return s.repository.RevokeManagedSession(ctx, id, now.UTC(), event)
}

// ListAudit returns a bounded page of append-only audit events.
func (s *Service) ListAudit(ctx context.Context, principal session.Principal, eventType string, cursor pagination.Cursor, limit int) ([]audit.Event, error) {
	if err := s.Authorize(principal); err != nil {
		return nil, err
	}
	if !audit.ValidEventType(eventType) {
		return nil, ErrInvalidFilter
	}
	return s.repository.ListAuditEvents(ctx, eventType, cursor, pagination.Limit(limit)+1)
}
