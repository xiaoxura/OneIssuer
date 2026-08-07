// Package session owns opaque browser tokens, server-side login session
// validity, CSRF binding, cookie attributes, rotation, and revocation.
package session

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/identity"
)

var (
	// ErrUnauthenticated indicates missing, invalid, revoked, disabled, or expired authority.
	ErrUnauthenticated = errors.New("authentication required")
	// ErrInvalidCSRF indicates a missing, expired, or mismatched CSRF value.
	ErrInvalidCSRF = errors.New("CSRF validation failed")
	// ErrNotFound hides a session not owned or visible to the caller.
	ErrNotFound = errors.New("session not found")
	// ErrConsumed indicates that a pre-auth session has already been used.
	ErrConsumed = errors.New("pre-auth session already consumed")
)

// Record is the database-safe representation of a newly issued authenticated
// session. It contains hashes only, never browser tokens.
type Record struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	SessionBindingID uuid.UUID
	TokenHash        []byte
	CSRFHash         []byte
	CSRFExpiresAt    time.Time
	CreatedAt        time.Time
	LastSeenAt       time.Time
	AuthenticatedAt  time.Time
	ExpiresAt        time.Time
	IdleExpiresAt    time.Time
	UserAgentHash    []byte
	IPPrefix         string
}

// Issued contains values that may be sent to the browser exactly once and the
// hash-only record that persistence accepts. It must never be logged.
type Issued struct {
	Token     string
	CSRFToken string
	Record    Record
}

// PreAuthRecord binds one zero-authority browser flow to a server transaction.
type PreAuthRecord struct {
	ID                uuid.UUID
	TokenHash         []byte
	CSRFHash          []byte
	AuthTransactionID uuid.UUID
	CreatedAt         time.Time
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
	AttemptCount      int16
}

// IssuedPreAuth is write-only browser material plus its hash-only record.
type IssuedPreAuth struct {
	Token     string
	CSRFToken string
	Record    PreAuthRecord
}

// Principal is resolved from a server-side session on every authenticated
// request; current user status is therefore never cached solely in a cookie.
type Principal struct {
	SessionID        uuid.UUID
	SessionBindingID uuid.UUID
	User             identity.User
	CSRFHash         []byte
	CSRFExpiresAt    time.Time
	CreatedAt        time.Time
	LastSeenAt       time.Time
	AuthenticatedAt  time.Time
	ExpiresAt        time.Time
	IdleExpiresAt    time.Time
	RevokedAt        *time.Time
}

// Summary is safe for current-user/admin list responses.
type Summary struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"user_id,omitempty"`
	Username        string     `json:"username,omitempty"`
	UserStatus      string     `json:"user_status,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	AuthenticatedAt time.Time  `json:"authenticated_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	IdleExpiresAt   time.Time  `json:"idle_expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	RevokeReason    string     `json:"revoke_reason,omitempty"`
	IPPrefix        string     `json:"ip_prefix,omitempty"`
	Current         bool       `json:"current,omitempty"`
}
