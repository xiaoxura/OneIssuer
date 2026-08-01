// Package identity owns user, credential, normalization, password-policy, and
// password-verification rules. It intentionally knows nothing about HTTP
// cookies or administrator route authorization.
package identity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the complete phase-two user status set.
type Status string

const (
	// StatusActive permits authentication and session use.
	StatusActive Status = "active"
	// StatusDisabled rejects authentication and invalidates sessions.
	StatusDisabled Status = "disabled"
)

// Role is the intentionally minimal phase-two role set.
type Role string

const (
	// RoleUser grants self-service identity and session access.
	RoleUser Role = "user"
	// RoleAdmin additionally grants management access.
	RoleAdmin Role = "admin"
)

var (
	// ErrInvalidInput identifies a policy or syntax failure safe to map to a
	// stable validation response.
	ErrInvalidInput = errors.New("identity input is invalid")
	// ErrDuplicate identifies a normalized username/email conflict without
	// exposing a PostgreSQL error.
	ErrDuplicate = errors.New("identity already exists")
	// ErrConflict identifies an optimistic-concurrency conflict without
	// conflating a stale version with a duplicate identifier.
	ErrConflict = errors.New("identity update conflict")
	// ErrInvalidCredentials is deliberately shared by unknown, disabled, and
	// bad-password browser responses.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrDisabled is an internal classification. Browser callers must map it to
	// the same message/status as ErrInvalidCredentials.
	ErrDisabled = errors.New("user is disabled")
	// ErrNotFound identifies a resource invisible to the caller.
	ErrNotFound = errors.New("user not found")
	// ErrLastAdmin protects the final active administrator.
	ErrLastAdmin = errors.New("last active administrator is protected")
	// ErrBootstrapExists means an administrator already exists.
	ErrBootstrapExists = errors.New("administrator already exists")
)

// ValidationError contains only a stable field/code pair; it never includes a
// submitted value (which may be a password or account identifier).
type ValidationError struct {
	Field string
	Code  string
}

func (e *ValidationError) Error() string { return ErrInvalidInput.Error() }
func (e *ValidationError) Unwrap() error { return ErrInvalidInput }

// User is the credential-free domain representation returned to callers.
type User struct {
	ID                 uuid.UUID  `json:"id"`
	Subject            string     `json:"subject"`
	Username           string     `json:"username"`
	UsernameNormalized string     `json:"-"`
	DisplayName        string     `json:"display_name"`
	Email              string     `json:"email"`
	EmailNormalized    string     `json:"-"`
	EmailVerified      bool       `json:"email_verified"`
	Status             Status     `json:"status"`
	Role               Role       `json:"role"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	Version            time.Time  `json:"-"`
}

// LoginRecord is a narrow internal projection. It must never be serialized,
// logged, or passed to an HTTP response.
type LoginRecord struct {
	User         User
	PasswordHash string
}

// CreateInput contains user-supplied account fields. Password is deliberately
// write-only and no type containing it has JSON output tags.
type CreateInput struct {
	Username    string
	DisplayName string
	Email       string
	Password    string
}

// PreparedUser is ready for an atomic persistence operation. PasswordHash is
// still sensitive and callers must not log the struct.
type PreparedUser struct {
	User         User
	PasswordHash string
}

// UpdateInput is a restricted administrative profile/status patch. Credentials
// are intentionally absent from this phase-two operation.
type UpdateInput struct {
	Username    *string
	DisplayName *string
	Email       *string
	Status      *Status
	Role        *Role
}
