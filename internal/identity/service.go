package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/config"
	"golang.org/x/text/unicode/norm"
)

// Service prepares credential-bearing writes and performs constant-shape login
// verification. Persistence/transaction boundaries are supplied by callers.
type Service struct {
	policy    PasswordPolicy
	hasher    *PasswordHasher
	random    io.Reader
	dummyHash string
}

// NewService creates the identity service and precomputes a dummy hash used for
// nonexistent-account login paths.
func NewService(ctx context.Context, cfg config.PasswordConfig, randomSource io.Reader) (*Service, error) {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	hasher, err := NewPasswordHasher(Argon2Params{
		MemoryKiB: cfg.Argon2MemoryKiB,
		Time:      cfg.Argon2Time,
		Threads:   cfg.Argon2Threads,
		SaltLen:   defaultSaltLen,
		KeyLen:    defaultKeyLen,
	}, cfg.MaxConcurrent, randomSource)
	if err != nil {
		return nil, err
	}
	dummy, err := hasher.Hash(ctx, "oneissuer-dummy-password-never-valid")
	if err != nil {
		return nil, fmt.Errorf("initialize password verifier: %w", err)
	}
	return &Service{
		policy:    PasswordPolicy{MinLength: cfg.MinLength, MaxBytes: cfg.MaxBytes},
		hasher:    hasher,
		random:    randomSource,
		dummyHash: dummy,
	}, nil
}

// PrepareUser validates/normalizes account fields, generates independent UUID
// and subject values, then hashes the exact submitted password.
func (s *Service) PrepareUser(ctx context.Context, input CreateInput, role Role, now time.Time) (PreparedUser, error) {
	username, usernameNormalized, err := NormalizeUsername(input.Username)
	if err != nil {
		return PreparedUser{}, err
	}
	email, emailNormalized, err := NormalizeEmail(input.Email)
	if err != nil {
		return PreparedUser{}, err
	}
	if usernameNormalized == emailNormalized {
		return PreparedUser{}, &ValidationError{Field: "username", Code: "ambiguous_identifier"}
	}
	displayName, err := normalizeDisplayName(input.DisplayName, username)
	if err != nil {
		return PreparedUser{}, err
	}
	if role != RoleUser && role != RoleAdmin {
		return PreparedUser{}, &ValidationError{Field: "role", Code: "invalid_value"}
	}
	if err := s.policy.ValidatePassword(input.Password); err != nil {
		return PreparedUser{}, err
	}
	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return PreparedUser{}, fmt.Errorf("generate user identifier")
	}
	subject, err := randomString(s.random, "sub_", 32)
	if err != nil {
		return PreparedUser{}, fmt.Errorf("generate user subject")
	}
	passwordHash, err := s.hasher.Hash(ctx, input.Password)
	if err != nil {
		return PreparedUser{}, err
	}
	now = now.UTC()
	return PreparedUser{
		User: User{
			ID:                 id,
			Subject:            subject,
			Username:           username,
			UsernameNormalized: usernameNormalized,
			DisplayName:        displayName,
			Email:              email,
			EmailNormalized:    emailNormalized,
			EmailVerified:      false,
			Status:             StatusActive,
			Role:               role,
			CreatedAt:          now,
			UpdatedAt:          now,
			Version:            1,
		},
		PasswordHash: passwordHash,
	}, nil
}

// PrepareUpdate applies a restricted patch and returns only whitelisted field
// names for audit. The existing Version is retained for optimistic persistence.
func (s *Service) PrepareUpdate(existing User, input UpdateInput, now time.Time) (User, []string, error) {
	updated := existing
	changed := make([]string, 0, 5)
	if input.Username != nil {
		display, normalized, err := NormalizeUsername(*input.Username)
		if err != nil {
			return User{}, nil, err
		}
		if display != existing.Username {
			updated.Username, updated.UsernameNormalized = display, normalized
			changed = append(changed, "username")
		}
	}
	if input.Email != nil {
		display, normalized, err := NormalizeEmail(*input.Email)
		if err != nil {
			return User{}, nil, err
		}
		if display != existing.Email {
			updated.Email, updated.EmailNormalized = display, normalized
			changed = append(changed, "email")
		}
	}
	if updated.UsernameNormalized == updated.EmailNormalized {
		return User{}, nil, &ValidationError{Field: "username", Code: "ambiguous_identifier"}
	}
	if input.DisplayName != nil {
		value, err := normalizeDisplayName(*input.DisplayName, updated.Username)
		if err != nil {
			return User{}, nil, err
		}
		if value != existing.DisplayName {
			updated.DisplayName = value
			changed = append(changed, "display_name")
		}
	}
	if input.Status != nil {
		if *input.Status != StatusActive && *input.Status != StatusDisabled {
			return User{}, nil, &ValidationError{Field: "status", Code: "invalid_value"}
		}
		if *input.Status != existing.Status {
			updated.Status = *input.Status
			changed = append(changed, "status")
		}
	}
	if input.Role != nil {
		if *input.Role != RoleUser && *input.Role != RoleAdmin {
			return User{}, nil, &ValidationError{Field: "role", Code: "invalid_value"}
		}
		if *input.Role != existing.Role {
			updated.Role = *input.Role
			changed = append(changed, "role")
		}
	}
	if len(changed) == 0 {
		return User{}, nil, &ValidationError{Field: "body", Code: "no_changes"}
	}
	updated.UpdatedAt = now.UTC()
	return updated, changed, nil
}

// NormalizeSearchPrefix applies the same trim/NFC/case-fold policy without
// pretending a partial admin search value is a complete username or email.
func NormalizeSearchPrefix(raw string) string {
	return fold.String(norm.NFC.String(strings.TrimSpace(raw)))
}

// VerifyLogin always runs Argon2id. A nil record uses the precomputed dummy
// digest so account existence is not exposed through an obvious fast path.
func (s *Service) VerifyLogin(ctx context.Context, password string, record *LoginRecord) (needsRehash bool, replacementHash string, err error) {
	hash := s.dummyHash
	if record != nil {
		hash = record.PasswordHash
	}
	matches, needsRehash, verifyErr := s.hasher.Verify(ctx, password, hash)
	if verifyErr != nil {
		return false, "", verifyErr
	}
	if record == nil || !matches {
		return false, "", ErrInvalidCredentials
	}
	if record.User.Status != StatusActive {
		return false, "", ErrDisabled
	}
	if needsRehash {
		replacementHash, err = s.hasher.Hash(ctx, password)
		if err != nil {
			return false, "", err
		}
	}
	return needsRehash, replacementHash, nil
}

func randomString(source io.Reader, prefix string, bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := io.ReadFull(source, buffer); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}
