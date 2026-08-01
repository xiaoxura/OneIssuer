// Package authorization owns phase-three consent decisions, opaque
// Authorization Code generation, strict S256 verification, and the explicit
// atomic repository boundary for grant/code/transaction state.
package authorization

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/consent"
)

const codePrefix = "c1_"

var (
	// ErrInvalid identifies malformed use-case input without echoing it.
	ErrInvalid = errors.New("authorization operation is invalid")
	// ErrNotFound hides unknown clear codes and missing protocol state.
	ErrNotFound = errors.New("authorization state not found")
	// ErrExpired indicates elapsed single-use authority.
	ErrExpired = errors.New("authorization state expired")
	// ErrConsumed indicates an already-terminal transaction or code.
	ErrConsumed = errors.New("authorization state already consumed")
	// ErrConsentRequired indicates that silent issuance has no covering grant.
	ErrConsentRequired = errors.New("consent is required")
	// ErrInactive indicates that the bound User or Client is no longer active.
	ErrInactive = errors.New("authorization principal is inactive")
)

// IssueCommit contains only digest/binding material for the atomic persistence
// boundary. The clear Code is intentionally absent and cannot be logged by an
// adapter.
type IssueCommit struct {
	Transaction        authflow.Transaction
	UserID             uuid.UUID
	AuthenticatedAt    time.Time
	InteractiveConsent bool
	CodeID             uuid.UUID
	CodeHash           []byte
	ProposedGrantID    uuid.UUID
	CreatedAt          time.Time
	ExpiresAt          time.Time
	RequestID          string
}

// DenyCommit atomically terminates one live authorization transaction.
type DenyCommit struct {
	Transaction authflow.Transaction
	UserID      uuid.UUID
	DeniedAt    time.Time
	RequestID   string
}

// Issued is sensitive transient output. Code must only be placed in a verified
// redirect response and never persisted, logged, audited, or metered.
type Issued struct {
	Code      string
	CodeID    uuid.UUID
	Grant     consent.Grant
	ExpiresAt time.Time
}

// Repository implements the cross-table atomicity contract. Implementations
// must re-lock and revalidate transaction, User, Client, URI, Scope, and Grant.
type Repository interface {
	IssueAuthorizationCode(context.Context, IssueCommit) (consent.Grant, error)
	DenyAuthorization(context.Context, DenyCommit) error
}

// Metrics records only bounded operation/result labels.
type Metrics interface {
	Authorization(operation, result string)
}

// Service generates clear values and delegates all authority transitions to a
// repository transaction.
type Service struct {
	repository Repository
	random     io.Reader
	codeTTL    time.Duration
	metrics    Metrics
}

// NewService creates a Code/consent authorization service.
func NewService(repository Repository, randomSource io.Reader, codeTTL time.Duration, metrics Metrics) (*Service, error) {
	if repository == nil || codeTTL < 30*time.Second || codeTTL > 5*time.Minute {
		return nil, ErrInvalid
	}
	if randomSource == nil {
		randomSource = rand.Reader
	}
	return &Service{repository: repository, random: randomSource, codeTTL: codeTTL, metrics: metrics}, nil
}

// Issue creates one opaque Code and commits it with the transaction/Grant state.
// A clear Code is returned only after the repository commit succeeds.
func (s *Service) Issue(ctx context.Context, transaction authflow.Transaction, userID uuid.UUID, authenticatedAt time.Time, interactiveConsent bool, requestID string, now time.Time) (Issued, error) {
	now = now.UTC()
	authenticatedAt = authenticatedAt.UTC()
	if !validAuthorizationTransaction(transaction) || userID == uuid.Nil || authenticatedAt.IsZero() || authenticatedAt.After(now) ||
		!now.Before(transaction.ExpiresAt.UTC()) || transaction.ConsumedAt != nil {
		s.observe("issue", "rejected")
		return Issued{}, ErrInvalid
	}

	clearCode, err := newCode(s.random)
	if err != nil {
		s.observe("issue", "failure")
		return Issued{}, err
	}
	codeID, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		s.observe("issue", "failure")
		return Issued{}, errors.New("authorization code identifier generation failed")
	}
	grantID, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		s.observe("issue", "failure")
		return Issued{}, errors.New("consent grant identifier generation failed")
	}
	expiresAt := now.Add(s.codeTTL)
	grant, err := s.repository.IssueAuthorizationCode(ctx, IssueCommit{
		Transaction: transaction, UserID: userID, AuthenticatedAt: authenticatedAt,
		InteractiveConsent: interactiveConsent, CodeID: codeID, CodeHash: HashCode(clearCode),
		ProposedGrantID: grantID, CreatedAt: now, ExpiresAt: expiresAt, RequestID: requestID,
	})
	if err != nil {
		result := "failure"
		if errors.Is(err, ErrConsumed) || errors.Is(err, ErrExpired) || errors.Is(err, ErrConsentRequired) || errors.Is(err, ErrInactive) {
			result = "rejected"
		}
		s.observe("issue", result)
		return Issued{}, err
	}
	s.observe("issue", "success")
	return Issued{Code: clearCode, CodeID: codeID, Grant: grant, ExpiresAt: expiresAt}, nil
}

// Deny atomically consumes a live transaction without changing an existing
// Grant and records the fixed authorization-denied audit transition.
func (s *Service) Deny(ctx context.Context, transaction authflow.Transaction, userID uuid.UUID, requestID string, now time.Time) error {
	now = now.UTC()
	if !validAuthorizationTransaction(transaction) || userID == uuid.Nil || !now.Before(transaction.ExpiresAt.UTC()) || transaction.ConsumedAt != nil {
		s.observe("deny", "rejected")
		return ErrInvalid
	}
	err := s.repository.DenyAuthorization(ctx, DenyCommit{
		Transaction: transaction, UserID: userID, DeniedAt: now, RequestID: requestID,
	})
	if err != nil {
		result := "failure"
		if errors.Is(err, ErrConsumed) || errors.Is(err, ErrExpired) || errors.Is(err, ErrInactive) {
			result = "rejected"
		}
		s.observe("deny", result)
		return err
	}
	s.observe("deny", "success")
	return nil
}

// HashCode returns the domain-separated digest persisted in PostgreSQL.
func HashCode(clearCode string) []byte {
	digest := sha256.Sum256([]byte("oneissuer:authorization-code:v1:" + clearCode))
	return digest[:]
}

// DigestPresentedCode validates a versioned 256-bit Code before hashing it.
func DigestPresentedCode(clearCode string) ([]byte, error) {
	if len(clearCode) != len(codePrefix)+43 || len(clearCode) < len(codePrefix) || clearCode[:len(codePrefix)] != codePrefix {
		return nil, ErrNotFound
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(clearCode[len(codePrefix):])
	if err != nil || len(raw) != 32 {
		return nil, ErrNotFound
	}
	return HashCode(clearCode), nil
}

// VerifyS256 enforces the exact RFC 7636 verifier grammar and compares the
// derived challenge in constant time.
func VerifyS256(verifier, expectedChallenge string) error {
	if ValidateVerifier(verifier) != nil || len(expectedChallenge) != 43 {
		return ErrInvalid
	}
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedChallenge)) != 1 {
		return ErrInvalid
	}
	return nil
}

// ValidateVerifier enforces the 43–128 byte RFC 7636 unreserved ASCII grammar
// without needing or exposing the stored challenge.
func ValidateVerifier(verifier string) error {
	if len(verifier) < 43 || len(verifier) > 128 {
		return ErrInvalid
	}
	for index := 0; index < len(verifier); index++ {
		if !isVerifierCharacter(verifier[index]) {
			return ErrInvalid
		}
	}
	return nil
}

func isVerifierCharacter(character byte) bool {
	return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9') || character == '-' || character == '.' || character == '_' || character == '~'
}

func newCode(source io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", errors.New("secure authorization code generation failed")
	}
	return codePrefix + base64.RawURLEncoding.EncodeToString(value), nil
}

func validAuthorizationTransaction(value authflow.Transaction) bool {
	return value.ID != uuid.Nil && value.Kind == authflow.KindAuthorization && value.ClientID != nil && *value.ClientID != uuid.Nil &&
		value.ResponseType == "code" && value.ResponseMode == "query" && value.RedirectURI != "" &&
		value.PKCEMethod == "S256" && len(value.PKCEChallenge) == 43 && len(value.Scopes) >= 1 && len(value.Scopes) <= 3
}

func (s *Service) observe(operation, result string) {
	if s.metrics != nil {
		s.metrics.Authorization(operation, result)
	}
}
