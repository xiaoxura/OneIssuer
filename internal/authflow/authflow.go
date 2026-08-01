// Package authflow stores short-lived, server-issued registration/authorization
// context. It does not parse OIDC requests or issue codes/tokens.
package authflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
)

// Kind distinguishes local browser flows from verified authorization context.
type Kind string

// Supported phase-two authorization transaction kinds.
const (
	KindLocal         Kind = "local"
	KindAuthorization Kind = "authorization"
)

var (
	// ErrInvalid identifies invalid transaction input.
	ErrInvalid = errors.New("authorization transaction is invalid")
	// ErrNotFound hides invalid and unknown clear transaction tokens.
	ErrNotFound = errors.New("authorization transaction not found")
	// ErrExpired indicates that the transaction lifetime elapsed.
	ErrExpired = errors.New("authorization transaction expired")
	// ErrConsumed indicates that the transaction has already been used.
	ErrConsumed = errors.New("authorization transaction already consumed")
)

// Transaction contains already-validated context only. Sensitive protocol
// values have no JSON tags and must never be logged or audited.
type Transaction struct {
	ID            uuid.UUID
	TokenHash     []byte
	Kind          Kind
	ClientID      *uuid.UUID
	RedirectURI   string
	Scopes        []string
	PKCEChallenge string
	PKCEMethod    string
	State         string
	Nonce         string
	PromptCreate  bool
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	FailureReason string
}

// VerifiedInput is reserved for the phase-three protocol adapter, which must
// validate Client/URI/scope before calling this boundary.
type VerifiedInput struct {
	ClientID      uuid.UUID
	RedirectURI   string
	Scopes        []string
	PKCEChallenge string
	State         string
	Nonce         string
	PromptCreate  bool
}

// Repository is the persistence boundary for short-lived transactions.
type Repository interface {
	CreateAuthTransaction(context.Context, Transaction, audit.Event) error
	FindAuthTransaction(context.Context, []byte) (Transaction, error)
	ConsumeAuthTransaction(context.Context, uuid.UUID, time.Time, audit.Event) (Transaction, error)
	ExpireAuthTransactions(context.Context, time.Time) (int64, error)
	CleanupAuthTransactions(context.Context, time.Time) (int64, error)
}

// Metrics records low-cardinality transaction outcomes.
type Metrics interface {
	AuthTransaction(operation, result string)
}

// Service creates, resolves, consumes, and cleans up opaque transactions.
type Service struct {
	repository Repository
	random     io.Reader
	ttl        time.Duration
	metrics    Metrics
}

// NewService creates a transaction service with a bounded lifetime.
func NewService(repository Repository, randomSource io.Reader, ttl time.Duration, metrics Metrics) (*Service, error) {
	if randomSource == nil {
		randomSource = rand.Reader
	}
	if repository == nil || ttl <= 0 || ttl > time.Hour {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, random: randomSource, ttl: ttl, metrics: metrics}, nil
}

// CreateLocal starts a server-local browser authentication transaction.
func (s *Service) CreateLocal(ctx context.Context, requestID string, now time.Time) (string, Transaction, error) {
	return s.create(ctx, KindLocal, VerifiedInput{}, requestID, now)
}

// CreateVerified persists context already validated by a protocol adapter.
func (s *Service) CreateVerified(ctx context.Context, input VerifiedInput, requestID string, now time.Time) (string, Transaction, error) {
	if input.ClientID == uuid.Nil || !validAbsoluteURI(input.RedirectURI) || len(input.Scopes) == 0 || len(input.Scopes) > 32 {
		return "", Transaction{}, ErrInvalid
	}
	if input.PKCEChallenge != "" && (len(input.PKCEChallenge) < 43 || len(input.PKCEChallenge) > 128) {
		return "", Transaction{}, ErrInvalid
	}
	if len(input.State) > 1024 || len(input.Nonce) > 1024 {
		return "", Transaction{}, ErrInvalid
	}
	input.Scopes = canonicalStrings(input.Scopes)
	return s.create(ctx, KindAuthorization, input, requestID, now)
}

func (s *Service) create(ctx context.Context, kind Kind, input VerifiedInput, requestID string, now time.Time) (string, Transaction, error) {
	token, err := newToken(s.random)
	if err != nil {
		s.observe("create", "failure")
		return "", Transaction{}, err
	}
	id, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		s.observe("create", "failure")
		return "", Transaction{}, errors.New("transaction identifier generation failed")
	}
	now = now.UTC()
	transaction := Transaction{
		ID: id, TokenHash: HashToken(token), Kind: kind, RedirectURI: input.RedirectURI,
		Scopes: append([]string{}, input.Scopes...), PKCEChallenge: input.PKCEChallenge, State: input.State,
		Nonce: input.Nonce, PromptCreate: input.PromptCreate, CreatedAt: now, ExpiresAt: now.Add(s.ttl),
	}
	if kind == KindAuthorization {
		clientID := input.ClientID
		transaction.ClientID = &clientID
		if input.PKCEChallenge != "" {
			transaction.PKCEMethod = "S256"
		}
	}
	event, err := audit.New(audit.AuthorizationTransactionCreated, audit.ResultSuccess, nil, audit.TargetAuthTransaction, &id, requestID, []string{"created"}, now)
	if err != nil {
		return "", Transaction{}, err
	}
	if err := s.repository.CreateAuthTransaction(ctx, transaction, event); err != nil {
		s.observe("create", "failure")
		return "", Transaction{}, err
	}
	s.observe("create", "success")
	return token, transaction, nil
}

// Resolve validates an opaque token and returns an unexpired, unconsumed transaction.
func (s *Service) Resolve(ctx context.Context, token string, now time.Time) (Transaction, error) {
	if !validToken(token) {
		s.observe("resolve", "rejected")
		return Transaction{}, ErrNotFound
	}
	transaction, err := s.repository.FindAuthTransaction(ctx, HashToken(token))
	if err != nil {
		s.observe("resolve", "rejected")
		return Transaction{}, err
	}
	if transaction.ConsumedAt != nil {
		s.observe("resolve", "rejected")
		return Transaction{}, ErrConsumed
	}
	if !now.UTC().Before(transaction.ExpiresAt) {
		s.observe("resolve", "rejected")
		return Transaction{}, ErrExpired
	}
	s.observe("resolve", "success")
	return transaction, nil
}

// Consume marks a transaction used exactly once and records an audit event.
func (s *Service) Consume(ctx context.Context, transaction Transaction, actor *uuid.UUID, requestID string, now time.Time) (Transaction, error) {
	event, err := audit.New(audit.AuthorizationTransactionConsumed, audit.ResultSuccess, actor, audit.TargetAuthTransaction, &transaction.ID, requestID, nil, now)
	if err != nil {
		return Transaction{}, err
	}
	result, err := s.repository.ConsumeAuthTransaction(ctx, transaction.ID, now.UTC(), event)
	if err != nil {
		s.observe("consume", "rejected")
		return Transaction{}, err
	}
	s.observe("consume", "success")
	return result, nil
}

// Cleanup expires live stale transactions and deletes old terminal records.
func (s *Service) Cleanup(ctx context.Context, now time.Time) (int64, error) {
	expired, err := s.repository.ExpireAuthTransactions(ctx, now.UTC())
	if err != nil {
		return 0, err
	}
	deleted, err := s.repository.CleanupAuthTransactions(ctx, now.UTC().Add(-24*time.Hour))
	if err != nil {
		return expired, err
	}
	return expired + deleted, nil
}

func (s *Service) observe(operation, result string) {
	if s.metrics != nil {
		s.metrics.AuthTransaction(operation, result)
	}
}

func newToken(source io.Reader) (string, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(source, buffer); err != nil {
		return "", errors.New("secure transaction token generation failed")
	}
	return "t1_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func validToken(token string) bool {
	if !strings.HasPrefix(token, "t1_") {
		return false
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, "t1_"))
	return err == nil && len(value) == 32
}

// HashToken returns the domain-separated lookup digest stored in PostgreSQL.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte("oneissuer:auth-transaction:v1:" + token))
	return sum[:]
}

func validAbsoluteURI(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.Fragment == "" && parsed.User == nil
}

func canonicalStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	output := result[:0]
	for _, value := range result {
		if value == "" || (len(output) > 0 && output[len(output)-1] == value) {
			continue
		}
		output = append(output, value)
	}
	return output
}
