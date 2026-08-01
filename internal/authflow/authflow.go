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
	ResponseType  string
	ResponseMode  string
	Prompts       []string
	MaxAgeSeconds *uint32
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
	ResponseType  string
	ResponseMode  string
	Prompts       []string
	MaxAgeSeconds *uint32
}

// Repository is the persistence boundary for short-lived transactions.
type Repository interface {
	CreateAuthTransaction(context.Context, Transaction, audit.Event) error
	FindAuthTransaction(context.Context, []byte) (Transaction, error)
	ConsumeAuthTransaction(context.Context, uuid.UUID, time.Time, audit.Event) (Transaction, error)
	RejectAuthTransaction(context.Context, uuid.UUID, string, time.Time, audit.Event) (Transaction, error)
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
	input.Scopes = canonicalStrings(input.Scopes)
	if input.ClientID == uuid.Nil || !validAbsoluteURI(input.RedirectURI) || input.ResponseType != "code" || input.ResponseMode != "query" ||
		len(input.Scopes) == 0 || len(input.Scopes) > 3 || !validOIDCScopes(input.Scopes) {
		return "", Transaction{}, ErrInvalid
	}
	if !validS256Challenge(input.PKCEChallenge) {
		return "", Transaction{}, ErrInvalid
	}
	if len(input.State) > 1024 || len(input.Nonce) > 1024 {
		return "", Transaction{}, ErrInvalid
	}
	if input.PromptCreate && len(input.Prompts) == 0 {
		input.Prompts = []string{"create"}
	}
	if !validPrompts(input.Prompts) || input.PromptCreate != contains(input.Prompts, "create") {
		return "", Transaction{}, ErrInvalid
	}
	if input.MaxAgeSeconds != nil && *input.MaxAgeSeconds > 30*24*60*60 {
		return "", Transaction{}, ErrInvalid
	}
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
		Nonce: input.Nonce, PromptCreate: input.PromptCreate, ResponseType: input.ResponseType, ResponseMode: input.ResponseMode,
		Prompts: append([]string{}, input.Prompts...), MaxAgeSeconds: cloneUint32(input.MaxAgeSeconds),
		CreatedAt: now, ExpiresAt: now.Add(s.ttl),
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

// Reject terminally consumes a live transaction with one fixed reason and a
// value-free audit event. Retrying the browser transaction can never mint
// authority after this transition.
func (s *Service) Reject(ctx context.Context, transaction Transaction, reason string, actor *uuid.UUID, requestID string, now time.Time) (Transaction, error) {
	if !validFailureReason(reason) {
		return Transaction{}, ErrInvalid
	}
	event, err := audit.New(audit.AuthorizationTransactionRejected, audit.ResultRejected, actor, audit.TargetAuthTransaction, &transaction.ID, requestID, nil, now)
	if err != nil {
		return Transaction{}, err
	}
	result, err := s.repository.RejectAuthTransaction(ctx, transaction.ID, reason, now.UTC(), event)
	if err != nil {
		s.observe("reject", "failure")
		return Transaction{}, err
	}
	s.observe("reject", "success")
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

func validS256Challenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validOIDCScopes(values []string) bool {
	if !contains(values, "openid") {
		return false
	}
	for _, value := range values {
		if value != "openid" && value != "profile" && value != "email" {
			return false
		}
	}
	return true
}

func validPrompts(values []string) bool {
	canonical := canonicalStrings(values)
	if len(canonical) != len(values) {
		return false
	}
	for index := range canonical {
		if canonical[index] != values[index] ||
			(canonical[index] != "consent" && canonical[index] != "create" && canonical[index] != "login" && canonical[index] != "none") {
			return false
		}
	}
	return (!contains(values, "none") || len(values) == 1) && (!contains(values, "create") || !contains(values, "login"))
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func validFailureReason(reason string) bool {
	switch reason {
	case "invalid", "client_disabled", "registration_disabled", "canceled", "login_required", "consent_required", "interaction_required", "access_denied", "server_error":
		return true
	default:
		return false
	}
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
