// Package authn orchestrates the browser registration/login transaction across
// identity, pre-auth CSRF, login sessions, authorization context, and audit.
// HTTP handlers depend on this use-case boundary rather than persistence.
package authn

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/session"
)

var (
	// ErrInvalidFlow identifies an invalid, expired, or mismatched browser flow.
	ErrInvalidFlow = errors.New("authentication flow is invalid")
	// ErrRegistrationDisabled indicates that self-service registration is unavailable.
	ErrRegistrationDisabled = errors.New("self-service registration is disabled")
)

const maxAuthenticationAttempts int16 = 5

// BeginMode selects login or registration form preparation.
type BeginMode string

// Supported browser form modes.
const (
	BeginLogin    BeginMode = "login"
	BeginRegister BeginMode = "register"
)

// BeginResult must not be logged; it carries clear one-time browser values.
type BeginResult struct {
	TransactionToken string
	Transaction      authflow.Transaction
	PreAuth          session.IssuedPreAuth
}

// RegisterInput carries clear browser values and must never be logged.
type RegisterInput struct {
	PreAuthToken         string
	CSRFToken            string
	TransactionToken     string
	Account              identity.CreateInput
	ExistingSessionToken string
	UserAgent            string
	ClientIP             netip.Addr
	RequestID            string
}

// LoginInput carries clear credentials and must never be logged.
type LoginInput struct {
	PreAuthToken         string
	CSRFToken            string
	TransactionToken     string
	Identifier           string
	Password             string
	ExistingSessionToken string
	UserAgent            string
	ClientIP             netip.Addr
	RequestID            string
}

// RegisterCommit contains the records written atomically for registration.
type RegisterCommit struct {
	User                identity.PreparedUser
	Session             session.Record
	PreAuthID           uuid.UUID
	TransactionID       uuid.UUID
	ConsumeTransaction  bool
	ExistingSessionHash []byte
	RequestID           string
	Events              []audit.Event
}

// LoginCommit contains the records mutated atomically for successful login.
type LoginCommit struct {
	UserID              uuid.UUID
	Session             session.Record
	PreAuthID           uuid.UUID
	TransactionID       uuid.UUID
	ConsumeTransaction  bool
	ExistingSessionHash []byte
	ReplacementHash     string
	Now                 time.Time
	RequestID           string
	Events              []audit.Event
}

// Repository is the atomic persistence boundary for browser authentication.
type Repository interface {
	CreatePreAuth(context.Context, session.PreAuthRecord) error
	FindPreAuth(context.Context, []byte) (session.PreAuthRecord, error)
	ReservePreAuthAttempt(context.Context, uuid.UUID, time.Time, int16) error
	FindLoginRecord(context.Context, string) (identity.LoginRecord, error)
	CommitRegistration(context.Context, RegisterCommit) error
	CommitLogin(context.Context, LoginCommit) (uuid.UUID, error)
	AppendAudit(context.Context, audit.Event) error
}

// ClientLookup resolves registration policy for a verified client context.
type ClientLookup interface {
	Get(context.Context, uuid.UUID) (clientdomain.Client, error)
}

// Metrics records low-cardinality authentication outcomes.
type Metrics interface {
	IdentityRegistration(result string)
	IdentityLogin(result string)
	PasswordRehash(result string)
	SessionCreated(result string)
}

// Service orchestrates identity verification, sessions, transactions, and audit.
type Service struct {
	repository          Repository
	identity            *identity.Service
	sessions            *session.TokenManager
	transactions        *authflow.Service
	clients             ClientLookup
	registrationEnabled bool
	metrics             Metrics
}

// NewService creates the browser authentication use-case service.
func NewService(repository Repository, identities *identity.Service, sessions *session.TokenManager, transactions *authflow.Service, clients ClientLookup, registrationEnabled bool, metrics Metrics) *Service {
	return &Service{
		repository: repository, identity: identities, sessions: sessions,
		transactions: transactions, clients: clients, registrationEnabled: registrationEnabled, metrics: metrics,
	}
}

// Begin creates a pre-auth session bound to a server-issued transaction.
func (s *Service) Begin(ctx context.Context, mode BeginMode, transactionToken, requestID string, now time.Time) (BeginResult, error) {
	if mode == BeginRegister && transactionToken == "" && !s.registrationEnabled {
		return BeginResult{}, ErrRegistrationDisabled
	}
	var transaction authflow.Transaction
	var err error
	if transactionToken == "" {
		transactionToken, transaction, err = s.transactions.CreateLocal(ctx, requestID, now)
	} else {
		transaction, err = s.transactions.Resolve(ctx, transactionToken, now)
	}
	if err != nil {
		return BeginResult{}, ErrInvalidFlow
	}
	if mode == BeginLogin && transaction.Kind == authflow.KindAuthorization && transaction.PromptCreate {
		return BeginResult{}, ErrInvalidFlow
	}
	if mode == BeginRegister {
		if err := s.checkRegistration(ctx, transaction); err != nil {
			return BeginResult{}, err
		}
		if transaction.Kind == authflow.KindAuthorization && !transaction.PromptCreate {
			return BeginResult{}, ErrInvalidFlow
		}
	}
	preauth, err := s.sessions.NewPreAuth(transaction.ID, now)
	if err != nil {
		return BeginResult{}, err
	}
	if err := s.repository.CreatePreAuth(ctx, preauth.Record); err != nil {
		return BeginResult{}, err
	}
	return BeginResult{TransactionToken: transactionToken, Transaction: transaction, PreAuth: preauth}, nil
}

// Register atomically creates a user and authenticated session after CSRF validation.
func (s *Service) Register(ctx context.Context, input RegisterInput, now time.Time) (session.Issued, error) {
	preauth, transaction, err := s.validateFlow(ctx, input.PreAuthToken, input.CSRFToken, input.TransactionToken, now)
	if err != nil {
		s.observeRegistration("rejected")
		return session.Issued{}, err
	}
	if err := s.repository.ReservePreAuthAttempt(ctx, preauth.ID, now.UTC(), maxAuthenticationAttempts); err != nil {
		s.observeRegistration("rejected")
		return session.Issued{}, ErrInvalidFlow
	}
	if err := s.checkRegistration(ctx, transaction); err != nil {
		s.observeRegistration("rejected")
		s.recordRejected(ctx, audit.UserRegistrationRejected, input.RequestID, now)
		return session.Issued{}, err
	}
	prepared, err := s.identity.PrepareUser(ctx, input.Account, identity.RoleUser, now)
	if err != nil {
		s.observeRegistration("rejected")
		s.recordRejected(ctx, audit.UserRegistrationRejected, input.RequestID, now)
		return session.Issued{}, err
	}
	issued, err := s.sessions.NewAuthenticated(prepared.User.ID, now, input.UserAgent, input.ClientIP)
	if err != nil {
		return session.Issued{}, err
	}
	consumeTransaction := transaction.Kind == authflow.KindLocal
	events, err := successEvents(prepared.User.ID, issued.Record.ID, transaction.ID, input.RequestID, now, true, consumeTransaction)
	if err != nil {
		return session.Issued{}, err
	}
	commit := RegisterCommit{
		User: prepared, Session: issued.Record, PreAuthID: preauth.ID, TransactionID: transaction.ID,
		ConsumeTransaction: consumeTransaction, RequestID: input.RequestID, Events: events,
	}
	if input.ExistingSessionToken != "" {
		commit.ExistingSessionHash = session.HashToken(input.ExistingSessionToken)
	}
	if err := s.repository.CommitRegistration(ctx, commit); err != nil {
		s.observeRegistration("failure")
		if errors.Is(err, identity.ErrDuplicate) {
			s.recordRejected(ctx, audit.UserRegistrationRejected, input.RequestID, now)
		}
		return session.Issued{}, err
	}
	s.observeRegistration("success")
	if s.metrics != nil {
		s.metrics.SessionCreated("success")
	}
	return issued, nil
}

// Login verifies credentials with enumeration-safe semantics and rotates the session.
func (s *Service) Login(ctx context.Context, input LoginInput, now time.Time) (session.Issued, identity.User, error) {
	preauth, transaction, err := s.validateFlow(ctx, input.PreAuthToken, input.CSRFToken, input.TransactionToken, now)
	if err != nil {
		s.observeLogin("rejected")
		return session.Issued{}, identity.User{}, err
	}
	if err := s.repository.ReservePreAuthAttempt(ctx, preauth.ID, now.UTC(), maxAuthenticationAttempts); err != nil {
		s.observeLogin("rejected")
		return session.Issued{}, identity.User{}, ErrInvalidFlow
	}
	normalized, normalizeErr := identity.NormalizeLoginIdentifier(input.Identifier)
	var record *identity.LoginRecord
	if normalizeErr == nil {
		found, findErr := s.repository.FindLoginRecord(ctx, normalized)
		if findErr == nil {
			record = &found
		} else if !errors.Is(findErr, identity.ErrNotFound) {
			return session.Issued{}, identity.User{}, findErr
		}
	}
	needsRehash, replacement, verifyErr := s.identity.VerifyLogin(ctx, input.Password, record)
	if verifyErr != nil {
		eventType := audit.LoginFailed
		var target *uuid.UUID
		if record != nil {
			target = &record.User.ID
			if errors.Is(verifyErr, identity.ErrDisabled) {
				eventType = audit.LoginDisabledUser
			}
		}
		s.recordLoginFailure(ctx, eventType, target, input.RequestID, now)
		s.observeLogin("rejected")
		if errors.Is(verifyErr, identity.ErrDisabled) || errors.Is(verifyErr, identity.ErrInvalidCredentials) || normalizeErr != nil {
			return session.Issued{}, identity.User{}, identity.ErrInvalidCredentials
		}
		return session.Issued{}, identity.User{}, verifyErr
	}
	if record == nil { // defensive; VerifyLogin only succeeds with a record.
		return session.Issued{}, identity.User{}, identity.ErrInvalidCredentials
	}
	issued, err := s.sessions.NewAuthenticated(record.User.ID, now, input.UserAgent, input.ClientIP)
	if err != nil {
		return session.Issued{}, identity.User{}, err
	}
	consumeTransaction := transaction.Kind == authflow.KindLocal
	events, err := successEvents(record.User.ID, issued.Record.ID, transaction.ID, input.RequestID, now, false, consumeTransaction)
	if err != nil {
		return session.Issued{}, identity.User{}, err
	}
	commit := LoginCommit{
		UserID: record.User.ID, Session: issued.Record, PreAuthID: preauth.ID, TransactionID: transaction.ID,
		ConsumeTransaction: consumeTransaction,
		ReplacementHash:    replacement, Now: now.UTC(), RequestID: input.RequestID, Events: events,
	}
	if input.ExistingSessionToken != "" {
		commit.ExistingSessionHash = session.HashToken(input.ExistingSessionToken)
	}
	bindingID, err := s.repository.CommitLogin(ctx, commit)
	if err != nil {
		s.observeLogin("failure")
		return session.Issued{}, identity.User{}, err
	}
	if bindingID == uuid.Nil {
		s.observeLogin("failure")
		return session.Issued{}, identity.User{}, ErrInvalidFlow
	}
	issued.Record.SessionBindingID = bindingID
	s.observeLogin("success")
	if s.metrics != nil {
		s.metrics.SessionCreated("success")
		if needsRehash {
			s.metrics.PasswordRehash("success")
		}
	}
	record.User.LastLoginAt = pointerTime(now.UTC())
	return issued, record.User, nil
}

func (s *Service) validateFlow(ctx context.Context, preauthToken, csrfToken, transactionToken string, now time.Time) (session.PreAuthRecord, authflow.Transaction, error) {
	if preauthToken == "" || transactionToken == "" {
		return session.PreAuthRecord{}, authflow.Transaction{}, ErrInvalidFlow
	}
	preauth, err := s.repository.FindPreAuth(ctx, session.HashToken(preauthToken))
	if err != nil {
		return session.PreAuthRecord{}, authflow.Transaction{}, ErrInvalidFlow
	}
	if err := s.sessions.ValidatePreAuth(preauth, preauthToken, csrfToken, now); err != nil {
		if errors.Is(err, session.ErrInvalidCSRF) {
			return session.PreAuthRecord{}, authflow.Transaction{}, session.ErrInvalidCSRF
		}
		return session.PreAuthRecord{}, authflow.Transaction{}, ErrInvalidFlow
	}
	transaction, err := s.transactions.Resolve(ctx, transactionToken, now)
	if err != nil || transaction.ID != preauth.AuthTransactionID {
		return session.PreAuthRecord{}, authflow.Transaction{}, ErrInvalidFlow
	}
	return preauth, transaction, nil
}

func (s *Service) checkRegistration(ctx context.Context, transaction authflow.Transaction) error {
	if !s.registrationEnabled {
		return ErrRegistrationDisabled
	}
	if transaction.Kind == authflow.KindLocal {
		return nil
	}
	if transaction.ClientID == nil || s.clients == nil {
		return ErrRegistrationDisabled
	}
	clientValue, err := s.clients.Get(ctx, *transaction.ClientID)
	if err != nil || clientValue.Status != clientdomain.StatusActive || !clientValue.RegistrationEnabled {
		return ErrRegistrationDisabled
	}
	return nil
}

// CanRegister reports whether a verified server transaction may enter the
// hosted registration flow. It accepts no browser-supplied Client policy.
func (s *Service) CanRegister(ctx context.Context, transaction authflow.Transaction) bool {
	return s.checkRegistration(ctx, transaction) == nil &&
		(transaction.Kind == authflow.KindLocal || transaction.PromptCreate)
}

func successEvents(userID, sessionID, transactionID uuid.UUID, requestID string, now time.Time, registration, consumeTransaction bool) ([]audit.Event, error) {
	typeValue := audit.LoginSucceeded
	var changed []string
	if registration {
		typeValue = audit.UserRegistered
		changed = []string{"created"}
	}
	first, err := audit.New(typeValue, audit.ResultSuccess, &userID, audit.TargetUser, &userID, requestID, changed, now)
	if err != nil {
		return nil, err
	}
	created, err := audit.New(audit.SessionCreated, audit.ResultSuccess, &userID, audit.TargetSession, &sessionID, requestID, []string{"created"}, now)
	if err != nil {
		return nil, err
	}
	events := []audit.Event{first, created}
	if consumeTransaction {
		consumed, err := audit.New(audit.AuthorizationTransactionConsumed, audit.ResultSuccess, &userID, audit.TargetAuthTransaction, &transactionID, requestID, nil, now)
		if err != nil {
			return nil, err
		}
		events = append(events, consumed)
	}
	return events, nil
}

func (s *Service) recordRejected(ctx context.Context, eventType audit.EventType, requestID string, now time.Time) {
	event, err := audit.New(eventType, audit.ResultRejected, nil, "", nil, requestID, nil, now)
	if err == nil {
		_ = s.repository.AppendAudit(ctx, event)
	}
}

func (s *Service) recordLoginFailure(ctx context.Context, eventType audit.EventType, target *uuid.UUID, requestID string, now time.Time) {
	targetType := audit.TargetType("")
	if target != nil {
		targetType = audit.TargetUser
	}
	event, err := audit.New(eventType, audit.ResultRejected, nil, targetType, target, requestID, nil, now)
	if err == nil {
		_ = s.repository.AppendAudit(ctx, event)
	}
}

func (s *Service) observeRegistration(result string) {
	if s.metrics != nil {
		s.metrics.IdentityRegistration(result)
	}
}

func (s *Service) observeLogin(result string) {
	if s.metrics != nil {
		s.metrics.IdentityLogin(result)
	}
}

func pointerTime(value time.Time) *time.Time { return &value }
