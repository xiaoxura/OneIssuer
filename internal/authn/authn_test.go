package authn

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/session"
)

type authnTestRepository struct {
	mu              sync.Mutex
	preauth         session.PreAuthRecord
	loginLookups    int
	auditAppends    int
	registrationErr error
}

func (r *authnTestRepository) CreatePreAuth(_ context.Context, record session.PreAuthRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preauth = record
	return nil
}

func (r *authnTestRepository) FindPreAuth(_ context.Context, hash []byte) (session.PreAuthRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !bytes.Equal(hash, r.preauth.TokenHash) {
		return session.PreAuthRecord{}, session.ErrNotFound
	}
	return r.preauth, nil
}

func (r *authnTestRepository) ReservePreAuthAttempt(_ context.Context, id uuid.UUID, now time.Time, maximum int16) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.preauth.ID != id || r.preauth.ConsumedAt != nil || !now.Before(r.preauth.ExpiresAt) || r.preauth.AttemptCount >= maximum {
		return session.ErrConsumed
	}
	r.preauth.AttemptCount++
	return nil
}

func (r *authnTestRepository) FindLoginRecord(context.Context, string) (identity.LoginRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loginLookups++
	return identity.LoginRecord{}, identity.ErrNotFound
}

func (r *authnTestRepository) CommitRegistration(context.Context, RegisterCommit) error {
	return r.registrationErr
}

func (r *authnTestRepository) CommitLogin(_ context.Context, commit LoginCommit) (uuid.UUID, error) {
	return commit.Session.SessionBindingID, nil
}

func (r *authnTestRepository) AppendAudit(context.Context, audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auditAppends++
	return nil
}

type authnTransactionRepository struct {
	mu      sync.Mutex
	created authflow.Transaction
	creates int
}

func (r *authnTransactionRepository) CreateAuthTransaction(_ context.Context, value authflow.Transaction, _ audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.created = value
	r.creates++
	return nil
}

func (r *authnTransactionRepository) FindAuthTransaction(_ context.Context, hash []byte) (authflow.Transaction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !bytes.Equal(hash, r.created.TokenHash) {
		return authflow.Transaction{}, authflow.ErrNotFound
	}
	return r.created, nil
}

func (*authnTransactionRepository) ConsumeAuthTransaction(context.Context, uuid.UUID, time.Time, audit.Event) (authflow.Transaction, error) {
	return authflow.Transaction{}, nil
}

func (*authnTransactionRepository) RejectAuthTransaction(context.Context, uuid.UUID, string, time.Time, audit.Event) (authflow.Transaction, error) {
	return authflow.Transaction{}, nil
}

func (*authnTransactionRepository) ExpireAuthTransactions(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (*authnTransactionRepository) CleanupAuthTransactions(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func TestLoginPreAuthAttemptBudgetStopsLookupAndArgonWork(t *testing.T) {
	now := time.Date(2026, time.August, 2, 11, 0, 0, 0, time.UTC)
	repository := &authnTestRepository{}
	transactions, err := authflow.NewService(&authnTransactionRepository{}, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := session.NewTokenManager(nil, time.Hour, time.Hour, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewService(context.Background(), config.PasswordConfig{
		MinLength: 15, MaxBytes: 1024, Argon2MemoryKiB: 19 * 1024,
		Argon2Time: 2, Argon2Threads: 1, MaxConcurrent: 1,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, identities, tokens, transactions, nil, false, nil)
	begin, err := service.Begin(context.Background(), BeginLogin, "", "request", now)
	if err != nil {
		t.Fatal(err)
	}
	input := LoginInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken, Identifier: "missing@example.test", Password: "incorrect password",
	}
	for attempt := int16(1); attempt <= maxAuthenticationAttempts; attempt++ {
		if _, _, err := service.Login(context.Background(), input, now.Add(time.Duration(attempt)*time.Second)); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("attempt %d error = %v, want invalid credentials", attempt, err)
		}
	}
	if _, _, err := service.Login(context.Background(), input, now.Add(time.Minute)); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("attempt beyond budget error = %v, want invalid flow", err)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.preauth.AttemptCount != maxAuthenticationAttempts {
		t.Fatalf("reserved attempts = %d, want %d", repository.preauth.AttemptCount, maxAuthenticationAttempts)
	}
	if repository.loginLookups != int(maxAuthenticationAttempts) {
		t.Fatalf("credential lookups = %d, want %d", repository.loginLookups, maxAuthenticationAttempts)
	}
	if repository.auditAppends != int(maxAuthenticationAttempts) {
		t.Fatalf("rejection audit appends = %d, want %d", repository.auditAppends, maxAuthenticationAttempts)
	}
}

func TestRejectedAttemptReservationPrecedesCredentialWork(t *testing.T) {
	now := time.Date(2026, time.August, 2, 11, 0, 0, 0, time.UTC)
	repository := &authnTestRepository{}
	transactions, err := authflow.NewService(&authnTransactionRepository{}, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := session.NewTokenManager(nil, time.Hour, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, nil, tokens, transactions, nil, false, nil)
	begin, err := service.Begin(context.Background(), BeginLogin, "", "request", now)
	if err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	repository.preauth.AttemptCount = maxAuthenticationAttempts
	repository.mu.Unlock()
	_, _, err = service.Login(context.Background(), LoginInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken, Identifier: "must-not-be-looked-up", Password: "must-not-be-hashed",
	}, now.Add(time.Second))
	if !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("Login() error = %v, want invalid flow", err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.loginLookups != 0 {
		t.Fatalf("credential lookup ran after reservation rejection: %d", repository.loginLookups)
	}
}

func TestRegistrationUsesTheSamePreAuthAttemptBudget(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 2, 11, 30, 0, 0, time.UTC)
	repository := &authnTestRepository{}
	transactions, err := authflow.NewService(&authnTransactionRepository{}, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := session.NewTokenManager(nil, time.Hour, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, nil, tokens, transactions, nil, true, nil)
	begin, err := service.Begin(context.Background(), BeginRegister, "", "request", now)
	if err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	repository.preauth.AttemptCount = maxAuthenticationAttempts
	repository.mu.Unlock()
	_, err = service.Register(context.Background(), RegisterInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken,
	}, now.Add(time.Second))
	if !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("Register() error = %v, want invalid flow", err)
	}
}

func TestDisabledLocalRegistrationDoesNotCreateTransaction(t *testing.T) {
	t.Parallel()

	transactionRepository := &authnTransactionRepository{}
	transactions, err := authflow.NewService(transactionRepository, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := session.NewTokenManager(nil, time.Hour, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(&authnTestRepository{}, nil, tokens, transactions, nil, false, nil)
	if _, err := service.Begin(context.Background(), BeginRegister, "", "request", time.Now()); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("Begin(register) error = %v", err)
	}
	transactionRepository.mu.Lock()
	defer transactionRepository.mu.Unlock()
	if transactionRepository.creates != 0 {
		t.Fatalf("disabled registration created %d local transactions", transactionRepository.creates)
	}
}
