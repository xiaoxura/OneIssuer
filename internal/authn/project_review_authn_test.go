package authn

import (
	"bytes"
	"context"
	"encoding/base64"
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

// projectReviewAuthnRepository captures the atomic commit input without ever
// accepting a clear session token. It is deliberately separate from the
// broader authn tests so this contract remains easy to audit.
type projectReviewAuthnRepository struct {
	mu           sync.Mutex
	preauth      session.PreAuthRecord
	loginRecord  identity.LoginRecord
	registration RegisterCommit
	login        LoginCommit
	loginBinding uuid.UUID
}

func (r *projectReviewAuthnRepository) CreatePreAuth(_ context.Context, value session.PreAuthRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preauth = value
	return nil
}

func (r *projectReviewAuthnRepository) FindPreAuth(_ context.Context, hash []byte) (session.PreAuthRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !bytes.Equal(hash, r.preauth.TokenHash) {
		return session.PreAuthRecord{}, session.ErrNotFound
	}
	return r.preauth, nil
}

func (r *projectReviewAuthnRepository) ReservePreAuthAttempt(_ context.Context, id uuid.UUID, now time.Time, maximum int16) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.preauth.ID != id || r.preauth.ConsumedAt != nil || !now.Before(r.preauth.ExpiresAt) || r.preauth.AttemptCount >= maximum {
		return session.ErrConsumed
	}
	r.preauth.AttemptCount++
	return nil
}

func (r *projectReviewAuthnRepository) FindLoginRecord(context.Context, string) (identity.LoginRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loginRecord.User.ID == uuid.Nil {
		return identity.LoginRecord{}, identity.ErrNotFound
	}
	return r.loginRecord, nil
}

func (r *projectReviewAuthnRepository) CommitRegistration(_ context.Context, commit RegisterCommit) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registration = commit
	return nil
}

func (r *projectReviewAuthnRepository) CommitLogin(_ context.Context, commit LoginCommit) (uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.login = commit
	if r.loginBinding == uuid.Nil {
		return commit.Session.SessionBindingID, nil
	}
	return r.loginBinding, nil
}

func (*projectReviewAuthnRepository) AppendAudit(context.Context, audit.Event) error { return nil }

type projectReviewAuthnTransactionRepository struct {
	mu    sync.Mutex
	value authflow.Transaction
}

var _ Repository = (*projectReviewAuthnRepository)(nil)
var _ authflow.Repository = (*projectReviewAuthnTransactionRepository)(nil)

func (r *projectReviewAuthnTransactionRepository) CreateAuthTransaction(_ context.Context, value authflow.Transaction, _ audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.value = value
	return nil
}

func (r *projectReviewAuthnTransactionRepository) FindAuthTransaction(_ context.Context, hash []byte) (authflow.Transaction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !bytes.Equal(hash, r.value.TokenHash) {
		return authflow.Transaction{}, authflow.ErrNotFound
	}
	return r.value, nil
}

func (*projectReviewAuthnTransactionRepository) ConsumeAuthTransaction(context.Context, uuid.UUID, time.Time, audit.Event) (authflow.Transaction, error) {
	return authflow.Transaction{}, nil
}

func (*projectReviewAuthnTransactionRepository) RejectAuthTransaction(context.Context, uuid.UUID, string, time.Time, audit.Event) (authflow.Transaction, error) {
	return authflow.Transaction{}, nil
}

func (*projectReviewAuthnTransactionRepository) ExpireAuthTransactions(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (*projectReviewAuthnTransactionRepository) CleanupAuthTransactions(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func newProjectReviewAuthnService(t *testing.T, repository *projectReviewAuthnRepository) *Service {
	t.Helper()
	ctx := context.Background()
	identities, err := identity.NewService(ctx, config.PasswordConfig{
		MinLength: 15, MaxBytes: 1024, Argon2MemoryKiB: 8 * 1024,
		Argon2Time: 1, Argon2Threads: 1, MaxConcurrent: 1,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := session.NewTokenManager(nil, time.Hour, 30*time.Minute, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transactions, err := authflow.NewService(&projectReviewAuthnTransactionRepository{}, nil, 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewService(repository, identities, tokens, transactions, nil, true, nil)
}

func TestProjectReviewRegistrationPassesOnlySessionHash(t *testing.T) {
	ctx := context.Background()
	repository := &projectReviewAuthnRepository{}
	service := newProjectReviewAuthnService(t, repository)
	now := time.Date(2026, time.August, 6, 10, 0, 0, 0, time.UTC)
	begin, err := service.Begin(ctx, BeginRegister, "", "project-review-registration", now)
	if err != nil {
		t.Fatalf("Begin(register) error = %v", err)
	}
	clearSessionToken := "s1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	_, err = service.Register(ctx, RegisterInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken,
		Account: identity.CreateInput{
			Username: "project-review-registration-user", DisplayName: "Project Review Registration",
			Email: "project-review-registration@example.invalid", Password: "project-review-registration-password",
		},
		ExistingSessionToken: clearSessionToken,
		RequestID:            "project-review-registration",
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	repository.mu.Lock()
	commit := repository.registration
	repository.mu.Unlock()
	expectedHash := session.HashToken(clearSessionToken)
	if !bytes.Equal(commit.ExistingSessionHash, expectedHash) {
		t.Fatalf("ExistingSessionHash = %x, want session-token hash %x", commit.ExistingSessionHash, expectedHash)
	}
	if len(commit.ExistingSessionHash) != 32 {
		t.Fatalf("ExistingSessionHash length = %d, want 32", len(commit.ExistingSessionHash))
	}
	if string(commit.ExistingSessionHash) == clearSessionToken || bytes.Contains(commit.ExistingSessionHash, []byte(clearSessionToken)) {
		t.Fatal("clear ExistingSessionToken was copied into RegisterCommit")
	}
}

func TestProjectReviewLoginUsesRepositoryBinding(t *testing.T) {
	ctx := context.Background()
	repository := &projectReviewAuthnRepository{}
	service := newProjectReviewAuthnService(t, repository)
	now := time.Date(2026, time.August, 6, 11, 0, 0, 0, time.UTC)
	prepared, err := service.identity.PrepareUser(ctx, identity.CreateInput{
		Username: "project-review-login-user", DisplayName: "Project Review Login",
		Email: "project-review-login@example.invalid", Password: "project-review-login-password",
	}, identity.RoleUser, now)
	if err != nil {
		t.Fatal(err)
	}
	repository.loginRecord = identity.LoginRecord(prepared)
	repository.loginBinding = uuid.New()
	clearSessionToken := "s1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	begin, err := service.Begin(ctx, BeginLogin, "", "project-review-login", now)
	if err != nil {
		t.Fatalf("Begin(login) error = %v", err)
	}
	issued, user, err := service.Login(ctx, LoginInput{
		PreAuthToken: begin.PreAuth.Token, CSRFToken: begin.PreAuth.CSRFToken,
		TransactionToken: begin.TransactionToken, Identifier: prepared.User.Username,
		Password: "project-review-login-password", ExistingSessionToken: clearSessionToken,
		RequestID: "project-review-login",
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if user.ID != prepared.User.ID {
		t.Fatalf("Login() user ID = %s, want %s", user.ID, prepared.User.ID)
	}
	if issued.Record.SessionBindingID != repository.loginBinding {
		t.Fatalf("issued binding = %s, want repository binding %s", issued.Record.SessionBindingID, repository.loginBinding)
	}

	repository.mu.Lock()
	commit := repository.login
	repository.mu.Unlock()
	if !bytes.Equal(commit.ExistingSessionHash, session.HashToken(clearSessionToken)) {
		t.Fatalf("LoginCommit ExistingSessionHash = %x, want clear-token hash", commit.ExistingSessionHash)
	}
	if string(commit.ExistingSessionHash) == clearSessionToken {
		t.Fatal("clear ExistingSessionToken was copied into LoginCommit")
	}
}

func TestProjectReviewAuthnFakeRejectsUnexpectedFlow(t *testing.T) {
	// Keep one explicit failure assertion near the fake: a repository that does
	// not know the pre-auth digest must be mapped to ErrInvalidFlow, not allowed
	// to reach credential work.
	service := newProjectReviewAuthnService(t, &projectReviewAuthnRepository{})
	_, _, err := service.Login(context.Background(), LoginInput{
		PreAuthToken: "p1_invalid", CSRFToken: "c1_invalid", TransactionToken: "t1_invalid",
		Identifier: "project-review-unused", Password: "project-review-unused",
	}, time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("Login() invalid flow error = %v, want ErrInvalidFlow", err)
	}
}
