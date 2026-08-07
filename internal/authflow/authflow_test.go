package authflow

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
)

type transactionRepository struct {
	created      Transaction
	rejected     Transaction
	reason       string
	expired      int64
	expireErr    error
	deleted      int64
	cleanupErr   error
	cleanupCalls int
}

func (r *transactionRepository) CreateAuthTransaction(_ context.Context, value Transaction, _ audit.Event) error {
	r.created = value
	return nil
}
func (r *transactionRepository) FindAuthTransaction(context.Context, []byte) (Transaction, error) {
	return r.created, nil
}
func (r *transactionRepository) ConsumeAuthTransaction(context.Context, uuid.UUID, time.Time, audit.Event) (Transaction, error) {
	return Transaction{}, nil
}
func (r *transactionRepository) RejectAuthTransaction(_ context.Context, _ uuid.UUID, reason string, now time.Time, _ audit.Event) (Transaction, error) {
	if r.rejected.ID != uuid.Nil {
		return Transaction{}, ErrConsumed
	}
	r.reason = reason
	r.rejected = r.created
	r.rejected.ConsumedAt = &now
	r.rejected.FailureReason = reason
	return r.rejected, nil
}
func (r *transactionRepository) ExpireAuthTransactions(context.Context, time.Time) (int64, error) {
	return r.expired, r.expireErr
}
func (r *transactionRepository) CleanupAuthTransactions(context.Context, time.Time) (int64, error) {
	r.cleanupCalls++
	return r.deleted, r.cleanupErr
}

func TestCreateVerifiedPersistsCompleteCanonicalProtocolContext(t *testing.T) {
	t.Parallel()

	repository := &transactionRepository{}
	service, err := NewService(repository, bytes.NewReader(bytes.Repeat([]byte{7}, 256)), 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	maxAge := uint32(60)
	token, transaction, err := service.CreateVerified(context.Background(), VerifiedInput{
		ClientID: uuid.New(), RedirectURI: "https://rp.example.test/callback", Scopes: []string{"profile", "openid", "profile"},
		PKCEChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", State: "state", Nonce: "nonce",
		ResponseType: "code", ResponseMode: "query", Prompts: []string{"consent", "login"}, MaxAgeSeconds: &maxAge,
	}, "request", time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("CreateVerified() error = %v", err)
	}
	if !validToken(token) || transaction.PKCEMethod != "S256" || transaction.ResponseType != "code" || transaction.ResponseMode != "query" ||
		len(transaction.Scopes) != 2 || transaction.Scopes[0] != "openid" || transaction.Scopes[1] != "profile" ||
		transaction.MaxAgeSeconds == nil || *transaction.MaxAgeSeconds != maxAge {
		t.Fatalf("unexpected transaction: %+v", transaction)
	}
	if repository.created.State != "state" || repository.created.Nonce != "nonce" {
		t.Fatalf("repository lost opaque context: %+v", repository.created)
	}

	rejected, err := service.Reject(context.Background(), transaction, "login_required", nil, "request", time.Unix(1001, 0))
	if err != nil || rejected.FailureReason != "login_required" || repository.reason != "login_required" {
		t.Fatalf("Reject()=%+v reason=%q err=%v", rejected, repository.reason, err)
	}
	if _, err := service.Reject(context.Background(), transaction, "login_required", nil, "request", time.Unix(1002, 0)); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second Reject() error=%v", err)
	}
}

func TestCreateVerifiedRejectsIncompleteOrDowngradedContext(t *testing.T) {
	t.Parallel()

	valid := VerifiedInput{
		ClientID: uuid.New(), RedirectURI: "https://rp.example.test/callback", Scopes: []string{"openid"},
		PKCEChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", ResponseType: "code", ResponseMode: "query",
	}
	for _, mutate := range []func(*VerifiedInput){
		func(value *VerifiedInput) { value.ClientID = uuid.Nil },
		func(value *VerifiedInput) { value.RedirectURI = "https://rp.example.test/callback#fragment" },
		func(value *VerifiedInput) { value.Scopes = []string{"openid", "unsupported"} },
		func(value *VerifiedInput) { value.PKCEChallenge = "plain" },
		func(value *VerifiedInput) { value.ResponseType = "token" },
		func(value *VerifiedInput) { value.ResponseMode = "fragment" },
		func(value *VerifiedInput) { value.Prompts = []string{"none", "login"} },
		func(value *VerifiedInput) { value.Prompts = []string{"create"}; value.PromptCreate = false },
	} {
		repository := &transactionRepository{}
		service, err := NewService(repository, bytes.NewReader(bytes.Repeat([]byte{9}, 256)), time.Minute, nil)
		if err != nil {
			t.Fatal(err)
		}
		input := valid
		mutate(&input)
		if _, _, err := service.CreateVerified(context.Background(), input, "request", time.Now()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid input %+v error=%v", input, err)
		}
	}
}

func TestCleanupRetainsCommittedExpiryProgress(t *testing.T) {
	t.Parallel()

	expireErr := errors.New("later expiry batch failed")
	repository := &transactionRepository{expired: 250, expireErr: expireErr}
	service, err := NewService(repository, bytes.NewReader(bytes.Repeat([]byte{3}, 64)), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err := service.Cleanup(context.Background(), time.Unix(1000, 0))
	if count != 250 || !errors.Is(err, expireErr) {
		t.Fatalf("Cleanup() count=%d error=%v, want committed count 250 and expiry error", count, err)
	}
	if repository.cleanupCalls != 0 {
		t.Fatalf("CleanupAuthTransactions() calls=%d after expiry failure, want 0", repository.cleanupCalls)
	}
}
