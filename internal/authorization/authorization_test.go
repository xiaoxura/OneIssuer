package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/consent"
)

type captureRepository struct {
	commit IssueCommit
	grant  consent.Grant
	err    error
	denied DenyCommit
}

func (r *captureRepository) IssueAuthorizationCode(_ context.Context, commit IssueCommit) (consent.Grant, error) {
	r.commit = commit
	return r.grant, r.err
}

func (r *captureRepository) DenyAuthorization(_ context.Context, commit DenyCommit) error {
	r.denied = commit
	return r.err
}

func TestIssueReturnsClearCodeOnlyAfterDigestCommit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 2, 3, 4, 0, time.UTC)
	clientID := uuid.New()
	grant := consent.Grant{ID: uuid.New(), UserID: uuid.New(), ClientID: clientID, Scopes: []string{"openid"}, CreatedAt: now, UpdatedAt: now, Version: 1}
	repository := &captureRepository{grant: grant}
	randomBytes := bytes.Repeat([]byte{0x42}, 64)
	service, err := NewService(repository, bytes.NewReader(randomBytes), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	transaction := testTransaction(clientID, now)
	sessionID, bindingID := uuid.New(), uuid.New()
	issued, err := service.Issue(context.Background(), transaction, grant.UserID, sessionID, bindingID, now.Add(-time.Minute), true, "request-1", now)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if _, err := DigestPresentedCode(issued.Code); err != nil {
		t.Fatalf("issued Code invalid: %v", err)
	}
	if bytes.Contains(repository.commit.CodeHash, []byte(issued.Code)) || !bytes.Equal(repository.commit.CodeHash, HashCode(issued.Code)) {
		t.Fatal("repository did not receive only the expected Code digest")
	}
	if repository.commit.Transaction.ID != transaction.ID || repository.commit.UserID != grant.UserID ||
		repository.commit.SessionID != sessionID || repository.commit.SessionBindingID != bindingID || !repository.commit.InteractiveConsent {
		t.Fatalf("unexpected commit: %#v", repository.commit)
	}
}

func TestIssueDoesNotReturnCodeWhenCommitFails(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	clientID := uuid.New()
	repository := &captureRepository{err: ErrConsumed}
	service, _ := NewService(repository, bytes.NewReader(bytes.Repeat([]byte{1}, 64)), time.Minute, nil)
	issued, err := service.Issue(context.Background(), testTransaction(clientID, now), uuid.New(), uuid.New(), uuid.New(), now, false, "", now)
	if !errors.Is(err, ErrConsumed) || issued.Code != "" {
		t.Fatalf("issued=%#v error=%v", issued, err)
	}
}

func TestVerifyS256StrictGrammarAndComparison(t *testing.T) {
	t.Parallel()
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if err := VerifyS256(verifier, challenge); err != nil {
		t.Fatalf("VerifyS256(valid) error = %v", err)
	}
	for _, invalid := range []string{
		verifier[:42], verifier + string(bytes.Repeat([]byte{'a'}, 70)), "é" + verifier,
		verifier + "=", verifier + " ",
	} {
		if err := VerifyS256(invalid, challenge); !errors.Is(err, ErrInvalid) {
			t.Errorf("VerifyS256(%q) error = %v", invalid, err)
		}
	}
	if err := VerifyS256(verifier, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong challenge error = %v", err)
	}
}

func TestDigestPresentedCodeRejectsWrongVersionPaddingAndLength(t *testing.T) {
	t.Parallel()
	valid := "c1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if _, err := DigestPresentedCode(valid); err != nil {
		t.Fatalf("valid digest error = %v", err)
	}
	for _, value := range []string{"", "c2_" + valid[3:], valid + "=", valid[:len(valid)-1], "c1_" + string(bytes.Repeat([]byte{'*'}, 43))} {
		if _, err := DigestPresentedCode(value); !errors.Is(err, ErrNotFound) {
			t.Errorf("DigestPresentedCode(%q) error = %v", value, err)
		}
	}
}

func testTransaction(clientID uuid.UUID, now time.Time) authflow.Transaction {
	return authflow.Transaction{
		ID: uuid.New(), Kind: authflow.KindAuthorization, ClientID: &clientID,
		RedirectURI: "https://client.example/callback", Scopes: []string{"openid"},
		PKCEChallenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PKCEMethod: "S256",
		ResponseType: "code", ResponseMode: "query", CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	}
}
