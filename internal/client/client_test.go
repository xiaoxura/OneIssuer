package client

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/pagination"
)

type fakeRepository struct {
	created Client
	secret  *SecretRecord
}

func (f *fakeRepository) CreateClient(_ context.Context, value Client, secret *SecretRecord, _ audit.Event) error {
	f.created, f.secret = value, secret
	return nil
}
func (f *fakeRepository) GetClient(context.Context, uuid.UUID) (Client, error) { return f.created, nil }
func (f *fakeRepository) ListClients(context.Context, pagination.Cursor, int) ([]Client, error) {
	return []Client{f.created}, nil
}
func (f *fakeRepository) UpdateClient(context.Context, Client, audit.Event) error { return nil }
func (f *fakeRepository) RotateClientSecret(context.Context, uuid.UUID, SecretRecord, time.Time, audit.Event) error {
	return nil
}
func (f *fakeRepository) GetClientSecretHashes(context.Context, string) (Client, [][]byte, error) {
	if f.secret == nil {
		return f.created, nil, nil
	}
	return f.created, [][]byte{f.secret.SecretHash}, nil
}

func TestClientTypeURIAndSecretRules(t *testing.T) {
	t.Parallel()
	repository := &fakeRepository{}
	service := NewService(repository, bytes.NewReader(bytes.Repeat([]byte{3}, 512)), true, nil)
	actor := uuid.New()
	public, err := service.Create(context.Background(), actor, CreateInput{
		Type: TypePublic, Name: "Public", RedirectURIs: []string{"http://127.0.0.1:3000/callback"}, Scopes: []string{"profile", "openid"},
	}, "request", time.Now())
	if err != nil || public.Secret != "" || repository.secret != nil || public.Client.TokenEndpointAuthMethod != AuthMethodNone {
		t.Fatalf("public Create()=%+v secret=%+v err=%v", public, repository.secret, err)
	}
	confidential, err := service.Create(context.Background(), actor, CreateInput{
		Type: TypeConfidential, Name: "Confidential", RedirectURIs: []string{"https://app.example/callback?x=1"}, Scopes: []string{"openid"},
	}, "request", time.Now())
	if err != nil || confidential.Secret == "" || repository.secret == nil || !validSecret(confidential.Secret) {
		t.Fatalf("confidential Create() secret present=%v err=%v", confidential.Secret != "", err)
	}
	if string(repository.secret.SecretHash) == confidential.Secret {
		t.Fatal("clear secret was stored as its digest")
	}
	if !service.RedirectURIMatches(confidential.Client, "https://app.example/callback?x=1") ||
		service.RedirectURIMatches(confidential.Client, "https://app.example/callback?x=2") {
		t.Fatal("redirect URI matching was not exact")
	}
}

func TestUnsafeClientURIsAndScopesAreRejected(t *testing.T) {
	t.Parallel()
	service := NewService(&fakeRepository{}, bytes.NewReader(bytes.Repeat([]byte{4}, 512)), false, nil)
	for _, uri := range []string{"http://app.example/callback", "https://*.example/callback", "https://app.example/callback#fragment", "/relative"} {
		_, err := service.Create(context.Background(), uuid.New(), CreateInput{Type: TypePublic, Name: "Bad", RedirectURIs: []string{uri}, Scopes: []string{"openid"}}, "request", time.Now())
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("unsafe URI %q error=%v", uri, err)
		}
	}
	_, err := service.Create(context.Background(), uuid.New(), CreateInput{Type: TypePublic, Name: "Bad", RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"admin"}}, "request", time.Now())
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported scope error=%v", err)
	}
}
