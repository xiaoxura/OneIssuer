package consent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

type grantRepository struct {
	grant Grant
	err   error
}

func (r grantRepository) GetConsentGrant(context.Context, uuid.UUID, uuid.UUID) (Grant, error) {
	return r.grant, r.err
}

func TestEvaluateAppliesCurrentClientScopeIntersection(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	userID, clientID := uuid.New(), uuid.New()
	service, err := NewService(grantRepository{grant: Grant{
		ID: uuid.New(), UserID: userID, ClientID: clientID,
		Scopes: []string{"email", "openid", "profile"}, CreatedAt: now, UpdatedAt: now,
	}})
	if err != nil {
		t.Fatal(err)
	}
	clientValue := activeClient(clientID, []string{"openid", "profile"})

	evaluation, err := service.Evaluate(context.Background(), userID, clientValue, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !evaluation.Covers || !reflect.DeepEqual(evaluation.Effective, []string{"openid", "profile"}) || len(evaluation.NewScopes) != 0 {
		t.Fatalf("unexpected evaluation: %#v", evaluation)
	}

	evaluation, err = service.Evaluate(context.Background(), userID, activeClient(clientID, []string{"email", "openid"}), []string{"email", "openid", "profile"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("request outside current Client policy error = %v", err)
	}
}

func TestEvaluateMissingGrantAndScopeExpansion(t *testing.T) {
	t.Parallel()
	userID, clientID := uuid.New(), uuid.New()
	missing, _ := NewService(grantRepository{err: ErrNotFound})
	evaluation, err := missing.Evaluate(context.Background(), userID, activeClient(clientID, []string{"email", "openid", "profile"}), []string{"openid", "profile"})
	if err != nil || evaluation.Covers || !reflect.DeepEqual(evaluation.NewScopes, []string{"openid", "profile"}) {
		t.Fatalf("missing grant evaluation=%#v error=%v", evaluation, err)
	}

	now := time.Now().UTC()
	existing, _ := NewService(grantRepository{grant: Grant{
		ID: uuid.New(), UserID: userID, ClientID: clientID, Scopes: []string{"openid"}, CreatedAt: now, UpdatedAt: now,
	}})
	evaluation, err = existing.Evaluate(context.Background(), userID, activeClient(clientID, []string{"email", "openid", "profile"}), []string{"openid", "profile"})
	if err != nil || evaluation.Covers || !reflect.DeepEqual(evaluation.AlreadyGranted, []string{"openid"}) || !reflect.DeepEqual(evaluation.NewScopes, []string{"profile"}) {
		t.Fatalf("expansion evaluation=%#v error=%v", evaluation, err)
	}
}

func TestCanonicalScopesRejectsDuplicatesOfflineAndMissingOpenID(t *testing.T) {
	t.Parallel()
	for _, scopes := range [][]string{
		{}, {"profile"}, {"openid", "openid"}, {"openid", "offline_access"}, {" openid"},
	} {
		if _, err := CanonicalScopes(scopes); !errors.Is(err, ErrInvalid) {
			t.Errorf("CanonicalScopes(%q) error = %v", scopes, err)
		}
	}
	got, err := CanonicalScopes([]string{"profile", "openid", "email"})
	if err != nil || !reflect.DeepEqual(got, []string{"email", "openid", "profile"}) {
		t.Fatalf("canonical scopes=%q error=%v", got, err)
	}
}

func activeClient(id uuid.UUID, scopes []string) clientdomain.Client {
	return clientdomain.Client{
		ID: id, Status: clientdomain.StatusActive, Type: clientdomain.TypePublic,
		TokenEndpointAuthMethod: clientdomain.AuthMethodNone, Scopes: scopes,
	}
}
