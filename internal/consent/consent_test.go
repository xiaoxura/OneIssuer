package consent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

type grantRepository struct {
	grant   Grant
	list    []ManagedGrant
	revoked ManagedGrant
	err     error
}

func (r grantRepository) GetConsentGrant(context.Context, uuid.UUID, uuid.UUID) (Grant, error) {
	return r.grant, r.err
}

func (r grantRepository) ListCurrentUserGrants(context.Context, uuid.UUID, GrantCursor, int, time.Time) ([]ManagedGrant, error) {
	return append([]ManagedGrant(nil), r.list...), r.err
}

func (r grantRepository) RevokeCurrentUserGrant(context.Context, RevokeInput) (ManagedGrant, error) {
	return r.revoked, r.err
}

func TestEvaluateAppliesCurrentClientScopeIntersection(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	userID, clientID := uuid.New(), uuid.New()
	service, err := NewService(grantRepository{grant: Grant{
		ID: uuid.New(), UserID: userID, ClientID: clientID,
		Scopes: []string{"email", "openid", "profile"}, CreatedAt: now, UpdatedAt: now, Version: 1,
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
		ID: uuid.New(), UserID: userID, ClientID: clientID, Scopes: []string{"openid"}, CreatedAt: now, UpdatedAt: now, Version: 1,
	}})
	evaluation, err = existing.Evaluate(context.Background(), userID, activeClient(clientID, []string{"email", "openid", "profile"}), []string{"openid", "profile"})
	if err != nil || evaluation.Covers || !reflect.DeepEqual(evaluation.AlreadyGranted, []string{"openid"}) || !reflect.DeepEqual(evaluation.NewScopes, []string{"profile"}) {
		t.Fatalf("expansion evaluation=%#v error=%v", evaluation, err)
	}
}

func TestCanonicalScopesAcceptsOfflineAndRejectsDuplicatesOrMissingOpenID(t *testing.T) {
	t.Parallel()
	for _, scopes := range [][]string{
		{}, {"profile"}, {"openid", "openid"}, {"openid", "unknown"}, {" openid"},
	} {
		if _, err := CanonicalScopes(scopes); !errors.Is(err, ErrInvalid) {
			t.Errorf("CanonicalScopes(%q) error = %v", scopes, err)
		}
	}
	got, err := CanonicalScopes([]string{"profile", "openid", "email"})
	if err != nil || !reflect.DeepEqual(got, []string{"email", "openid", "profile"}) {
		t.Fatalf("canonical scopes=%q error=%v", got, err)
	}
	got, err = CanonicalScopes([]string{"profile", "offline_access", "openid"})
	if err != nil || !reflect.DeepEqual(got, []string{"offline_access", "openid", "profile"}) {
		t.Fatalf("offline canonical scopes=%q error=%v", got, err)
	}
}

func TestEvaluateRevokedGrantRequiresFreshConsent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	userID, clientID := uuid.New(), uuid.New()
	revokedAt := now.Add(-time.Minute)
	service, _ := NewService(grantRepository{grant: Grant{
		ID: uuid.New(), UserID: userID, ClientID: clientID,
		Scopes: []string{"offline_access", "openid", "profile"}, CreatedAt: now.Add(-time.Hour), UpdatedAt: revokedAt,
		RevokedAt: &revokedAt, Version: 2,
	}})
	evaluation, err := service.Evaluate(context.Background(), userID,
		activeClient(clientID, []string{"offline_access", "openid", "profile"}), []string{"offline_access", "openid"})
	if err != nil || evaluation.Covers || len(evaluation.Effective) != 0 ||
		!reflect.DeepEqual(evaluation.NewScopes, []string{"offline_access", "openid"}) {
		t.Fatalf("revoked evaluation=%#v error=%v", evaluation, err)
	}
}

func TestGrantCursorRoundTripContainsOnlyPublicOrderingKeys(t *testing.T) {
	t.Parallel()
	updated := time.Date(2026, time.August, 2, 9, 8, 7, 654321000, time.UTC)
	publicID := testPublicClientID(7)
	internalID := uuid.New()
	raw := EncodeGrantCursor(GrantCursor{UpdatedAt: updated, ClientID: publicID})
	if raw == "" || strings.Contains(raw, internalID.String()) {
		t.Fatalf("unsafe or empty cursor %q", raw)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != 3 || wire["v"] != float64(1) || wire["c"] != publicID || wire["u"] != updated.Format(time.RFC3339Nano) {
		t.Fatalf("cursor payload contains unexpected data: %s", payload)
	}
	decoded, err := DecodeGrantCursor(raw)
	if err != nil || decoded.ClientID != publicID || !decoded.UpdatedAt.Equal(updated) {
		t.Fatalf("decoded cursor=%#v error=%v", decoded, err)
	}
}

func TestGrantCursorStrictlyRejectsInternalOrNonCanonicalPayload(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	for _, raw := range []string{
		" ", "not+base64", strings.Repeat("a", 1025),
		encode(`{"v":2,"u":"` + now.Format(time.RFC3339Nano) + `","c":"` + testPublicClientID(1) + `"}`),
		encode(`{"v":1,"u":"` + now.Format(time.RFC3339Nano) + `","c":"` + uuid.NewString() + `"}`),
		encode(`{"v":1,"u":"2026-08-02T00:00:00.000000000Z","c":"` + testPublicClientID(2) + `"}`),
		encode(`{"v":1,"u":"` + now.Format(time.RFC3339Nano) + `","c":"` + testPublicClientID(3) + `","id":"` + uuid.NewString() + `"}`),
	} {
		if _, err := DecodeGrantCursor(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("DecodeGrantCursor(%q) error=%v", raw, err)
		}
	}
}

func TestListMineUsesSentinelAndSafeNextCursor(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	items := []ManagedGrant{
		{ClientID: testPublicClientID(1), UpdatedAt: now},
		{ClientID: testPublicClientID(2), UpdatedAt: now.Add(-time.Minute)},
		{ClientID: testPublicClientID(3), UpdatedAt: now.Add(-2 * time.Minute)},
	}
	service, _ := NewService(grantRepository{list: items})
	page, err := service.ListMine(context.Background(), uuid.New(), "", 2, now)
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("page=%#v error=%v", page, err)
	}
	cursor, err := DecodeGrantCursor(page.NextCursor)
	if err != nil || cursor.ClientID != items[1].ClientID || !cursor.UpdatedAt.Equal(items[1].UpdatedAt) {
		t.Fatalf("next cursor=%#v error=%v", cursor, err)
	}
}

func TestRevokeMineRejectsNonPublicSelectorUniformly(t *testing.T) {
	t.Parallel()
	service, _ := NewService(grantRepository{})
	for _, selector := range []string{"", uuid.NewString(), "other", " " + testPublicClientID(1)} {
		if _, err := service.RevokeMine(context.Background(), uuid.New(), selector, "request", time.Now()); !errors.Is(err, ErrNotFound) {
			t.Errorf("selector=%q error=%v", selector, err)
		}
	}
}

func testPublicClientID(fill byte) string {
	return "ois_cli_" + base64.RawURLEncoding.EncodeToString(bytesOf(fill, 24))
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func activeClient(id uuid.UUID, scopes []string) clientdomain.Client {
	return clientdomain.Client{
		ID: id, Status: clientdomain.StatusActive, Type: clientdomain.TypePublic,
		TokenEndpointAuthMethod: clientdomain.AuthMethodNone, Scopes: scopes,
	}
}
