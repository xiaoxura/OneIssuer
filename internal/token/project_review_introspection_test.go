package token

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
)

func TestProjectReviewActiveAccessIntrospectionHasExactJSONProfile(t *testing.T) {
	t.Parallel()

	fixture := newTokenFixture(t, []string{"email", "openid", "profile"})
	fixture.authority.Client.Type = clientdomain.TypeConfidential
	fixture.authority.Client.TokenEndpointAuthMethod = clientdomain.AuthMethodClientSecretBasic
	fixture.repository.exchangeAuthority = fixture.authority

	issued, err := fixture.service.Exchange(context.Background(), fixture.exchangeInput())
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.accessAuthority = fixture.accessAuthority()

	got, err := fixture.service.Introspect(context.Background(), IntrospectionInput{
		Client: fixture.authority.Client,
		Token:  issued.AccessToken,
		Now:    fixture.now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"active":     true,
		"token_type": "Bearer",
		"client_id":  fixture.authority.Client.ClientID,
		"scope":      "email openid profile",
		"sub":        fixture.authority.User.Subject,
		"iss":        testIssuer,
		"aud":        testIssuer + "/oauth2/userinfo",
		"iat":        float64(fixture.now.Unix()),
		"exp":        float64(fixture.now.Add(10 * time.Minute).Unix()),
	}
	assertProjectReviewIntrospectionJSON(t, got, want)
}

func TestProjectReviewActiveRefreshIntrospectionOmitsAccessOnlyFields(t *testing.T) {
	t.Parallel()

	fixture := newTokenFixture(t, []string{"offline_access", "openid", "profile"})
	clientValue := fixture.authority.Client
	clientValue.Type = clientdomain.TypeConfidential
	clientValue.TokenEndpointAuthMethod = clientdomain.AuthMethodClientSecretBasic
	now := fixture.now
	clearToken, digest, err := GenerateRefreshToken(bytes.NewReader(bytes.Repeat([]byte{0x42}, refreshTokenBytes)))
	if err != nil {
		t.Fatal(err)
	}
	familyID := uuid.New()
	grant := consent.Grant{
		ID: fixture.authority.GrantID, UserID: fixture.authority.User.ID, ClientID: clientValue.ID,
		Scopes: append([]string(nil), fixture.authority.Scopes...), CreatedAt: now.Add(-time.Hour), UpdatedAt: now, Version: 1,
	}
	repository := &projectReviewIntrospectionRepository{refreshAuthority: RefreshTokenAuthority{
		Generation: RefreshGeneration{
			ID: uuid.New(), FamilyID: familyID, TokenHash: digest, Generation: 0,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		},
		Family: RefreshFamily{
			ID: familyID, ConsentGrantID: grant.ID, UserID: fixture.authority.User.ID, ClientID: clientValue.ID,
			SessionBindingID: uuid.New(), Scopes: append([]string(nil), fixture.authority.Scopes...),
			CreatedAt: now.Add(-time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour),
		},
		Grant: grant, User: fixture.authority.User, Client: clientValue,
	}}
	service, err := NewService(repository, fixture.keys, bytes.NewReader(bytes.Repeat([]byte{0x11}, 128)), testIssuer, 5*time.Minute, 10*time.Minute, 30*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := service.Introspect(context.Background(), IntrospectionInput{
		Client: clientValue, Token: clearToken, Hint: "refresh_token", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"active":    true,
		"client_id": clientValue.ClientID,
		"scope":     "offline_access openid profile",
		"sub":       fixture.authority.User.Subject,
		"iss":       testIssuer,
		"iat":       float64(now.Add(-time.Minute).Unix()),
		"exp":       float64(now.Add(time.Hour).Unix()),
	}
	assertProjectReviewIntrospectionJSON(t, got, want)

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token_type", "aud"} {
		if bytes.Contains(encoded, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("refresh introspection emitted forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestProjectReviewInactiveIntrospectionIsExactlyMinimal(t *testing.T) {
	t.Parallel()

	fixture := newTokenFixture(t, []string{"openid"})
	fixture.authority.Client.Type = clientdomain.TypeConfidential
	fixture.authority.Client.TokenEndpointAuthMethod = clientdomain.AuthMethodClientSecretBasic
	got, err := fixture.service.Introspect(context.Background(), IntrospectionInput{
		Client: fixture.authority.Client, Token: "unknown", Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"active":false}` {
		t.Fatalf("inactive introspection JSON = %s", encoded)
	}
}

func assertProjectReviewIntrospectionJSON(t *testing.T, response IntrospectionResponse, want map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("introspection JSON is invalid: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("introspection JSON = %#v, want %#v (raw %s)", got, want, encoded)
	}
}

type projectReviewIntrospectionRepository struct {
	refreshAuthority RefreshTokenAuthority
}

func (r *projectReviewIntrospectionRepository) ExchangeAuthorizationCode(context.Context, ExchangeInput, MintFunc) (Response, error) {
	return Response{}, ErrInvalidGrant
}

func (r *projectReviewIntrospectionRepository) ExchangeRefreshToken(context.Context, RefreshInput, RefreshMintFunc) (Response, error) {
	return Response{}, ErrInvalidGrant
}

func (r *projectReviewIntrospectionRepository) RevokeToken(context.Context, RevocationLookup) error {
	return nil
}

func (r *projectReviewIntrospectionRepository) GetAccessTokenAuthority(context.Context, []byte, time.Time) (AccessAuthority, error) {
	return AccessAuthority{}, ErrInvalidToken
}

func (r *projectReviewIntrospectionRepository) GetRefreshTokenAuthority(_ context.Context, digest []byte) (RefreshTokenAuthority, error) {
	if !bytes.Equal(digest, r.refreshAuthority.Generation.TokenHash) {
		return RefreshTokenAuthority{}, ErrInvalidGrant
	}
	return r.refreshAuthority, nil
}

var _ Repository = (*projectReviewIntrospectionRepository)(nil)
