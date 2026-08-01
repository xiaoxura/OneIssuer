package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

type tokenClientResolver struct {
	public       clientdomain.Client
	confidential clientdomain.Client
	secret       string
}

func (r tokenClientResolver) ResolveActive(_ context.Context, id string) (clientdomain.Client, error) {
	if id == r.public.ClientID {
		return r.public, nil
	}
	if id == r.confidential.ClientID {
		return r.confidential, nil
	}
	return clientdomain.Client{}, clientdomain.ErrNotFound
}

func (r tokenClientResolver) ValidateSecret(_ context.Context, id, secret string) (clientdomain.Client, error) {
	if id == r.confidential.ClientID && secret == r.secret {
		return r.confidential, nil
	}
	return clientdomain.Client{}, clientdomain.ErrNotFound
}

func TestParseTokenRequestPublicAndConfidential(t *testing.T) {
	t.Parallel()
	resolver := tokenResolverFixture()
	for _, confidential := range []bool{false, true} {
		form := validTokenForm(resolver.public.ClientID)
		header := make(http.Header)
		if confidential {
			form.Del("client_id")
			header.Set("Authorization", basicHeader(resolver.confidential.ClientID, resolver.secret))
		}
		parsed, err := ParseTokenRequest(context.Background(), form, header, resolver)
		if err != nil {
			t.Fatalf("confidential=%v ParseTokenRequest() error = %v", confidential, err)
		}
		want := resolver.public.ID
		if confidential {
			want = resolver.confidential.ID
		}
		if parsed.Client.ID != want || len(parsed.CodeHash) != 32 || parsed.CodeVerifier == "" {
			t.Fatalf("confidential=%v parsed=%#v", confidential, parsed)
		}
	}
}

func TestParseTokenRequestNegativeMatrix(t *testing.T) {
	t.Parallel()
	resolver := tokenResolverFixture()
	tests := []struct {
		name      string
		mutate    func(url.Values, http.Header)
		wantCode  string
		challenge bool
	}{
		{name: "refresh unsupported", mutate: func(v url.Values, _ http.Header) { v.Set("grant_type", "refresh_token") }, wantCode: "unsupported_grant_type"},
		{name: "duplicate code", mutate: func(v url.Values, _ http.Header) { v.Add("code", v.Get("code")) }, wantCode: "invalid_request"},
		{name: "missing redirect", mutate: func(v url.Values, _ http.Header) { v.Del("redirect_uri") }, wantCode: "invalid_request"},
		{name: "wrong code version", mutate: func(v url.Values, _ http.Header) { v.Set("code", "c2_invalid") }, wantCode: "invalid_grant"},
		{name: "short verifier", mutate: func(v url.Values, _ http.Header) { v.Set("code_verifier", "short") }, wantCode: "invalid_grant"},
		{name: "client secret body", mutate: func(v url.Values, _ http.Header) { v.Set("client_secret", "secret") }, wantCode: "invalid_client"},
		{name: "confidential without Basic", mutate: func(v url.Values, _ http.Header) { v.Set("client_id", resolver.confidential.ClientID) }, wantCode: "invalid_client", challenge: true},
		{name: "public with Basic", mutate: func(v url.Values, h http.Header) {
			v.Del("client_id")
			h.Set("Authorization", basicHeader(resolver.public.ClientID, resolver.secret))
		}, wantCode: "invalid_client", challenge: true},
		{name: "mixed auth channels", mutate: func(_ url.Values, h http.Header) {
			h.Set("Authorization", basicHeader(resolver.confidential.ClientID, resolver.secret))
		}, wantCode: "invalid_client", challenge: true},
		{name: "bad Basic base64", mutate: func(v url.Values, h http.Header) { v.Del("client_id"); h.Set("Authorization", "Basic !!!") }, wantCode: "invalid_client", challenge: true},
		{name: "Bearer downgrade", mutate: func(v url.Values, h http.Header) { v.Del("client_id"); h.Set("Authorization", "Bearer token") }, wantCode: "invalid_client", challenge: true},
		{name: "duplicate Authorization", mutate: func(v url.Values, h http.Header) {
			v.Del("client_id")
			h.Add("Authorization", basicHeader(resolver.confidential.ClientID, resolver.secret))
			h.Add("Authorization", basicHeader(resolver.confidential.ClientID, resolver.secret))
		}, wantCode: "invalid_client", challenge: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			form := validTokenForm(resolver.public.ClientID)
			header := make(http.Header)
			test.mutate(form, header)
			_, err := ParseTokenRequest(context.Background(), form, header, resolver)
			var protocolError *TokenError
			if !errors.As(err, &protocolError) || protocolError.Code != test.wantCode || protocolError.BasicChallenge != test.challenge {
				t.Fatalf("error=%#v want code=%q challenge=%v", err, test.wantCode, test.challenge)
			}
			for _, sensitive := range []string{form.Get("code"), form.Get("code_verifier"), resolver.secret, resolver.public.ClientID} {
				if sensitive != "" && strings.Contains(err.Error(), sensitive) {
					t.Fatalf("TokenError leaked sensitive value: %v", err)
				}
			}
		})
	}
}

func tokenResolverFixture() tokenClientResolver {
	publicID := "ois_cli_" + base64.RawURLEncoding.EncodeToString(make([]byte, 24))
	confidentialBytes := make([]byte, 24)
	confidentialBytes[0] = 1
	confidentialID := "ois_cli_" + base64.RawURLEncoding.EncodeToString(confidentialBytes)
	secret := "ois_sec_v1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	return tokenClientResolver{
		public:       clientdomain.Client{ID: uuid.New(), ClientID: publicID, Type: clientdomain.TypePublic, TokenEndpointAuthMethod: clientdomain.AuthMethodNone, Status: clientdomain.StatusActive, Scopes: []string{"openid"}},
		confidential: clientdomain.Client{ID: uuid.New(), ClientID: confidentialID, Type: clientdomain.TypeConfidential, TokenEndpointAuthMethod: clientdomain.AuthMethodClientSecretBasic, Status: clientdomain.StatusActive, Scopes: []string{"openid"}},
		secret:       secret,
	}
}

func validTokenForm(clientID string) url.Values {
	code := "c1_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	if authorization.ValidateVerifier(verifier) != nil {
		panic("invalid verifier fixture")
	}
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://rp.example/cb"}, "code_verifier": {verifier}, "client_id": {clientID},
	}
}

func basicHeader(clientID, secret string) string {
	credentials := url.QueryEscape(clientID) + ":" + url.QueryEscape(secret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}
