package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzTokenRequestAndBasicParsing(f *testing.F) {
	resolver := tokenResolverFixture()
	f.Add(validTokenForm(resolver.public.ClientID).Encode(), "")
	f.Add(validTokenForm(resolver.confidential.ClientID).Encode(), basicHeader(resolver.confidential.ClientID, resolver.secret))
	f.Add("grant_type=refresh_token&code=canary", "Bearer downgrade")
	f.Add("code=%GG", "Basic !!!")

	f.Fuzz(func(t *testing.T, encodedForm, authorizationHeader string) {
		if len(encodedForm) > 32<<10 || len(authorizationHeader) > 32<<10 {
			t.Skip()
		}
		form, err := url.ParseQuery(encodedForm)
		if err != nil {
			return
		}
		header := make(http.Header)
		if authorizationHeader != "" {
			header["Authorization"] = []string{authorizationHeader}
		}
		verified, parseErr := ParseTokenRequest(context.Background(), form, header, resolver)
		if parseErr == nil {
			if len(verified.CodeHash) != 32 || verified.Client.ID.String() == "00000000-0000-0000-0000-000000000000" ||
				verified.RedirectURI == "" || verified.CodeVerifier == "" || strings.Contains(string(verified.CodeHash), form.Get("code")) {
				t.Fatalf("successful token parse violated boundary: %+v", verified)
			}
		}

		clientID, secret, basicErr := parseStrictBasic(authorizationHeader)
		if basicErr == nil && (clientID == "" || secret == "" || strings.ContainsAny(clientID+secret, "\x00\r\n")) {
			t.Fatal("strict Basic parser returned unsafe empty/control credentials")
		}
	})
}
