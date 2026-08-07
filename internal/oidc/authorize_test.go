package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	clientdomain "github.com/oneissuer/oneissuer/internal/client"
)

type authorizeClientResolver struct {
	client clientdomain.Client
	err    error
}

func (r authorizeClientResolver) ResolveActive(context.Context, string) (clientdomain.Client, error) {
	if r.err != nil {
		return clientdomain.Client{}, r.err
	}
	return r.client, nil
}
func (r authorizeClientResolver) RedirectURIMatches(value clientdomain.Client, candidate string) bool {
	for _, registered := range value.RedirectURIs {
		if registered == candidate {
			return true
		}
	}
	return false
}

func validAuthorizeFixture() (authorizeClientResolver, url.Values) {
	publicID := "ois_cli_" + base64.RawURLEncoding.EncodeToString(make([]byte, 24))
	redirect := "https://rp.example.test/callback?tenant=fixed"
	resolver := authorizeClientResolver{client: clientdomain.Client{
		ClientID: publicID, Type: clientdomain.TypePublic,
		TokenEndpointAuthMethod: clientdomain.AuthMethodNone, Status: clientdomain.StatusActive,
		RedirectURIs: []string{redirect}, Scopes: []string{"email", "openid", "profile"},
	}}
	values := url.Values{
		"client_id":             {publicID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"scope":                 {"openid profile email profile"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"opaque-state"},
		"nonce":                 {"opaque-nonce"},
		"prompt":                {"login consent"},
		"max_age":               {"0"},
	}
	return resolver, values
}

func TestParseAuthorizationRequestValidProfile(t *testing.T) {
	t.Parallel()

	resolver, values := validAuthorizeFixture()
	request, err := ParseAuthorizationRequest(context.Background(), values.Encode(), resolver)
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest() error = %v", err)
	}
	if request.Client.ClientID != resolver.client.ClientID || request.RedirectURI != resolver.client.RedirectURIs[0] ||
		request.ResponseType != "code" || request.ResponseMode != "query" || request.State != "opaque-state" || request.Nonce != "opaque-nonce" {
		t.Fatalf("unexpected request: %+v", request)
	}
	if !reflect.DeepEqual(request.Scopes, []string{"email", "openid", "profile"}) ||
		!reflect.DeepEqual(request.Prompts.Values(), []string{"consent", "login"}) || request.MaxAge == nil || *request.MaxAge != 0 {
		t.Fatalf("unexpected canonical values: scopes=%v prompts=%v max_age=%v", request.Scopes, request.Prompts.Values(), request.MaxAge)
	}
}

func TestParseAuthorizationRequestRejectsNULInNamesAndValues(t *testing.T) {
	t.Parallel()

	resolver, values := validAuthorizeFixture()
	for _, raw := range []string{
		values.Encode() + "&%00canary=value",
		strings.Replace(values.Encode(), "opaque-state", "opaque%00state", 1),
		strings.Replace(values.Encode(), resolver.client.ClientID, resolver.client.ClientID+"%00", 1),
	} {
		_, err := ParseAuthorizationRequest(context.Background(), raw, resolver)
		var protocolError *AuthorizationError
		if !errors.As(err, &protocolError) || protocolError.Code != ErrorInvalidRequest {
			t.Fatalf("NUL-bearing query error = %#v", err)
		}
	}
}

func TestParseAuthorizationRequestAcceptsOnlyFrozenPromptCombinations(t *testing.T) {
	t.Parallel()

	resolver, base := validAuthorizeFixture()
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "missing"},
		{name: "none", raw: "none", want: []string{"none"}},
		{name: "login", raw: "login", want: []string{"login"}},
		{name: "consent", raw: "consent", want: []string{"consent"}},
		{name: "create", raw: "create", want: []string{"create"}},
		{name: "login consent", raw: "login consent", want: []string{"consent", "login"}},
		{name: "create consent", raw: "create consent", want: []string{"consent", "create"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := cloneValues(base)
			if test.raw == "" {
				values.Del("prompt")
			} else {
				values.Set("prompt", test.raw)
			}
			request, err := ParseAuthorizationRequest(context.Background(), values.Encode(), resolver)
			if err != nil {
				t.Fatalf("ParseAuthorizationRequest(prompt=%q) error = %v", test.raw, err)
			}
			if got := request.Prompts.Values(); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("prompt=%q canonical values=%v, want %v", test.raw, got, test.want)
			}
		})
	}
}

func TestAuthorizationRedirectTrustBoundary(t *testing.T) {
	t.Parallel()

	resolver, base := validAuthorizeFixture()
	tests := []struct {
		name       string
		mutate     func(url.Values)
		resolver   authorizeClientResolver
		redirected bool
		code       ErrorCode
	}{
		{name: "malformed percent encoding", mutate: func(url.Values) {}, resolver: resolver, code: ErrorInvalidRequest},
		{name: "unknown client", mutate: func(url.Values) {}, resolver: authorizeClientResolver{err: clientdomain.ErrNotFound}, code: ErrorInvalidRequest},
		{name: "client lookup outage", mutate: func(url.Values) {}, resolver: authorizeClientResolver{err: errors.New("database unavailable")}, code: ErrorServerError},
		{name: "redirect mismatch", mutate: func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") }, resolver: resolver, code: ErrorInvalidRequest},
		{name: "duplicate client", mutate: func(v url.Values) { v.Add("client_id", "attacker") }, resolver: resolver, code: ErrorInvalidRequest},
		{name: "duplicate redirect", mutate: func(v url.Values) { v.Add("redirect_uri", "https://evil.example/cb") }, resolver: resolver, code: ErrorInvalidRequest},
		{name: "bad response type", mutate: func(v url.Values) { v.Set("response_type", "token") }, resolver: resolver, redirected: true, code: ErrorUnsupportedResponseType},
		{name: "duplicate state", mutate: func(v url.Values) { v.Add("state", "second") }, resolver: resolver, redirected: true, code: ErrorInvalidRequest},
		{name: "request object", mutate: func(v url.Values) { v.Set("request", "signed") }, resolver: resolver, redirected: true, code: ErrorRequestNotSupported},
		{name: "request URI", mutate: func(v url.Values) { v.Set("request_uri", "https://attacker.example/request") }, resolver: resolver, redirected: true, code: ErrorRequestURINotSupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := cloneValues(base)
			test.mutate(values)
			raw := values.Encode()
			if test.name == "malformed percent encoding" {
				raw = "%ZZ"
			}
			_, err := ParseAuthorizationRequest(context.Background(), raw, test.resolver)
			var protocolError *AuthorizationError
			if !errors.As(err, &protocolError) || protocolError.Code != test.code || protocolError.SafeToRedirect != test.redirected {
				t.Fatalf("error=%#v, want code=%s redirected=%v", err, test.code, test.redirected)
			}
			if !test.redirected && (protocolError.RedirectURI != "" || protocolError.State != "") {
				t.Fatalf("untrusted error retained redirect data: %+v", protocolError)
			}
			if test.name == "duplicate state" && protocolError.State != "" {
				t.Fatalf("duplicate state was reflected: %+v", protocolError)
			}
		})
	}
}

func TestAuthorizationParameterNegativeMatrix(t *testing.T) {
	t.Parallel()

	resolver, base := validAuthorizeFixture()
	tests := []struct {
		name         string
		mutate       func(url.Values)
		clientScopes []string
		code         ErrorCode
	}{
		{name: "missing openid", mutate: func(v url.Values) { v.Set("scope", "profile") }, code: ErrorInvalidScope},
		{name: "offline access", mutate: func(v url.Values) { v.Set("scope", "openid offline_access") }, code: ErrorInvalidScope},
		{name: "client disallowed scope", mutate: func(v url.Values) { v.Set("scope", "openid email") }, clientScopes: []string{"openid"}, code: ErrorInvalidScope},
		{name: "plain PKCE", mutate: func(v url.Values) { v.Set("code_challenge_method", "plain") }, code: ErrorInvalidRequest},
		{name: "padded challenge", mutate: func(v url.Values) { v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=") }, code: ErrorInvalidRequest},
		{name: "short challenge", mutate: func(v url.Values) { v.Set("code_challenge", "short") }, code: ErrorInvalidRequest},
		{name: "fragment mode", mutate: func(v url.Values) { v.Set("response_mode", "fragment") }, code: ErrorUnsupportedResponseMode},
		{name: "none plus login", mutate: func(v url.Values) { v.Set("prompt", "none login") }, code: ErrorInvalidRequest},
		{name: "create plus login", mutate: func(v url.Values) { v.Set("prompt", "create login") }, code: ErrorInvalidRequest},
		{name: "duplicate prompt", mutate: func(v url.Values) { v.Set("prompt", "consent consent") }, code: ErrorInvalidRequest},
		{name: "unknown prompt", mutate: func(v url.Values) { v.Set("prompt", "select_account") }, code: ErrorInvalidRequest},
		{name: "leading zero max age", mutate: func(v url.Values) { v.Set("max_age", "01") }, code: ErrorInvalidRequest},
		{name: "signed max age", mutate: func(v url.Values) { v.Set("max_age", "+1") }, code: ErrorInvalidRequest},
		{name: "max age too large", mutate: func(v url.Values) { v.Set("max_age", "2592001") }, code: ErrorInvalidRequest},
		{name: "empty state", mutate: func(v url.Values) { v.Set("state", "") }, code: ErrorInvalidRequest},
		{name: "oversized nonce", mutate: func(v url.Values) { v.Set("nonce", strings.Repeat("n", 1025)) }, code: ErrorInvalidRequest},
		{name: "duplicate code challenge", mutate: func(v url.Values) { v.Add("code_challenge", v.Get("code_challenge")) }, code: ErrorInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := cloneValues(base)
			test.mutate(values)
			localResolver := resolver
			if test.clientScopes != nil {
				localResolver.client.Scopes = append([]string(nil), test.clientScopes...)
			}
			_, err := ParseAuthorizationRequest(context.Background(), values.Encode(), localResolver)
			var protocolError *AuthorizationError
			if !errors.As(err, &protocolError) || protocolError.Code != test.code || !protocolError.SafeToRedirect {
				t.Fatalf("error=%#v, want redirected %s", err, test.code)
			}
		})
	}
}

func TestBuildAuthorizationRedirectMergesWithoutInjection(t *testing.T) {
	t.Parallel()

	registered := "https://rp.example.test/callback?tenant=fixed&code=old&state=old#error"
	if _, err := BuildAuthorizationRedirect(registered, url.Values{"code": {"new"}}); err == nil {
		t.Fatal("fragment-bearing redirect accepted")
	}
	registered = "https://rp.example.test/callback?tenant=fixed&code=old&state=old"
	state := "line1\r\nLocation: https://evil.example"
	location, err := BuildAuthorizationRedirect(registered, url.Values{"code": {"c1_value"}, "state": {state}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "rp.example.test" || parsed.Query().Get("tenant") != "fixed" || parsed.Query().Get("code") != "c1_value" || parsed.Query().Get("state") != state {
		t.Fatalf("unexpected redirect %q", location)
	}
	if strings.Contains(location, "\r") || strings.Contains(location, "\n") || strings.Contains(location, "evil.example#") {
		t.Fatalf("redirect contains raw header/fragment injection: %q", location)
	}
}

func TestBuildAuthorizationErrorRedirectOnlyUsesTrustedState(t *testing.T) {
	t.Parallel()

	location, err := BuildAuthorizationErrorRedirect(&AuthorizationError{
		Code: ErrorLoginRequired, SafeToRedirect: true,
		RedirectURI: "https://rp.example.test/callback?tenant=fixed", State: "exact state",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(location)
	if parsed.Query().Get("error") != "login_required" || parsed.Query().Get("state") != "exact state" || parsed.Query().Get("tenant") != "fixed" {
		t.Fatalf("unexpected error redirect: %s", location)
	}
	if _, err := BuildAuthorizationErrorRedirect(&AuthorizationError{Code: ErrorLoginRequired, RedirectURI: "https://evil.example"}); err == nil {
		t.Fatal("untrusted error redirect accepted")
	}
}

func TestBuildAuthorizationSuccessRedirectRequiresOpaqueCode(t *testing.T) {
	t.Parallel()
	location, err := BuildAuthorizationSuccessRedirect("https://rp.example/cb?tenant=fixed&error=old", "c1_opaque", "state")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(location)
	if parsed.Query().Get("code") != "c1_opaque" || parsed.Query().Get("state") != "state" || parsed.Query().Get("tenant") != "fixed" || parsed.Query().Has("error") {
		t.Fatalf("unexpected success redirect: %s", location)
	}
	for _, code := range []string{"", "value\r\nLocation:https://evil.example", "has space"} {
		if _, err := BuildAuthorizationSuccessRedirect("https://rp.example/cb", code, ""); err == nil {
			t.Errorf("unsafe code %q accepted", code)
		}
	}
}

func cloneValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = append([]string(nil), entries...)
	}
	return clone
}
