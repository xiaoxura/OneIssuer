package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/oidc"
)

type staticPublicKeySet struct {
	body []byte
	etag string
}

func (s staticPublicKeySet) PublicJWKS() []byte { return append([]byte(nil), s.body...) }
func (s staticPublicKeySet) ETag() string       { return s.etag }

func TestJWKSHandlerPublishesStablePublicBytesAndCachingContract(t *testing.T) {
	t.Parallel()

	const body = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"public-only\"}]}\n"
	const etag = `"public-content-digest"`
	handler := &applicationHandler{publicKeys: staticPublicKeySet{body: []byte(body), etag: etag}}

	request := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != body {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != jwksCacheControl || response.Header().Get("ETag") != etag {
		t.Fatalf("unexpected JWKS headers: %v", response.Header())
	}
}

func TestJWKSHandlerConditionalGETUsesWeakComparisonAndNoBody(t *testing.T) {
	t.Parallel()

	const etag = `"digest"`
	handler := &applicationHandler{publicKeys: staticPublicKeySet{body: []byte("{\"keys\":[]}\n"), etag: etag}}
	for _, condition := range []string{etag, `W/"digest"`, `"other", W/"digest"`, "*"} {
		condition := condition
		t.Run(condition, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
			request.Header.Set("If-None-Match", condition)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
				t.Fatalf("condition=%q status=%d body=%q", condition, response.Code, response.Body.String())
			}
			if response.Header().Get("ETag") != etag || response.Header().Get("Cache-Control") != jwksCacheControl {
				t.Fatalf("condition=%q headers=%v", condition, response.Header())
			}
			if response.Header().Get("Content-Type") != "" {
				t.Fatalf("304 unexpectedly has content type %q", response.Header().Get("Content-Type"))
			}
		})
	}
}

func TestJWKSHandlerMethodAvailabilityAndDiscoveryGate(t *testing.T) {
	t.Parallel()

	handler := &applicationHandler{publicKeys: staticPublicKeySet{body: []byte("{\"keys\":[]}\n"), etag: `"digest"`}}

	post := httptest.NewRequest(http.MethodPost, "/oauth2/jwks", strings.NewReader("ignored"))
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusMethodNotAllowed || postResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST status=%d headers=%v", postResponse.Code, postResponse.Header())
	}

	discovery := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	discoveryResponse := httptest.NewRecorder()
	handler.ServeHTTP(discoveryResponse, discovery)
	if discoveryResponse.Code != http.StatusNotFound {
		t.Fatalf("Discovery was enabled before advertised endpoints: status=%d body=%q", discoveryResponse.Code, discoveryResponse.Body.String())
	}
}

func TestJWKSHandlerFailsClosedWithoutUsablePublicMaterial(t *testing.T) {
	t.Parallel()

	for _, keys := range []staticPublicKeySet{{etag: `"digest"`}, {body: []byte("{\"keys\":[]}")}} {
		handler := &applicationHandler{publicKeys: keys}
		request := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "digest") {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	}
}

func TestDiscoveryIsEnabledOnlyForCompleteRealRouteSet(t *testing.T) {
	t.Parallel()
	handler := completeOIDCTestHandler(t)

	request := httptest.NewRequest(http.MethodGet, "https://attacker.invalid/.well-known/openid-configuration", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != discoveryCacheControl {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	var metadata oidc.ProviderMetadata
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != "https://issuer.example" || metadata.AuthorizationEndpoint != "https://issuer.example"+oidc.AuthorizePath ||
		metadata.TokenEndpoint != "https://issuer.example"+oidc.TokenPath || metadata.UserInfoEndpoint != "https://issuer.example"+oidc.UserInfoPath ||
		metadata.JWKSURI != "https://issuer.example"+oidc.JWKSPath || strings.Contains(response.Body.String(), "attacker.invalid") {
		t.Fatalf("metadata was not derived solely from configured issuer: %+v", metadata)
	}
	for _, forbidden := range []string{"refresh_token", "offline_access", "revocation_endpoint", "introspection_endpoint", "end_session_endpoint", "registration_endpoint"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("Discovery advertised unavailable capability %q: %s", forbidden, response.Body)
		}
	}

	// Every advertised path is actually dispatched. A malformed request may fail,
	// but it must not be an unimplemented 404.
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, oidc.AuthorizePath},
		{http.MethodGet, oidc.TokenPath},
		{http.MethodGet, oidc.UserInfoPath},
		{http.MethodGet, oidc.JWKSPath},
	} {
		request := httptest.NewRequest(route.method, route.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusNotFound {
			t.Fatalf("advertised route %s returned 404: %s", route.path, response.Body)
		}
	}

	post := httptest.NewRequest(http.MethodPost, oidc.DiscoveryPath, nil)
	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusMethodNotAllowed || postResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Discovery POST status=%d headers=%v", postResponse.Code, postResponse.Header())
	}
}

func TestDiscoveryFailsClosedForEachMissingProtocolDependency(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*applicationHandler)
	}{
		{name: "clients", mutate: func(handler *applicationHandler) { handler.clients = nil }},
		{name: "transactions", mutate: func(handler *applicationHandler) { handler.transactions = nil }},
		{name: "consents", mutate: func(handler *applicationHandler) { handler.consents = nil }},
		{name: "authorization", mutate: func(handler *applicationHandler) { handler.authorization = nil }},
		{name: "token clients", mutate: func(handler *applicationHandler) { handler.tokenClients = nil }},
		{name: "tokens", mutate: func(handler *applicationHandler) { handler.tokens = nil }},
		{name: "keys", mutate: func(handler *applicationHandler) { handler.publicKeys = nil }},
		{name: "metadata", mutate: func(handler *applicationHandler) { handler.metadata = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := completeOIDCTestHandler(t)
			test.mutate(handler)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, oidc.DiscoveryPath, nil))
			if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "issuer.example") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
		})
	}
}

func completeOIDCTestHandler(t *testing.T) *applicationHandler {
	t.Helper()
	issuer, err := url.Parse("https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := oidc.BuildProviderMetadata(issuer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := oidc.MarshalProviderMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return &applicationHandler{
		clients: &clientdomain.Service{}, tokenClients: newHTTPTokenResolver(), transactions: &authflow.Service{},
		consents: &consent.Service{}, authorization: &authorization.Service{}, tokens: &fakeProtocolTokens{},
		publicKeys: staticPublicKeySet{body: []byte("{\"keys\":[]}\n"), etag: `"digest"`}, metadata: encoded,
	}
}
