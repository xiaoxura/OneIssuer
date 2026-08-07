package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/oidc"
)

func TestLifecycleHandlersEnforceOwnerAndUniformRevocationBoundary(t *testing.T) {
	t.Parallel()
	resolver := newHTTPTokenResolver()
	service := &fakeProtocolTokens{}
	handler := &applicationHandler{tokenClients: resolver, tokens: service, now: func() time.Time { return httpTokenNow }}

	public := url.Values{"token": {"opaque-public"}, "client_id": {resolver.public.ClientID}}
	publicRequest := httptest.NewRequest(http.MethodPost, oidc.IntrospectionPath, strings.NewReader(public.Encode()))
	publicRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	publicResponse := httptest.NewRecorder()
	handler.handleIntrospection(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusUnauthorized || !strings.Contains(publicResponse.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("public introspection status=%d body=%s", publicResponse.Code, publicResponse.Body)
	}

	credentials := base64.StdEncoding.EncodeToString([]byte(resolver.confidential.ClientID + ":" + resolver.secret))
	confidential := url.Values{"token": {"opaque-confidential"}}
	confidentialRequest := httptest.NewRequest(http.MethodPost, oidc.IntrospectionPath, strings.NewReader(confidential.Encode()))
	confidentialRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	confidentialRequest.Header.Set("Authorization", "Basic "+credentials)
	confidentialResponse := httptest.NewRecorder()
	handler.handleIntrospection(confidentialResponse, confidentialRequest)
	if confidentialResponse.Code != http.StatusOK {
		t.Fatalf("confidential introspection status=%d body=%s", confidentialResponse.Code, confidentialResponse.Body)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(confidentialResponse.Body.Bytes(), &snapshot); err != nil || len(snapshot) != 1 || snapshot["active"] != false {
		t.Fatalf("introspection snapshot=%v err=%v", snapshot, err)
	}

	revocation := url.Values{"token": {"opaque-public"}, "client_id": {resolver.public.ClientID}, "token_type_hint": {"access_token"}}
	revocationRequest := httptest.NewRequest(http.MethodPost, oidc.RevocationPath, strings.NewReader(revocation.Encode()))
	revocationRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revocationResponse := httptest.NewRecorder()
	handler.handleRevocation(revocationResponse, revocationRequest)
	if revocationResponse.Code != http.StatusOK || revocationResponse.Body.Len() != 0 {
		t.Fatalf("revocation status=%d body=%s", revocationResponse.Code, revocationResponse.Body)
	}
}
