package oidc

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestProviderMetadataExactPhaseThreeSnapshot(t *testing.T) {
	t.Parallel()

	issuer, err := url.Parse("https://id.example.test:8443")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := BuildProviderMetadata(issuer)
	if err != nil {
		t.Fatalf("BuildProviderMetadata() error = %v", err)
	}
	encoded, err := MarshalProviderMetadata(metadata)
	if err != nil {
		t.Fatalf("MarshalProviderMetadata() error = %v", err)
	}
	const want = `{"issuer":"https://id.example.test:8443","authorization_endpoint":"https://id.example.test:8443/oauth2/authorize","token_endpoint":"https://id.example.test:8443/oauth2/token","userinfo_endpoint":"https://id.example.test:8443/oauth2/userinfo","jwks_uri":"https://id.example.test:8443/oauth2/jwks","response_types_supported":["code"],"response_modes_supported":["query"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["none","client_secret_basic"],"scopes_supported":["openid","profile","email"],"claims_supported":["sub","iss","aud","exp","iat","auth_time","nonce","azp","name","preferred_username","email","email_verified"],"code_challenge_methods_supported":["S256"],"prompt_values_supported":["none","login","consent","create"]}` + "\n"
	if string(encoded) != want {
		t.Fatalf("metadata snapshot mismatch\n got: %s\nwant: %s", encoded, want)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"revocation_endpoint", "introspection_endpoint", "end_session_endpoint",
		"registration_endpoint", "request_parameter_supported", "request_uri_parameter_supported",
	} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("metadata advertised unavailable capability %q", forbidden)
		}
	}
	if strings.Contains(string(encoded), "refresh_token") || strings.Contains(string(encoded), "offline_access") {
		t.Fatalf("metadata advertised phase-four capability: %s", encoded)
	}
}

func TestProviderMetadataRejectsNonOriginIssuer(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://id.example.test/path",
		"https://id.example.test?query=value",
		"https://id.example.test#fragment",
		"ftp://id.example.test",
		"https://user@id.example.test",
		"/relative",
	} {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			issuer, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BuildProviderMetadata(issuer); err == nil {
				t.Fatalf("BuildProviderMetadata(%q) accepted non-origin issuer", raw)
			}
		})
	}
	if _, err := BuildProviderMetadata(nil); err == nil {
		t.Fatal("nil issuer accepted")
	}
}

func TestProviderMetadataDoesNotMutateIssuer(t *testing.T) {
	t.Parallel()

	issuer, _ := url.Parse("https://id.example.test")
	before := *issuer
	metadata, err := BuildProviderMetadata(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*issuer, before) || metadata.Issuer != issuer.String() {
		t.Fatalf("issuer mutated: before=%+v after=%+v", before, *issuer)
	}
}
