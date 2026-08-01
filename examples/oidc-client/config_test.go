package main

import (
	"testing"
)

func TestLoadExampleConfigPublicAndConfidentialProfiles(t *testing.T) {
	setValidExampleEnvironment(t)
	public, err := loadExampleConfig()
	if err != nil {
		t.Fatal(err)
	}
	if public.ClientSecret != "" || expectedAuthMethod(public) != "none" || public.Issuer.String() != "http://localhost:8080" ||
		public.ProviderBackchannel.String() != "http://oneissuer:8080" || public.RedirectURI != "http://127.0.0.1:8081/callback" {
		t.Fatalf("public config=%+v", public)
	}
	t.Setenv("EXAMPLE_CLIENT_SECRET", "confidential-secret-from-runtime")
	confidential, err := loadExampleConfig()
	if err != nil || expectedAuthMethod(confidential) != "client_secret_basic" {
		t.Fatalf("confidential config=%+v err=%v", confidential, err)
	}
}

func TestLoadExampleConfigRejectsUnsafeOriginsRedirectScopesAndCookies(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "issuer path", key: "EXAMPLE_ISSUER", value: "https://issuer.example/path"},
		{name: "remote HTTP issuer", key: "EXAMPLE_ISSUER", value: "http://issuer.example"},
		{name: "backchannel path", key: "EXAMPLE_PROVIDER_BACKCHANNEL", value: "http://oneissuer:8080/path"},
		{name: "redirect query", key: "EXAMPLE_REDIRECT_URI", value: "http://127.0.0.1:8081/callback?x=1"},
		{name: "remote HTTP redirect", key: "EXAMPLE_REDIRECT_URI", value: "http://rp.example/callback"},
		{name: "offline scope", key: "EXAMPLE_SCOPES", value: "openid offline_access"},
		{name: "missing openid", key: "EXAMPLE_SCOPES", value: "profile email"},
		{name: "duplicate scope", key: "EXAMPLE_SCOPES", value: "openid openid"},
		{name: "cookie injection", key: "EXAMPLE_COOKIE_NAME", value: "bad;cookie"},
		{name: "secret newline", key: "EXAMPLE_CLIENT_SECRET", value: "secret\nvalue"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidExampleEnvironment(t)
			t.Setenv(test.key, test.value)
			if _, err := loadExampleConfig(); err == nil {
				t.Fatal("unsafe example configuration was accepted")
			}
		})
	}
}

func setValidExampleEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("EXAMPLE_NAME", "Example A")
	t.Setenv("EXAMPLE_HTTP_ADDR", ":8080")
	t.Setenv("EXAMPLE_ISSUER", "http://localhost:8080")
	t.Setenv("EXAMPLE_PROVIDER_BACKCHANNEL", "http://oneissuer:8080")
	t.Setenv("EXAMPLE_CLIENT_ID", "ois_cli_runtime_value")
	t.Setenv("EXAMPLE_CLIENT_SECRET", "")
	t.Setenv("EXAMPLE_CLIENT_SECRET_FILE", "")
	t.Setenv("EXAMPLE_REDIRECT_URI", "http://127.0.0.1:8081/callback")
	t.Setenv("EXAMPLE_SCOPES", "openid profile email")
	t.Setenv("EXAMPLE_COOKIE_NAME", "example_a_session")
	t.Setenv("EXAMPLE_COOKIE_SECURE", "false")
}
