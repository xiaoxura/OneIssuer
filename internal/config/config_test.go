package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const validDatabaseURL = "postgres://oneissuer:super-secret@localhost:5432/oneissuer?sslmode=disable"

func env(values map[string]string) LookupEnv {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{"ONEISSUER_DATABASE_URL": validDatabaseURL}), ScopeService)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Environment != EnvironmentDevelopment || cfg.Issuer.String() != defaultIssuer {
		t.Fatalf("unexpected defaults: %#v", cfg.SafeMap())
	}
	if cfg.HTTP.Addr != ":8080" || cfg.HTTP.ReadHeaderTimeout != 5*time.Second || cfg.HTTP.MaxHeaderBytes != 1<<20 {
		t.Fatalf("unexpected HTTP defaults: %#v", cfg.HTTP)
	}
	if cfg.Database.MaxConns != 10 || cfg.Log.Level != LogLevelInfo || cfg.Log.Format != LogFormatJSON {
		t.Fatalf("unexpected database/log defaults: %#v", cfg.SafeMap())
	}
	if cfg.Browser.CookieName != "oneissuer_session" || cfg.Browser.SessionTTL != 24*time.Hour || cfg.Browser.RegistrationEnabled {
		t.Fatalf("unexpected browser defaults: %#v", cfg.Browser)
	}
	if cfg.Password.MinLength != 15 || cfg.Password.MaxBytes < 64 || cfg.Password.Argon2MemoryKiB < 19*1024 {
		t.Fatalf("unexpected password defaults: %#v", cfg.Password)
	}
}

func TestLoadValidOverrides(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_ENV":                      "test",
		"ONEISSUER_ISSUER":                   "https://id.example.test/base",
		"ONEISSUER_HTTP_ADDR":                "127.0.0.1:9090",
		"ONEISSUER_DATABASE_URL":             "postgresql://user:pass@db.example.test/app?sslmode=require",
		"ONEISSUER_LOG_LEVEL":                "debug",
		"ONEISSUER_LOG_FORMAT":               "text",
		"ONEISSUER_SHUTDOWN_TIMEOUT":         "20s",
		"ONEISSUER_HTTP_READ_HEADER_TIMEOUT": "2s",
		"ONEISSUER_HTTP_READ_TIMEOUT":        "3s",
		"ONEISSUER_HTTP_WRITE_TIMEOUT":       "4s",
		"ONEISSUER_HTTP_IDLE_TIMEOUT":        "5s",
		"ONEISSUER_HTTP_MAX_HEADER_BYTES":    "2048",
		"ONEISSUER_DATABASE_MAX_CONNS":       "20",
		"ONEISSUER_TRUSTED_PROXIES":          "10.0.0.1/8, 2001:db8::/32",
	}), ScopeService)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Environment != EnvironmentTest || cfg.HTTP.Addr != "127.0.0.1:9090" || cfg.Database.MaxConns != 20 {
		t.Fatalf("overrides were not applied: %#v", cfg.SafeMap())
	}
	if got := fmt.Sprint(cfg.TrustedProxies); got != "[10.0.0.0/8 2001:db8::/32]" {
		t.Fatalf("TrustedProxies = %q", got)
	}
}

func TestLoadReportsAllInvalidSettingsWithoutValues(t *testing.T) {
	t.Parallel()

	secret := "never-print-this"
	_, err := LoadFrom(env(map[string]string{
		"ONEISSUER_ENV":                      "staging",
		"ONEISSUER_ISSUER":                   "ftp://user:pass@example.test/path?q=1",
		"ONEISSUER_HTTP_ADDR":                "invalid",
		"ONEISSUER_DATABASE_URL":             "mysql://user:" + secret + "@localhost/app",
		"ONEISSUER_LOG_LEVEL":                "trace",
		"ONEISSUER_LOG_FORMAT":               "xml",
		"ONEISSUER_SHUTDOWN_TIMEOUT":         "0s",
		"ONEISSUER_HTTP_READ_HEADER_TIMEOUT": "forever",
		"ONEISSUER_HTTP_READ_TIMEOUT":        "20m",
		"ONEISSUER_HTTP_WRITE_TIMEOUT":       "-1s",
		"ONEISSUER_HTTP_IDLE_TIMEOUT":        "0",
		"ONEISSUER_HTTP_MAX_HEADER_BYTES":    "0",
		"ONEISSUER_DATABASE_MAX_CONNS":       "1000",
		"ONEISSUER_TRUSTED_PROXIES":          "not-a-cidr",
	}), ScopeService)
	if err == nil {
		t.Fatal("LoadFrom() error = nil")
	}
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error type = %T", err)
	}
	if len(validationError.Problems) != 14 {
		t.Fatalf("problem count = %d, want 14: %v", len(validationError.Problems), err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("validation error leaked a secret")
	}
}

func TestProductionSafetyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values map[string]string
		field  string
	}{
		{
			name: "issuer must be explicit",
			values: map[string]string{
				"ONEISSUER_ENV":          "production",
				"ONEISSUER_DATABASE_URL": "postgres://u:p@db/app?sslmode=require",
			},
			field: "ONEISSUER_ISSUER",
		},
		{
			name: "issuer must use HTTPS",
			values: map[string]string{
				"ONEISSUER_ENV":          "production",
				"ONEISSUER_ISSUER":       "http://id.example.test",
				"ONEISSUER_DATABASE_URL": "postgres://u:p@db/app?sslmode=require",
			},
			field: "must use https",
		},
		{
			name: "database TLS cannot be disabled",
			values: map[string]string{
				"ONEISSUER_ENV":          "production",
				"ONEISSUER_ISSUER":       "https://id.example.test",
				"ONEISSUER_DATABASE_URL": validDatabaseURL,
			},
			field: "must not disable TLS",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(env(test.values), ScopeService)
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("LoadFrom() error = %v, want containing %q", err, test.field)
			}
		})
	}
}

func TestDatabaseScopeIgnoresUnrelatedSettings(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL": "postgres://u:p@db/app?sslmode=disable",
		"ONEISSUER_ENV":          "invalid",
		"ONEISSUER_ISSUER":       "invalid",
		"ONEISSUER_HTTP_ADDR":    "invalid",
	}), ScopeDatabase)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Database.URL.UnsafeValue() == "" {
		t.Fatal("database URL was not loaded")
	}
}

func TestSecretURLIsRedactedEverywhere(t *testing.T) {
	t.Parallel()

	raw := "postgres://alice:p%40ssword@db.example.test/app?sslmode=require&access_token=abc"
	secret := newSecretURL(raw)
	wantFragments := []string{"xxxxx", "alice", "db.example.test"}
	got := secret.String()
	for _, fragment := range wantFragments {
		if !strings.Contains(got, fragment) {
			t.Fatalf("redacted URL %q does not contain %q", got, fragment)
		}
	}
	for _, forbidden := range []string{"p%40ssword", "p@ssword", "abc"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redacted URL leaked %q: %s", forbidden, got)
		}
	}

	jsonValue, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(jsonValue), "ssword") || strings.Contains(string(jsonValue), "abc") {
		t.Fatalf("JSON leaked a secret: %s", jsonValue)
	}
	if slog.AnyValue(secret).Resolve().String() != got {
		t.Fatal("slog representation differs from safe String representation")
	}
}

func TestDatabaseURLIsRequired(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom(env(nil), ScopeService)
	if err == nil || !strings.Contains(err.Error(), "ONEISSUER_DATABASE_URL: is required") {
		t.Fatalf("LoadFrom() error = %v", err)
	}
}

func TestPhaseTwoSecurityConfigurationValidation(t *testing.T) {
	t.Parallel()
	_, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":          validDatabaseURL,
		"ONEISSUER_SESSION_TTL":           "1h",
		"ONEISSUER_SESSION_IDLE_TIMEOUT":  "2h",
		"ONEISSUER_PASSWORD_MIN_LENGTH":   "14",
		"ONEISSUER_PASSWORD_MAX_BYTES":    "32",
		"ONEISSUER_ARGON2_MEMORY_KIB":     "1024",
		"ONEISSUER_ARGON2_TIME":           "1",
		"ONEISSUER_ARGON2_THREADS":        "0",
		"ONEISSUER_ARGON2_MAX_CONCURRENT": "0",
		"ONEISSUER_COOKIE_NAME":           "bad cookie",
		"ONEISSUER_COOKIE_SECURE":         "sometimes",
		"ONEISSUER_REGISTRATION_ENABLED":  "perhaps",
	}), ScopeService)
	if err == nil {
		t.Fatal("unsafe phase-two settings were accepted")
	}
	for _, field := range []string{
		"ONEISSUER_SESSION_IDLE_TIMEOUT", "ONEISSUER_PASSWORD_MIN_LENGTH",
		"ONEISSUER_ARGON2_MEMORY_KIB", "ONEISSUER_COOKIE_NAME", "ONEISSUER_COOKIE_SECURE",
	} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("aggregated error missing %s: %v", field, err)
		}
	}
}

func TestProductionBrowserSafetyRequiresExplicitSecureChoices(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ONEISSUER_ENV":          "production",
		"ONEISSUER_ISSUER":       "https://id.example.test",
		"ONEISSUER_DATABASE_URL": "postgres://u:p@db/app?sslmode=require",
	}
	_, err := LoadFrom(env(base), ScopeService)
	if err == nil || !strings.Contains(err.Error(), "ONEISSUER_COOKIE_SECURE") ||
		!strings.Contains(err.Error(), "__Host-") || !strings.Contains(err.Error(), "ONEISSUER_REGISTRATION_ENABLED") {
		t.Fatalf("production browser validation error=%v", err)
	}
	base["ONEISSUER_COOKIE_SECURE"] = "true"
	base["ONEISSUER_COOKIE_NAME"] = "__Host-oneissuer_session"
	base["ONEISSUER_REGISTRATION_ENABLED"] = "false"
	if _, err := LoadFrom(env(base), ScopeService); err != nil {
		t.Fatalf("safe production browser settings rejected: %v", err)
	}
}

func TestBootstrapScopeIgnoresHTTPButEnforcesPasswordAndDatabaseSafety(t *testing.T) {
	t.Parallel()
	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL": "postgres://u:p@db/app?sslmode=disable",
		"ONEISSUER_HTTP_ADDR":    "invalid",
		"ONEISSUER_ISSUER":       "invalid",
	}), ScopeBootstrap)
	if err != nil || cfg.Password.MinLength != 15 {
		t.Fatalf("bootstrap scope cfg=%+v err=%v", cfg.Password, err)
	}
	_, err = LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":        "postgres://u:p@db/app?sslmode=disable",
		"ONEISSUER_PASSWORD_MIN_LENGTH": "5",
	}), ScopeBootstrap)
	if err == nil || !strings.Contains(err.Error(), "ONEISSUER_PASSWORD_MIN_LENGTH") {
		t.Fatalf("unsafe bootstrap password policy error=%v", err)
	}
}
