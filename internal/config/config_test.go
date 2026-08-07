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
const validSigningKeyFile = "/run/secrets/oneissuer-signing-key.jwk"

func env(values map[string]string) LookupEnv {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":     validDatabaseURL,
		"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
	}), ScopeService)
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
	if cfg.Browser.AuthRatePerMinute != 20 || cfg.Browser.AuthRateBurst != 10 ||
		cfg.Browser.AuthGlobalRate != 50 || cfg.Browser.AuthGlobalBurst != 100 {
		t.Fatalf("unexpected authentication rate defaults: %#v", cfg.Browser)
	}
	if cfg.Password.MinLength != 15 || cfg.Password.MaxBytes < 64 || cfg.Password.Argon2MemoryKiB < 19*1024 {
		t.Fatalf("unexpected password defaults: %#v", cfg.Password)
	}
	if cfg.OIDC.SigningKeyFile != validSigningKeyFile || cfg.OIDC.AuthorizationCodeTTL != time.Minute ||
		cfg.OIDC.IDTokenTTL != 5*time.Minute || cfg.OIDC.AccessTokenTTL != 10*time.Minute || cfg.OIDC.ClockSkew != 30*time.Second {
		t.Fatalf("unexpected OIDC defaults: %#v", cfg.OIDC)
	}
}

func TestLoadValidOverrides(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_ENV":                         "test",
		"ONEISSUER_ISSUER":                      "https://id.example.test:8443",
		"ONEISSUER_HTTP_ADDR":                   "127.0.0.1:9090",
		"ONEISSUER_DATABASE_URL":                "postgresql://user:pass@db.example.test/app?sslmode=require",
		"ONEISSUER_LOG_LEVEL":                   "debug",
		"ONEISSUER_LOG_FORMAT":                  "text",
		"ONEISSUER_SHUTDOWN_TIMEOUT":            "20s",
		"ONEISSUER_HTTP_READ_HEADER_TIMEOUT":    "2s",
		"ONEISSUER_HTTP_READ_TIMEOUT":           "3s",
		"ONEISSUER_HTTP_WRITE_TIMEOUT":          "4s",
		"ONEISSUER_HTTP_IDLE_TIMEOUT":           "5s",
		"ONEISSUER_HTTP_MAX_HEADER_BYTES":       "2048",
		"ONEISSUER_DATABASE_MAX_CONNS":          "20",
		"ONEISSUER_TRUSTED_PROXIES":             "10.0.0.1/8, 2001:db8::/32",
		"ONEISSUER_SIGNING_KEY_FILE":            validSigningKeyFile,
		"ONEISSUER_VERIFICATION_KEYS_FILE":      "/run/secrets/oneissuer-verification-keys.jwks",
		"ONEISSUER_AUTHORIZATION_CODE_TTL":      "2m",
		"ONEISSUER_ID_TOKEN_TTL":                "10m",
		"ONEISSUER_ACCESS_TOKEN_TTL":            "20m",
		"ONEISSUER_OIDC_CLOCK_SKEW":             "0s",
		"ONEISSUER_AUTH_RATE_PER_MINUTE":        "30",
		"ONEISSUER_AUTH_RATE_BURST":             "15",
		"ONEISSUER_AUTH_GLOBAL_RATE_PER_SECOND": "75",
		"ONEISSUER_AUTH_GLOBAL_BURST":           "150",
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
	if cfg.OIDC.AuthorizationCodeTTL != 2*time.Minute || cfg.OIDC.ClockSkew != 0 || cfg.OIDC.VerificationKeysFile == "" {
		t.Fatalf("OIDC overrides were not applied: %#v", cfg.OIDC)
	}
	if cfg.Browser.AuthRatePerMinute != 30 || cfg.Browser.AuthRateBurst != 15 ||
		cfg.Browser.AuthGlobalRate != 75 || cfg.Browser.AuthGlobalBurst != 150 {
		t.Fatalf("authentication rate overrides were not applied: %#v", cfg.Browser)
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
		"ONEISSUER_SIGNING_KEY_FILE":         " bad-key-path ",
		"ONEISSUER_VERIFICATION_KEYS_FILE":   " bad-verification-path ",
		"ONEISSUER_AUTHORIZATION_CODE_TTL":   "10s",
		"ONEISSUER_ID_TOKEN_TTL":             "16m",
		"ONEISSUER_ACCESS_TOKEN_TTL":         "31m",
		"ONEISSUER_OIDC_CLOCK_SKEW":          "3m",
	}), ScopeService)
	if err == nil {
		t.Fatal("LoadFrom() error = nil")
	}
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error type = %T", err)
	}
	if len(validationError.Problems) != 20 {
		t.Fatalf("problem count = %d, want 20: %v", len(validationError.Problems), err)
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
				"ONEISSUER_ENV":              "production",
				"ONEISSUER_DATABASE_URL":     "postgres://u:p@db/app?sslmode=verify-full",
				"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
			},
			field: "ONEISSUER_ISSUER",
		},
		{
			name: "issuer must use HTTPS",
			values: map[string]string{
				"ONEISSUER_ENV":              "production",
				"ONEISSUER_ISSUER":           "http://id.example.test",
				"ONEISSUER_DATABASE_URL":     "postgres://u:p@db/app?sslmode=verify-full",
				"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
			},
			field: "must use https",
		},
		{
			name: "database TLS must verify host",
			values: map[string]string{
				"ONEISSUER_ENV":          "production",
				"ONEISSUER_ISSUER":       "https://id.example.test",
				"ONEISSUER_DATABASE_URL": validDatabaseURL,
			},
			field: "must explicitly use sslmode=verify-full",
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

func TestProductionDatabaseRequiresExactlyOneVerifyFullSSLModeInEveryScope(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"ONEISSUER_ENV":                   "production",
		"ONEISSUER_ISSUER":                "https://id.example.test",
		"ONEISSUER_SIGNING_KEY_FILE":      validSigningKeyFile,
		"ONEISSUER_COOKIE_SECURE":         "true",
		"ONEISSUER_COOKIE_NAME":           "__Host-oneissuer_session",
		"ONEISSUER_REGISTRATION_ENABLED":  "false",
		"ONEISSUER_DATABASE_MAX_CONNS":    "5",
		"ONEISSUER_PASSWORD_MIN_LENGTH":   "15",
		"ONEISSUER_PASSWORD_MAX_BYTES":    "1024",
		"ONEISSUER_ARGON2_MAX_CONCURRENT": "2",
	}
	for _, scope := range []Scope{ScopeService, ScopeDatabase, ScopeBootstrap} {
		scope := scope
		for _, suffix := range []string{
			"", "?sslmode=disable", "?sslmode=allow", "?sslmode=prefer", "?sslmode=require",
			"?sslmode=verify-ca", "?sslmode=verify-full&sslmode=verify-full",
		} {
			suffix := suffix
			t.Run(fmt.Sprintf("scope_%d_%s", scope, strings.TrimPrefix(suffix, "?sslmode=")), func(t *testing.T) {
				t.Parallel()
				values := make(map[string]string, len(base)+1)
				for key, value := range base {
					values[key] = value
				}
				values["ONEISSUER_DATABASE_URL"] = "postgres://u:p@db/app" + suffix
				_, err := LoadFrom(env(values), scope)
				if err == nil || !strings.Contains(err.Error(), "sslmode=verify-full") {
					t.Fatalf("scope %d accepted production database URL suffix %q: %v", scope, suffix, err)
				}
			})
		}
		t.Run(fmt.Sprintf("scope_%d_verify_full", scope), func(t *testing.T) {
			t.Parallel()
			values := make(map[string]string, len(base)+1)
			for key, value := range base {
				values[key] = value
			}
			values["ONEISSUER_DATABASE_URL"] = "postgres://u:p@db/app?sslmode=verify-full"
			if _, err := LoadFrom(env(values), scope); err != nil {
				t.Fatalf("scope %d rejected verify-full production database URL: %v", scope, err)
			}
		})
	}
}

func TestDatabaseScopeIgnoresUnrelatedServiceSettings(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":     "postgres://u:p@db/app?sslmode=disable",
		"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
		"ONEISSUER_ENV":              "test",
		"ONEISSUER_ISSUER":           "invalid",
		"ONEISSUER_HTTP_ADDR":        "invalid",
	}), ScopeDatabase)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Database.URL.UnsafeValue() == "" {
		t.Fatal("database URL was not loaded")
	}
}

func TestDatabaseScopeValidatesEnvironment(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL": validDatabaseURL,
		"ONEISSUER_ENV":          "invalid",
	}), ScopeDatabase)
	if err == nil || !strings.Contains(err.Error(), "ONEISSUER_ENV") {
		t.Fatalf("database scope accepted an invalid environment: %v", err)
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

func TestServiceSigningKeyReferenceIsRequiredButNarrowScopesIgnoreIt(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom(env(map[string]string{"ONEISSUER_DATABASE_URL": validDatabaseURL}), ScopeService)
	if err == nil || !strings.Contains(err.Error(), "ONEISSUER_SIGNING_KEY_FILE: is required") {
		t.Fatalf("service scope missing-key error = %v", err)
	}
	if _, err := LoadFrom(env(map[string]string{"ONEISSUER_DATABASE_URL": validDatabaseURL}), ScopeDatabase); err != nil {
		t.Fatalf("database scope unexpectedly required a key: %v", err)
	}
	if _, err := LoadFrom(env(map[string]string{"ONEISSUER_DATABASE_URL": validDatabaseURL}), ScopeBootstrap); err != nil {
		t.Fatalf("bootstrap scope unexpectedly required a key: %v", err)
	}
}

func TestIssuerMustBeCanonicalOriginAndHTTPMustBeLoopback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer string
		valid  bool
	}{
		{name: "https origin", issuer: "https://id.example.test", valid: true},
		{name: "https explicit port", issuer: "https://id.example.test:8443", valid: true},
		{name: "localhost http", issuer: "http://localhost:8080", valid: true},
		{name: "IPv4 loopback http", issuer: "http://127.0.0.1:8080", valid: true},
		{name: "IPv6 loopback http", issuer: "http://[::1]:8080", valid: true},
		{name: "path", issuer: "https://id.example.test/tenant", valid: false},
		{name: "trailing slash", issuer: "https://id.example.test/", valid: false},
		{name: "empty query", issuer: "https://id.example.test?", valid: false},
		{name: "empty fragment", issuer: "https://id.example.test#", valid: false},
		{name: "userinfo", issuer: "https://user@id.example.test", valid: false},
		{name: "uppercase scheme", issuer: "HTTPS://id.example.test", valid: false},
		{name: "non-loopback http", issuer: "http://id.example.test", valid: false},
		{name: "empty port", issuer: "https://id.example.test:", valid: false},
		{name: "surrounding whitespace", issuer: " https://id.example.test", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(env(map[string]string{
				"ONEISSUER_DATABASE_URL":     validDatabaseURL,
				"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
				"ONEISSUER_ISSUER":           test.issuer,
			}), ScopeService)
			if test.valid && err != nil {
				t.Fatalf("valid issuer rejected: %v", err)
			}
			if !test.valid && (err == nil || !strings.Contains(err.Error(), "ONEISSUER_ISSUER")) {
				t.Fatalf("invalid issuer accepted/error=%v", err)
			}
		})
	}
}

func TestOIDCLifetimeBoundsAndSafeMapDoNotExposePaths(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{name: "code below minimum", field: "ONEISSUER_AUTHORIZATION_CODE_TTL", value: "29s"},
		{name: "code above maximum", field: "ONEISSUER_AUTHORIZATION_CODE_TTL", value: "5m1s"},
		{name: "id below minimum", field: "ONEISSUER_ID_TOKEN_TTL", value: "59s"},
		{name: "id above maximum", field: "ONEISSUER_ID_TOKEN_TTL", value: "15m1s"},
		{name: "access below minimum", field: "ONEISSUER_ACCESS_TOKEN_TTL", value: "59s"},
		{name: "access above maximum", field: "ONEISSUER_ACCESS_TOKEN_TTL", value: "30m1s"},
		{name: "negative skew", field: "ONEISSUER_OIDC_CLOCK_SKEW", value: "-1s"},
		{name: "excessive skew", field: "ONEISSUER_OIDC_CLOCK_SKEW", value: "2m1s"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := map[string]string{
				"ONEISSUER_DATABASE_URL":     validDatabaseURL,
				"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
				test.field:                   test.value,
			}
			_, err := LoadFrom(env(values), ScopeService)
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("out-of-range lifetime error=%v", err)
			}
		})
	}

	const verificationPath = "/private/verification-location.jwks"
	cfg, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":           validDatabaseURL,
		"ONEISSUER_SIGNING_KEY_FILE":       validSigningKeyFile,
		"ONEISSUER_VERIFICATION_KEYS_FILE": verificationPath,
	}), ScopeService)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	encoded, err := json.Marshal(cfg.SafeMap())
	if err != nil {
		t.Fatalf("json.Marshal(SafeMap) error = %v", err)
	}
	if strings.Contains(string(encoded), validSigningKeyFile) || strings.Contains(string(encoded), verificationPath) {
		t.Fatalf("SafeMap leaked a key path: %s", encoded)
	}
}

func TestPhaseTwoSecurityConfigurationValidation(t *testing.T) {
	t.Parallel()
	_, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":          validDatabaseURL,
		"ONEISSUER_SIGNING_KEY_FILE":      validSigningKeyFile,
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

func TestArgon2CombinedMemoryBudgetIsBounded(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom(env(map[string]string{
		"ONEISSUER_DATABASE_URL":          validDatabaseURL,
		"ONEISSUER_SIGNING_KEY_FILE":      validSigningKeyFile,
		"ONEISSUER_ARGON2_MEMORY_KIB":     "1048576",
		"ONEISSUER_ARGON2_MAX_CONCURRENT": "64",
	}), ScopeService)
	if err == nil || !strings.Contains(err.Error(), "combined Argon2 memory budget") {
		t.Fatalf("64 GiB Argon2 concurrency envelope was accepted: %v", err)
	}
}

func TestAuthenticationRateConfigurationBounds(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{name: "per minute zero", field: "ONEISSUER_AUTH_RATE_PER_MINUTE", value: "0"},
		{name: "per minute excessive", field: "ONEISSUER_AUTH_RATE_PER_MINUTE", value: "60001"},
		{name: "burst zero", field: "ONEISSUER_AUTH_RATE_BURST", value: "0"},
		{name: "burst excessive", field: "ONEISSUER_AUTH_RATE_BURST", value: "1001"},
		{name: "global rate zero", field: "ONEISSUER_AUTH_GLOBAL_RATE_PER_SECOND", value: "0"},
		{name: "global rate excessive", field: "ONEISSUER_AUTH_GLOBAL_RATE_PER_SECOND", value: "10001"},
		{name: "global burst zero", field: "ONEISSUER_AUTH_GLOBAL_BURST", value: "0"},
		{name: "global burst excessive", field: "ONEISSUER_AUTH_GLOBAL_BURST", value: "20001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadFrom(env(map[string]string{
				"ONEISSUER_DATABASE_URL":     validDatabaseURL,
				"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
				test.field:                   test.value,
			}), ScopeService)
			if err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("out-of-range authentication rate value was accepted: %v", err)
			}
		})
	}
}

func TestProductionBrowserSafetyRequiresExplicitSecureChoices(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"ONEISSUER_ENV":              "production",
		"ONEISSUER_ISSUER":           "https://id.example.test",
		"ONEISSUER_DATABASE_URL":     "postgres://u:p@db/app?sslmode=verify-full",
		"ONEISSUER_SIGNING_KEY_FILE": validSigningKeyFile,
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
