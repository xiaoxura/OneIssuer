// Package config loads and validates OneIssuer's environment-based
// configuration. It deliberately keeps secrets in types whose default string
// and slog representations are redacted.
package config

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Environment identifies the deployment class.
type Environment string

const (
	// EnvironmentDevelopment enables local-safe defaults.
	EnvironmentDevelopment Environment = "development"
	// EnvironmentTest identifies automated or isolated tests.
	EnvironmentTest Environment = "test"
	// EnvironmentProduction enables production-only safety validation.
	EnvironmentProduction Environment = "production"
)

// LogFormat controls the structured log encoder.
type LogFormat string

const (
	// LogFormatJSON emits one JSON object per log record.
	LogFormatJSON LogFormat = "json"
	// LogFormatText emits developer-friendly key/value text.
	LogFormatText LogFormat = "text"
)

// LogLevel is a validated slog level name.
type LogLevel string

const (
	// LogLevelDebug enables debug and higher-severity records.
	LogLevelDebug LogLevel = "debug"
	// LogLevelInfo enables informational and higher-severity records.
	LogLevelInfo LogLevel = "info"
	// LogLevelWarn enables warning and error records.
	LogLevelWarn LogLevel = "warn"
	// LogLevelError enables only error records.
	LogLevelError LogLevel = "error"
)

// HTTPConfig contains bounded net/http server settings.
type HTTPConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// DatabaseConfig contains PostgreSQL pool settings.
type DatabaseConfig struct {
	URL      SecretURL
	MaxConns int32
}

// LogConfig contains logging settings.
type LogConfig struct {
	Level  LogLevel
	Format LogFormat
}

// BrowserConfig contains security-sensitive browser session and registration
// settings. Clear session/CSRF values are never configuration values.
type BrowserConfig struct {
	CookieName          string
	CookieSecure        bool
	SessionTTL          time.Duration
	SessionIdleTimeout  time.Duration
	CSRFTTL             time.Duration
	AuthTransactionTTL  time.Duration
	LoginReauthWindow   time.Duration
	CleanupInterval     time.Duration
	RegistrationEnabled bool
}

// PasswordConfig freezes the phase-two password policy and Argon2id resource
// envelope. These values are safe to display, but password material is not.
type PasswordConfig struct {
	MinLength       int
	MaxBytes        int
	Argon2MemoryKiB uint32
	Argon2Time      uint32
	Argon2Threads   uint8
	MaxConcurrent   int
}

// Config is the complete service configuration.
type Config struct {
	Environment     Environment
	Issuer          *url.URL
	HTTP            HTTPConfig
	Database        DatabaseConfig
	Log             LogConfig
	Browser         BrowserConfig
	Password        PasswordConfig
	ShutdownTimeout time.Duration
	TrustedProxies  []netip.Prefix
}

// SecretURL stores a URL without exposing its raw value through common
// formatting, JSON, or slog paths. UnsafeValue should only be passed directly
// to a database driver.
type SecretURL struct {
	raw string
}

func newSecretURL(raw string) SecretURL {
	return SecretURL{raw: raw}
}

// UnsafeValue returns the database driver value. Callers must never log it.
func (s SecretURL) UnsafeValue() string {
	return s.raw
}

// String returns a display-safe representation.
func (s SecretURL) String() string {
	return RedactURL(s.raw)
}

// LogValue ensures slog never receives the raw URL.
func (s SecretURL) LogValue() slog.Value {
	return slog.StringValue(s.String())
}

// MarshalJSON ensures accidental config serialization remains safe.
func (s SecretURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// RedactURL masks credentials and secret-like query values in a URL.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "<redacted>"
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		if _, hasPassword := parsed.User.Password(); hasPassword {
			parsed.User = url.UserPassword(username, "xxxxx")
		}
	}

	query := parsed.Query()
	for key := range query {
		if isSecretName(key) {
			query.Set(key, "xxxxx")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func isSecretName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	for _, fragment := range []string{
		"password", "passwd", "secret", "token", "credential", "authorization", "cookie",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

// SafeMap returns all effective configuration values in a form suitable for
// config-check output and diagnostic logging.
func (c Config) SafeMap() map[string]any {
	issuer := ""
	if c.Issuer != nil {
		issuer = c.Issuer.String()
	}

	proxies := make([]string, 0, len(c.TrustedProxies))
	for _, prefix := range c.TrustedProxies {
		proxies = append(proxies, prefix.String())
	}
	sort.Strings(proxies)

	return map[string]any{
		"environment":        c.Environment,
		"issuer":             issuer,
		"http_addr":          c.HTTP.Addr,
		"database_url":       c.Database.URL.String(),
		"database_max_conns": c.Database.MaxConns,
		"log_level":          c.Log.Level,
		"log_format":         c.Log.Format,
		"shutdown_timeout":   c.ShutdownTimeout.String(),
		"browser": map[string]any{
			"cookie_name":          c.Browser.CookieName,
			"cookie_secure":        c.Browser.CookieSecure,
			"session_ttl":          c.Browser.SessionTTL.String(),
			"session_idle_timeout": c.Browser.SessionIdleTimeout.String(),
			"csrf_ttl":             c.Browser.CSRFTTL.String(),
			"auth_transaction_ttl": c.Browser.AuthTransactionTTL.String(),
			"login_reauth_window":  c.Browser.LoginReauthWindow.String(),
			"cleanup_interval":     c.Browser.CleanupInterval.String(),
			"registration_enabled": c.Browser.RegistrationEnabled,
		},
		"password": map[string]any{
			"min_length":            c.Password.MinLength,
			"max_bytes":             c.Password.MaxBytes,
			"argon2_memory_kib":     c.Password.Argon2MemoryKiB,
			"argon2_time":           c.Password.Argon2Time,
			"argon2_threads":        c.Password.Argon2Threads,
			"argon2_max_concurrent": c.Password.MaxConcurrent,
		},
		"http": map[string]any{
			"read_header_timeout": c.HTTP.ReadHeaderTimeout.String(),
			"read_timeout":        c.HTTP.ReadTimeout.String(),
			"write_timeout":       c.HTTP.WriteTimeout.String(),
			"idle_timeout":        c.HTTP.IdleTimeout.String(),
			"max_header_bytes":    c.HTTP.MaxHeaderBytes,
		},
		"trusted_proxies": proxies,
	}
}
