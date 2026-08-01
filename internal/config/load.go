package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIssuer          = "http://localhost:8080"
	defaultMaxHeaderBytes  = 1 << 20
	maxShutdownTimeout     = 5 * time.Minute
	maxHTTPTimeout         = 10 * time.Minute
	maxHeaderBytes         = 16 << 20
	maxDatabaseConnections = 100
	maxSessionTTL          = 30 * 24 * time.Hour
	maxCSRFTTL             = time.Hour
	maxAuthTransactionTTL  = time.Hour
)

var cookieNamePattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

// Scope selects the configuration required by a command.
type Scope uint8

const (
	// ScopeService validates every setting needed by serve and config check.
	ScopeService Scope = iota
	// ScopeDatabase validates only settings used by migration commands.
	ScopeDatabase
	// ScopeBootstrap validates the database and password-security subset needed
	// by the interactive first-admin command.
	ScopeBootstrap
)

// LookupEnv is injectable so tests and embedding callers do not mutate global
// process state.
type LookupEnv func(string) (string, bool)

// Load reads configuration from the process environment.
func Load(scope Scope) (Config, error) {
	return LoadFrom(os.LookupEnv, scope)
}

// LoadFrom reads configuration through lookup and reports every discoverable
// validation problem in a single error.
func LoadFrom(lookup LookupEnv, scope Scope) (Config, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}

	cfg := defaults()
	problems := make([]Problem, 0)

	databaseURL, databaseURLSet := lookup("ONEISSUER_DATABASE_URL")
	if !databaseURLSet || strings.TrimSpace(databaseURL) == "" {
		problems = append(problems, Problem{"ONEISSUER_DATABASE_URL", "is required"})
	} else if err := validateDatabaseURL(databaseURL); err != nil {
		problems = append(problems, Problem{"ONEISSUER_DATABASE_URL", err.Error()})
	} else {
		cfg.Database.URL = newSecretURL(databaseURL)
	}

	parseInt32(lookup, "ONEISSUER_DATABASE_MAX_CONNS", cfg.Database.MaxConns, 1, maxDatabaseConnections, &cfg.Database.MaxConns, &problems)

	if scope == ScopeDatabase {
		if len(problems) > 0 {
			return Config{}, &ValidationError{Problems: problems}
		}
		return cfg, nil
	}

	environmentRaw, _ := valueOrDefault(lookup, "ONEISSUER_ENV", string(cfg.Environment))
	switch Environment(environmentRaw) {
	case EnvironmentDevelopment, EnvironmentTest, EnvironmentProduction:
		cfg.Environment = Environment(environmentRaw)
	default:
		problems = append(problems, Problem{"ONEISSUER_ENV", "must be one of development, test, production"})
	}
	parsePasswordConfig(lookup, &cfg, &problems)
	if cfg.Environment == EnvironmentProduction && databaseURLSet && databaseDisablesTLS(databaseURL) {
		problems = append(problems, Problem{"ONEISSUER_DATABASE_URL", "must not disable TLS in production"})
	}
	if scope == ScopeBootstrap {
		if len(problems) > 0 {
			return Config{}, &ValidationError{Problems: problems}
		}
		return cfg, nil
	}

	issuerRaw, issuerSet := valueOrDefault(lookup, "ONEISSUER_ISSUER", defaultIssuer)
	issuer, err := validateIssuer(issuerRaw)
	if err != nil {
		problems = append(problems, Problem{"ONEISSUER_ISSUER", err.Error()})
	} else {
		cfg.Issuer = issuer
	}
	if cfg.Environment == EnvironmentProduction {
		if !issuerSet {
			problems = append(problems, Problem{"ONEISSUER_ISSUER", "must be explicitly set in production"})
		} else if issuer != nil && issuer.Scheme != "https" {
			problems = append(problems, Problem{"ONEISSUER_ISSUER", "must use https in production"})
		}
	}

	httpAddr, _ := valueOrDefault(lookup, "ONEISSUER_HTTP_ADDR", cfg.HTTP.Addr)
	if err := validateHTTPAddr(httpAddr); err != nil {
		problems = append(problems, Problem{"ONEISSUER_HTTP_ADDR", err.Error()})
	} else {
		cfg.HTTP.Addr = httpAddr
	}

	parseLogLevel(lookup, &cfg, &problems)
	parseLogFormat(lookup, &cfg, &problems)
	parseDuration(lookup, "ONEISSUER_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout, maxShutdownTimeout, &cfg.ShutdownTimeout, &problems)
	parseDuration(lookup, "ONEISSUER_HTTP_READ_HEADER_TIMEOUT", cfg.HTTP.ReadHeaderTimeout, maxHTTPTimeout, &cfg.HTTP.ReadHeaderTimeout, &problems)
	parseDuration(lookup, "ONEISSUER_HTTP_READ_TIMEOUT", cfg.HTTP.ReadTimeout, maxHTTPTimeout, &cfg.HTTP.ReadTimeout, &problems)
	parseDuration(lookup, "ONEISSUER_HTTP_WRITE_TIMEOUT", cfg.HTTP.WriteTimeout, maxHTTPTimeout, &cfg.HTTP.WriteTimeout, &problems)
	parseDuration(lookup, "ONEISSUER_HTTP_IDLE_TIMEOUT", cfg.HTTP.IdleTimeout, maxHTTPTimeout, &cfg.HTTP.IdleTimeout, &problems)

	maxHeaders := int32(defaultMaxHeaderBytes)
	parseInt32(lookup, "ONEISSUER_HTTP_MAX_HEADER_BYTES", maxHeaders, 1, maxHeaderBytes, &maxHeaders, &problems)
	cfg.HTTP.MaxHeaderBytes = int(maxHeaders)

	parseTrustedProxies(lookup, &cfg, &problems)
	parseBrowserConfig(lookup, &cfg, &problems)

	if len(problems) > 0 {
		return Config{}, &ValidationError{Problems: problems}
	}
	return cfg, nil
}

func defaults() Config {
	issuer, _ := url.Parse(defaultIssuer)
	return Config{
		Environment: EnvironmentDevelopment,
		Issuer:      issuer,
		HTTP: HTTPConfig{
			Addr:              ":8080",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    defaultMaxHeaderBytes,
		},
		Database: DatabaseConfig{MaxConns: 10},
		Log: LogConfig{
			Level:  LogLevelInfo,
			Format: LogFormatJSON,
		},
		Browser: BrowserConfig{
			CookieName:          "oneissuer_session",
			CookieSecure:        false,
			SessionTTL:          24 * time.Hour,
			SessionIdleTimeout:  2 * time.Hour,
			CSRFTTL:             15 * time.Minute,
			AuthTransactionTTL:  10 * time.Minute,
			LoginReauthWindow:   15 * time.Minute,
			CleanupInterval:     5 * time.Minute,
			RegistrationEnabled: false,
		},
		Password: PasswordConfig{
			MinLength:       15,
			MaxBytes:        1024,
			Argon2MemoryKiB: 64 * 1024,
			Argon2Time:      3,
			Argon2Threads:   2,
			MaxConcurrent:   2,
		},
		ShutdownTimeout: 15 * time.Second,
		TrustedProxies:  []netip.Prefix{},
	}
}

func valueOrDefault(lookup LookupEnv, name, fallback string) (string, bool) {
	value, ok := lookup(name)
	if !ok {
		return fallback, false
	}
	return value, true
}

func validateIssuer(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return nil, fmt.Errorf("must be an absolute http or https URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("must use the http or https scheme")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("must not contain a query or fragment")
	}
	return parsed, nil
}

func validateHTTPAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be a valid TCP listen address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("must contain a port between 1 and 65535")
	}
	return nil
}

func validateDatabaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("must be a valid PostgreSQL URL with a host")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("must use the postgres or postgresql scheme")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return fmt.Errorf("must select a database")
	}
	return nil
}

func databaseDisablesTLS(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Query().Get("sslmode"), "disable")
}

func parseLogLevel(lookup LookupEnv, cfg *Config, problems *[]Problem) {
	raw, _ := valueOrDefault(lookup, "ONEISSUER_LOG_LEVEL", string(cfg.Log.Level))
	switch LogLevel(raw) {
	case LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError:
		cfg.Log.Level = LogLevel(raw)
	default:
		*problems = append(*problems, Problem{"ONEISSUER_LOG_LEVEL", "must be one of debug, info, warn, error"})
	}
}

func parseLogFormat(lookup LookupEnv, cfg *Config, problems *[]Problem) {
	raw, _ := valueOrDefault(lookup, "ONEISSUER_LOG_FORMAT", string(cfg.Log.Format))
	switch LogFormat(raw) {
	case LogFormatJSON, LogFormatText:
		cfg.Log.Format = LogFormat(raw)
	default:
		*problems = append(*problems, Problem{"ONEISSUER_LOG_FORMAT", "must be one of json, text"})
	}
}

func parseDuration(lookup LookupEnv, name string, fallback, maximum time.Duration, target *time.Duration, problems *[]Problem) {
	raw, set := lookup(name)
	if !set {
		*target = fallback
		return
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		*problems = append(*problems, Problem{name, "must be a positive duration"})
		return
	}
	if value > maximum {
		*problems = append(*problems, Problem{name, fmt.Sprintf("must not exceed %s", maximum)})
		return
	}
	*target = value
}

func parseInt32(lookup LookupEnv, name string, fallback, minimum, maximum int32, target *int32, problems *[]Problem) {
	raw, set := lookup(name)
	if !set {
		*target = fallback
		return
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || value < int64(minimum) || value > int64(maximum) {
		*problems = append(*problems, Problem{name, fmt.Sprintf("must be an integer between %d and %d", minimum, maximum)})
		return
	}
	*target = int32(value)
}

func parseBool(lookup LookupEnv, name string, fallback bool, target *bool, problems *[]Problem) bool {
	raw, set := lookup(name)
	if !set {
		*target = fallback
		return false
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		*problems = append(*problems, Problem{name, "must be true or false"})
		return true
	}
	*target = value
	return true
}

func parseInt(lookup LookupEnv, name string, fallback, minimum, maximum int, target *int, problems *[]Problem) {
	raw, set := lookup(name)
	if !set {
		*target = fallback
		return
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		*problems = append(*problems, Problem{name, fmt.Sprintf("must be an integer between %d and %d", minimum, maximum)})
		return
	}
	*target = value
}

func parseUint32(lookup LookupEnv, name string, fallback, minimum, maximum uint32, target *uint32, problems *[]Problem) {
	raw, set := lookup(name)
	if !set {
		*target = fallback
		return
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value < uint64(minimum) || value > uint64(maximum) {
		*problems = append(*problems, Problem{name, fmt.Sprintf("must be an integer between %d and %d", minimum, maximum)})
		return
	}
	// #nosec G115 -- ParseUint's bit size and the explicit bounds prove this conversion safe.
	*target = uint32(value)
}

func parseUint8(lookup LookupEnv, name string, fallback, minimum, maximum uint8, target *uint8, problems *[]Problem) {
	raw, set := lookup(name)
	if !set {
		*target = fallback
		return
	}
	value, err := strconv.ParseUint(raw, 10, 8)
	if err != nil || value < uint64(minimum) || value > uint64(maximum) {
		*problems = append(*problems, Problem{name, fmt.Sprintf("must be an integer between %d and %d", minimum, maximum)})
		return
	}
	// #nosec G115 -- ParseUint's bit size and the explicit bounds prove this conversion safe.
	*target = uint8(value)
}

func parsePasswordConfig(lookup LookupEnv, cfg *Config, problems *[]Problem) {
	parseInt(lookup, "ONEISSUER_PASSWORD_MIN_LENGTH", cfg.Password.MinLength, 15, 128, &cfg.Password.MinLength, problems)
	parseInt(lookup, "ONEISSUER_PASSWORD_MAX_BYTES", cfg.Password.MaxBytes, 64, 4096, &cfg.Password.MaxBytes, problems)
	if cfg.Password.MaxBytes < cfg.Password.MinLength {
		*problems = append(*problems, Problem{"ONEISSUER_PASSWORD_MAX_BYTES", "must be at least the configured minimum password length"})
	}

	parseUint32(lookup, "ONEISSUER_ARGON2_MEMORY_KIB", cfg.Password.Argon2MemoryKiB, 19*1024, 1024*1024, &cfg.Password.Argon2MemoryKiB, problems)
	parseUint32(lookup, "ONEISSUER_ARGON2_TIME", cfg.Password.Argon2Time, 2, 10, &cfg.Password.Argon2Time, problems)
	parseUint8(lookup, "ONEISSUER_ARGON2_THREADS", cfg.Password.Argon2Threads, 1, 16, &cfg.Password.Argon2Threads, problems)
	parseInt(lookup, "ONEISSUER_ARGON2_MAX_CONCURRENT", cfg.Password.MaxConcurrent, 1, 64, &cfg.Password.MaxConcurrent, problems)
}

func parseBrowserConfig(lookup LookupEnv, cfg *Config, problems *[]Problem) {
	cookieName, _ := valueOrDefault(lookup, "ONEISSUER_COOKIE_NAME", cfg.Browser.CookieName)
	if !cookieNamePattern.MatchString(cookieName) {
		*problems = append(*problems, Problem{"ONEISSUER_COOKIE_NAME", "must be a valid cookie name"})
	} else {
		cfg.Browser.CookieName = cookieName
	}
	parseBool(lookup, "ONEISSUER_COOKIE_SECURE", cfg.Browser.CookieSecure, &cfg.Browser.CookieSecure, problems)
	parseDuration(lookup, "ONEISSUER_SESSION_TTL", cfg.Browser.SessionTTL, maxSessionTTL, &cfg.Browser.SessionTTL, problems)
	parseDuration(lookup, "ONEISSUER_SESSION_IDLE_TIMEOUT", cfg.Browser.SessionIdleTimeout, maxSessionTTL, &cfg.Browser.SessionIdleTimeout, problems)
	parseDuration(lookup, "ONEISSUER_CSRF_TTL", cfg.Browser.CSRFTTL, maxCSRFTTL, &cfg.Browser.CSRFTTL, problems)
	parseDuration(lookup, "ONEISSUER_AUTH_TRANSACTION_TTL", cfg.Browser.AuthTransactionTTL, maxAuthTransactionTTL, &cfg.Browser.AuthTransactionTTL, problems)
	parseDuration(lookup, "ONEISSUER_LOGIN_REAUTH_WINDOW", cfg.Browser.LoginReauthWindow, 24*time.Hour, &cfg.Browser.LoginReauthWindow, problems)
	parseDuration(lookup, "ONEISSUER_CLEANUP_INTERVAL", cfg.Browser.CleanupInterval, time.Hour, &cfg.Browser.CleanupInterval, problems)
	registrationSet := parseBool(lookup, "ONEISSUER_REGISTRATION_ENABLED", cfg.Browser.RegistrationEnabled, &cfg.Browser.RegistrationEnabled, problems)

	if cfg.Browser.SessionIdleTimeout > cfg.Browser.SessionTTL {
		*problems = append(*problems, Problem{"ONEISSUER_SESSION_IDLE_TIMEOUT", "must not exceed ONEISSUER_SESSION_TTL"})
	}
	if cfg.Environment == EnvironmentProduction {
		if !cfg.Browser.CookieSecure {
			*problems = append(*problems, Problem{"ONEISSUER_COOKIE_SECURE", "must be true in production"})
		}
		if !strings.HasPrefix(cfg.Browser.CookieName, "__Host-") {
			*problems = append(*problems, Problem{"ONEISSUER_COOKIE_NAME", "must use the __Host- prefix in production"})
		}
		if !registrationSet {
			*problems = append(*problems, Problem{"ONEISSUER_REGISTRATION_ENABLED", "must be explicitly set in production"})
		}
	}
}

func parseTrustedProxies(lookup LookupEnv, cfg *Config, problems *[]Problem) {
	raw, set := lookup("ONEISSUER_TRUSTED_PROXIES")
	if !set || strings.TrimSpace(raw) == "" {
		cfg.TrustedProxies = []netip.Prefix{}
		return
	}

	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	invalid := false
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			invalid = true
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if invalid {
		*problems = append(*problems, Problem{"ONEISSUER_TRUSTED_PROXIES", "must be a comma-separated list of CIDR prefixes"})
		return
	}
	cfg.TrustedProxies = prefixes
}
