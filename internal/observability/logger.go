package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"

	"github.com/oneissuer/oneissuer/internal/config"
)

var (
	databaseCredentialPattern = regexp.MustCompile(`(?i)(postgres(?:ql)?://[^\s:/@]+:)[^\s@]+(@)`)
	bearerTokenPattern        = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/=-]+`)
	oneIssuerOpaquePattern    = regexp.MustCompile(`(^|[^A-Za-z0-9_-])(?:ois_sec_v1_|s1_|p1_|c1_|t1_|r1_|lt1_|lc1_)[A-Za-z0-9_-]{43}([^A-Za-z0-9_-]|$)`)
	argon2DigestPattern       = regexp.MustCompile(`\$argon2id\$[^\s]+`)
)

// NewLogger constructs a synchronous slog logger. JSON is the production
// default; both encoders use stable timestamp/message keys and a final privacy
// filter.
func NewLogger(output io.Writer, cfg config.LogConfig) *slog.Logger {
	if output == nil {
		output = io.Discard
	}

	options := &slog.HandlerOptions{
		Level: parseSlogLevel(cfg.Level),
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey:
				attr.Key = "timestamp"
			case slog.MessageKey:
				attr.Key = "message"
			}
			return attr
		},
	}

	var handler slog.Handler
	if cfg.Format == config.LogFormatText {
		handler = slog.NewTextHandler(output, options)
	} else {
		handler = slog.NewJSONHandler(output, options)
	}
	return slog.New(&redactingHandler{next: handler})
}

// WithProcessFields adds the low-cardinality fields required on process logs.
func WithProcessFields(logger *slog.Logger, build BuildInfo, environment config.Environment) *slog.Logger {
	return logger.With(
		slog.String("version", build.Version),
		slog.String("commit", build.Commit),
		slog.String("environment", string(environment)),
	)
}

func parseSlogLevel(level config.LogLevel) slog.Level {
	switch level {
	case config.LogLevelDebug:
		return slog.LevelDebug
	case config.LogLevelWarn:
		return slog.LevelWarn
	case config.LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type redactingHandler struct {
	next slog.Handler
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	copyRecord := slog.NewRecord(record.Time, record.Level, redactText(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		copyRecord.AddAttrs(redactAttr(attr))
		return true
	})
	return h.next.Handle(ctx, copyRecord)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		redacted = append(redacted, redactAttr(attr))
	}
	return &redactingHandler{next: h.next.WithAttrs(redacted)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{next: h.next.WithGroup(name)}
}

func redactAttr(attr slog.Attr) slog.Attr {
	if attr.Equal(slog.Attr{}) {
		return attr
	}
	if sensitiveKey(attr.Key) {
		return slog.String(attr.Key, "[REDACTED]")
	}

	value := attr.Value.Resolve()
	switch value.Kind() {
	case slog.KindString:
		attr.Value = slog.StringValue(redactText(value.String()))
	case slog.KindAny:
		switch typed := value.Any().(type) {
		case error:
			attr.Value = slog.StringValue(redactText(typed.Error()))
		case fmt.Stringer:
			attr.Value = slog.StringValue(redactText(typed.String()))
		}
	case slog.KindGroup:
		group := value.Group()
		redacted := make([]slog.Attr, 0, len(group))
		for _, child := range group {
			redacted = append(redacted, redactAttr(child))
		}
		attr.Value = slog.GroupValue(redacted...)
	}
	return attr
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	for _, fragment := range []string{
		"password", "passwd", "secret", "token", "credential", "authorization", "cookie", "database_url", "dsn",
		"csrf", "state", "nonce", "pkce", "username", "email", "identifier", "user_agent", "client_ip",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func redactText(value string) string {
	value = databaseCredentialPattern.ReplaceAllString(value, `${1}xxxxx${2}`)
	value = bearerTokenPattern.ReplaceAllString(value, `${1}[REDACTED]`)
	// The boundary matcher consumes separators. Repeating allows adjacent
	// credentials that share a separator to be redacted without losing it.
	for {
		redacted := oneIssuerOpaquePattern.ReplaceAllString(value, `${1}[REDACTED]${2}`)
		if redacted == value {
			break
		}
		value = redacted
	}
	return argon2DigestPattern.ReplaceAllString(value, `[REDACTED]`)
}
