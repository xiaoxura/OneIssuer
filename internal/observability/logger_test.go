package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/config"
)

func TestLoggerUsesStructuredContractAndRedactsSecrets(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := NewLogger(&output, config.LogConfig{Level: config.LogLevelDebug, Format: config.LogFormatJSON})
	logger.Info(
		"request completed with postgres://alice:message-secret@db/app",
		slog.String("request_id", "req_example"),
		slog.String("database_url", "postgres://alice:attribute-secret@db/app"),
		slog.String("authorization", "Bearer token-secret"),
		slog.Any("error", errors.New("dial postgres://alice:error-secret@db/app")),
	)

	line := output.String()
	for _, secret := range []string{"message-secret", "attribute-secret", "token-secret", "error-secret"} {
		if strings.Contains(line, secret) {
			t.Fatalf("log leaked %q: %s", secret, line)
		}
	}

	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("log is not JSON: %v", err)
	}
	for _, key := range []string{"timestamp", "level", "message", "request_id"} {
		if _, exists := decoded[key]; !exists {
			t.Errorf("log key %q is missing: %#v", key, decoded)
		}
	}
	if decoded["database_url"] != "[REDACTED]" || decoded["authorization"] != "[REDACTED]" {
		t.Fatalf("sensitive attributes were not redacted: %#v", decoded)
	}
}

func TestLoggerRedactsPhaseTwoAuthenticationMaterial(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"password":       "phase-two-password-value",
		"session_cookie": "s1_" + strings.Repeat("A", 43),
		"csrf_token":     "c1_" + strings.Repeat("B", 43),
		"client_secret":  "ois_sec_v1_" + strings.Repeat("C", 43),
		"transaction":    "t1_" + strings.Repeat("D", 43),
		"username":       "private-account-name",
		"email":          "private-address@example.invalid",
		"state":          "private-state-value",
		"nonce":          "private-nonce-value",
		"pkce_challenge": "private-pkce-value",
	}
	phc := "$argon2id$v=19$m=65536,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"

	var output bytes.Buffer
	logger := NewLogger(&output, config.LogConfig{Level: config.LogLevelDebug, Format: config.LogFormatJSON})
	attributes := make([]any, 0, len(values)*2)
	for key, value := range values {
		attributes = append(attributes, key, value)
	}
	logger.Info("opaque material "+values["session_cookie"]+" "+values["client_secret"]+" "+phc, attributes...)

	line := output.String()
	for key, value := range values {
		if strings.Contains(line, value) {
			t.Fatalf("log leaked %s", key)
		}
	}
	if strings.Contains(line, phc) || !strings.Contains(line, "[REDACTED]") {
		t.Fatalf("log did not redact phase-two material: %s", line)
	}
}

func TestWithProcessFields(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := WithProcessFields(
		NewLogger(&output, config.LogConfig{Level: config.LogLevelInfo, Format: config.LogFormatJSON}),
		NewBuildInfo("v0.1.0-dev.2", "abc123", "2026-01-01T00:00:00Z"),
		config.EnvironmentTest,
	)
	logger.Info("started")

	for _, fragment := range []string{`"version":"v0.1.0-dev.2"`, `"commit":"abc123"`, `"environment":"test"`} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("process log missing %s: %s", fragment, output.String())
		}
	}
}
