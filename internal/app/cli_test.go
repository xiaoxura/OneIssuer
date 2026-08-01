package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/keystore"
	"github.com/oneissuer/oneissuer/internal/observability"
)

func TestVersionDoesNotReadConfiguration(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	lookup := func(string) (string, bool) {
		panic("version must not read environment configuration")
	}
	build := observability.NewBuildInfo("v0.1.0-dev.3", "abc123", "2026-08-01T00:00:00Z")
	code := Execute(context.Background(), []string{"version"}, lookup, &stdout, &stderr, build)
	if code != exitSuccess || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, value := range []string{build.Version, build.Commit, build.BuildTime, build.GoVersion} {
		if !strings.Contains(stdout.String(), value) {
			t.Fatalf("version output missing %q: %s", value, stdout.String())
		}
	}
}

func TestConfigCheckRedactsDatabaseURL(t *testing.T) {
	t.Parallel()

	const secret = "do-not-print"
	keyPath := filepath.Join(t.TempDir(), "private-canary-signing-key.jwk")
	if _, err := keystore.Generate(keyPath, 2048, nil); err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	values := map[string]string{
		"ONEISSUER_DATABASE_URL":     "postgres://alice:" + secret + "@localhost/app?sslmode=disable",
		"ONEISSUER_SIGNING_KEY_FILE": keyPath,
	}
	lookup := config.LookupEnv(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"config", "check"}, lookup, &stdout, &stderr, observability.NewBuildInfo("", "", ""))
	if code != exitSuccess || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stdout.String(), keyPath) || !strings.Contains(stdout.String(), "xxxxx") {
		t.Fatalf("unsafe config output: %s", stdout.String())
	}
	var result struct {
		Status   string `json:"status"`
		KeyStore struct {
			Valid         bool   `json:"valid"`
			Algorithm     string `json:"algorithm"`
			ActiveKeyID   string `json:"active_kid"`
			PublishedKeys int    `json:"published_keys"`
		} `json:"key_store"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("config output is not JSON: %v", err)
	}
	if result.Status != "ok" || !result.KeyStore.Valid || result.KeyStore.Algorithm != keystore.Algorithm ||
		result.KeyStore.ActiveKeyID == "" || result.KeyStore.PublishedKeys != 1 {
		t.Fatalf("unexpected config-check key metadata: %+v", result)
	}
}

func TestKeysCommandsAreConfigurationIndependentAndNeverPrintPrivateMaterial(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private-location-canary.jwk")
	publicPath := filepath.Join(directory, "public.jwks")
	lookup := func(string) (string, bool) {
		panic("keys commands must not load environment configuration")
	}
	build := observability.NewBuildInfo("", "", "")

	var generateOut, generateErr bytes.Buffer
	code := Execute(context.Background(), []string{"keys", "generate", "--alg", "RS256", "--out", privatePath}, lookup, &generateOut, &generateErr, build)
	if code != exitSuccess || generateErr.Len() != 0 {
		t.Fatalf("generate code=%d stdout=%q stderr=%q", code, generateOut.String(), generateErr.String())
	}
	if strings.Contains(generateOut.String(), privatePath) || strings.Contains(generateOut.String(), `"d"`) {
		t.Fatalf("generate output leaked private information: %s", generateOut.String())
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("stat generated private key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%#o, want 0600", info.Mode().Perm())
	}

	var publicOut, publicErr bytes.Buffer
	code = Execute(context.Background(), []string{"keys", "public", "--in", privatePath, "--out", publicPath}, lookup, &publicOut, &publicErr, build)
	if code != exitSuccess || publicErr.Len() != 0 {
		t.Fatalf("public code=%d stdout=%q stderr=%q", code, publicOut.String(), publicErr.String())
	}
	publicJSON, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read public JWKS: %v", err)
	}
	for _, privateMember := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(string(publicJSON), privateMember) {
			t.Fatalf("public JWKS contains private member %s: %s", privateMember, publicJSON)
		}
	}
	if strings.Contains(publicOut.String(), privatePath) || strings.Contains(publicOut.String(), publicPath) {
		t.Fatalf("public command output leaked a key path: %s", publicOut.String())
	}

	var overwriteOut, overwriteErr bytes.Buffer
	code = Execute(context.Background(), []string{"keys", "generate", "--alg", "RS256", "--out", privatePath}, lookup, &overwriteOut, &overwriteErr, build)
	if code != exitRuntime || overwriteOut.Len() != 0 || strings.Contains(overwriteErr.String(), privatePath) {
		t.Fatalf("overwrite code=%d stdout=%q stderr=%q", code, overwriteOut.String(), overwriteErr.String())
	}

	var invalidOut, invalidErr bytes.Buffer
	code = Execute(context.Background(), []string{"keys", "generate", "--alg", "HS256", "--out", filepath.Join(directory, "bad.jwk")}, lookup, &invalidOut, &invalidErr, build)
	if code != exitUsage || invalidOut.Len() != 0 {
		t.Fatalf("unsupported algorithm code=%d stdout=%q stderr=%q", code, invalidOut.String(), invalidErr.String())
	}
}

func TestConfigCheckFailsClosedForInvalidKeyWithoutLeakingPath(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "secret-path-canary.jwk")
	if err := os.WriteFile(keyPath, []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	values := map[string]string{
		"ONEISSUER_DATABASE_URL":     "postgres://u:p@localhost/app?sslmode=disable",
		"ONEISSUER_SIGNING_KEY_FILE": keyPath,
	}
	lookup := func(name string) (string, bool) { value, ok := values[name]; return value, ok }
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"config", "check"}, lookup, &stdout, &stderr, observability.NewBuildInfo("", "", ""))
	if code != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "key store validation failed") || strings.Contains(stderr.String(), keyPath) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestUsageAndConfigErrorsHaveExplicitExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown", []string{"unknown"}},
		{"missing database", []string{"config", "check"}},
		{"bad nested migration", []string{"migrate", "down"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), test.args, func(string) (string, bool) { return "", false }, &stdout, &stderr, observability.NewBuildInfo("", "", ""))
			if code != exitUsage || stderr.Len() == 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestBootstrapPasswordInputNeverUsesArguments(t *testing.T) {
	t.Parallel()
	const password = "a-safe-bootstrap-password"
	value, err := readBootstrapPassword(strings.NewReader(password+"\n"+password+"\n"), io.Discard, true, 1024)
	if err != nil || value != password {
		t.Fatalf("readBootstrapPassword() value length=%d err=%v", len(value), err)
	}
	if _, err := readBootstrapPassword(strings.NewReader(password+"\ndifferent-password\n"), io.Discard, true, 1024); err == nil || strings.Contains(err.Error(), password) {
		t.Fatalf("password mismatch error=%v", err)
	}

	var stdout, stderr bytes.Buffer
	code := ExecuteWithInput(context.Background(), []string{
		"admin", "bootstrap", "--username", "admin", "--email", "admin@example.invalid", "--password=" + password,
	}, func(string) (string, bool) { return "", false }, strings.NewReader(""), &stdout, &stderr, observability.NewBuildInfo("", "", ""))
	if code != exitUsage || strings.Contains(stderr.String(), password) || stdout.Len() != 0 {
		t.Fatalf("password argument handling code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
