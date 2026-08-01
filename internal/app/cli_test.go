package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/observability"
)

func TestVersionDoesNotReadConfiguration(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	lookup := func(string) (string, bool) {
		panic("version must not read environment configuration")
	}
	build := observability.NewBuildInfo("v0.1.0-dev.2", "abc123", "2026-08-01T00:00:00Z")
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
	values := map[string]string{
		"ONEISSUER_DATABASE_URL": "postgres://alice:" + secret + "@localhost/app?sslmode=disable",
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
	if strings.Contains(stdout.String(), secret) || !strings.Contains(stdout.String(), "xxxxx") {
		t.Fatalf("unsafe config output: %s", stdout.String())
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
