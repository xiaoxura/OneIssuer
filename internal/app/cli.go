package app

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	"golang.org/x/term"
)

const usageText = `OneIssuer engineering-foundation service

Usage:
  oneissuer serve
  oneissuer migrate up
  oneissuer migrate status
  oneissuer migrate version
	oneissuer config check
	oneissuer admin bootstrap --username <name> --email <address> [--password-stdin]
	oneissuer version
`

const (
	exitSuccess  = 0
	exitRuntime  = 1
	exitUsage    = 2
	exitCanceled = 130
	exitConflict = 3
)

// Execute runs the CLI without process-global I/O or environment mutation.
func Execute(
	ctx context.Context,
	args []string,
	lookup config.LookupEnv,
	stdout io.Writer,
	stderr io.Writer,
	build observability.BuildInfo,
) int {
	return ExecuteWithInput(ctx, args, lookup, os.Stdin, stdout, stderr, build)
}

// ExecuteWithInput is the testable CLI entry point. Password input is explicit
// and remains separate from process arguments and configuration.
func ExecuteWithInput(
	ctx context.Context,
	args []string,
	lookup config.LookupEnv,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	build observability.BuildInfo,
) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usageText)
		return exitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, usageText)
		return exitSuccess
	case "version":
		if code, done := parseNoFlags("version", args[1:], stderr); done {
			return code
		}
		_, _ = fmt.Fprintf(stdout, "version=%s\ncommit=%s\nbuild_time=%s\ngo_version=%s\n",
			build.Version, build.Commit, build.BuildTime, build.GoVersion)
		return exitSuccess
	case "config":
		return executeConfig(args[1:], lookup, stdout, stderr)
	case "migrate":
		return executeMigration(ctx, args[1:], lookup, stdout, stderr)
	case "admin":
		return executeAdmin(ctx, args[1:], lookup, stdin, stdout, stderr)
	case "serve":
		if code, done := parseNoFlags("serve", args[1:], stderr); done {
			return code
		}
		cfg, err := config.LoadFrom(lookup, config.ScopeService)
		if err != nil {
			writeCLIError(stderr, err)
			return exitUsage
		}
		logger := observability.WithProcessFields(observability.NewLogger(stderr, cfg.Log), build, cfg.Environment)
		logger.Info("OneIssuer process starting", slog.String("build_time", build.BuildTime), slog.String("go_version", build.GoVersion))
		if err := Serve(ctx, cfg, build, logger); err != nil {
			logger.Error("OneIssuer process stopped with an error", slog.Any("error", err))
			writeCLIError(stderr, err)
			if errors.Is(err, context.Canceled) {
				return exitCanceled
			}
			return exitRuntime
		}
		return exitSuccess
	default:
		_, _ = fmt.Fprintf(stderr, "oneissuer: unknown command %q\n\n%s", args[0], usageText)
		return exitUsage
	}
}

func executeAdmin(ctx context.Context, args []string, lookup config.LookupEnv, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "bootstrap" {
		_, _ = io.WriteString(stderr, "usage: oneissuer admin bootstrap --username <name> --email <address> [--password-stdin]\n")
		return exitUsage
	}
	flags := flag.NewFlagSet("admin bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	username := flags.String("username", "", "administrator username")
	email := flags.String("email", "", "administrator email")
	passwordStdin := flags.Bool("password-stdin", false, "read and confirm password from two stdin lines")
	flags.Usage = func() {
		_, _ = io.WriteString(stderr, "usage: oneissuer admin bootstrap --username <name> --email <address> [--password-stdin]\n")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSuccess
		}
		return exitUsage
	}
	if flags.NArg() != 0 || strings.TrimSpace(*username) == "" || strings.TrimSpace(*email) == "" {
		flags.Usage()
		return exitUsage
	}
	cfg, err := config.LoadFrom(lookup, config.ScopeBootstrap)
	if err != nil {
		writeCLIError(stderr, err)
		return exitUsage
	}
	store, err := postgres.Open(ctx, cfg.Database.URL.UnsafeValue(), cfg.Database.MaxConns)
	if err != nil {
		writeCLIError(stderr, err)
		return exitRuntime
	}
	defer store.Close()
	if err := store.CheckMigrations(ctx); err != nil {
		writeCLIError(stderr, err)
		return exitRuntime
	}
	exists, err := store.HasAdmin(ctx)
	if err != nil {
		writeCLIError(stderr, err)
		return exitRuntime
	}
	if exists {
		recordBootstrapRejected(ctx, store, time.Now().UTC())
		_, _ = io.WriteString(stderr, "oneissuer: administrator already exists\n")
		return exitConflict
	}
	password, err := readBootstrapPassword(stdin, stderr, *passwordStdin, cfg.Password.MaxBytes)
	if err != nil {
		writeCLIError(stderr, err)
		return exitUsage
	}
	identityService, err := identity.NewService(ctx, cfg.Password, nil)
	if err != nil {
		writeCLIError(stderr, errors.New("password service initialization failed"))
		return exitRuntime
	}
	adminService := admin.NewService(store, identityService, nil, 0)
	created, err := adminService.Bootstrap(ctx, identity.CreateInput{
		Username: *username, DisplayName: *username, Email: *email, Password: password,
	}, "", time.Now().UTC())
	if err != nil {
		if errors.Is(err, identity.ErrBootstrapExists) {
			_, _ = io.WriteString(stderr, "oneissuer: administrator already exists\n")
			return exitConflict
		}
		writeCLIError(stderr, err)
		return exitRuntime
	}
	_, _ = fmt.Fprintf(stdout, "status=created\nid=%s\nusername=%s\n", created.ID, created.Username)
	return exitSuccess
}

func readBootstrapPassword(stdin io.Reader, stderr io.Writer, fromStdin bool, maximum int) (string, error) {
	if stdin == nil {
		return "", errors.New("password input is unavailable")
	}
	if fromStdin {
		limited := io.LimitReader(stdin, int64(2*(maximum+2)+1))
		reader := bufio.NewReader(limited)
		first, err := reader.ReadString('\n')
		if err != nil {
			return "", errors.New("password stdin must contain two newline-terminated lines")
		}
		second, err := reader.ReadString('\n')
		if err != nil {
			return "", errors.New("password stdin must contain two newline-terminated lines")
		}
		first = trimSingleLineEnding(first)
		second = trimSingleLineEnding(second)
		if len(first) > maximum || len(second) > maximum || subtle.ConstantTimeCompare([]byte(first), []byte(second)) != 1 {
			return "", errors.New("password confirmation did not match or exceeded the configured limit")
		}
		return first, nil
	}
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("interactive terminal required; use --password-stdin for a controlled non-interactive channel")
	}
	_, _ = io.WriteString(stderr, "Password: ")
	first, err := term.ReadPassword(int(file.Fd()))
	_, _ = io.WriteString(stderr, "\nConfirm password: ")
	if err != nil {
		return "", errors.New("could not read password from terminal")
	}
	second, secondErr := term.ReadPassword(int(file.Fd()))
	_, _ = io.WriteString(stderr, "\n")
	if secondErr != nil || len(first) > maximum || subtle.ConstantTimeCompare(first, second) != 1 {
		return "", errors.New("password confirmation did not match or exceeded the configured limit")
	}
	return string(first), nil
}

func trimSingleLineEnding(value string) string {
	value = strings.TrimSuffix(value, "\n")
	return strings.TrimSuffix(value, "\r")
}

func recordBootstrapRejected(ctx context.Context, store *postgres.Store, now time.Time) {
	event, err := audit.New(audit.AdminBootstrapRejected, audit.ResultRejected, nil, "", nil, "", nil, now)
	if err == nil {
		_ = store.AppendAudit(ctx, event)
	}
}

func executeConfig(args []string, lookup config.LookupEnv, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "check" {
		_, _ = io.WriteString(stderr, "usage: oneissuer config check\n")
		return exitUsage
	}
	cfg, err := config.LoadFrom(lookup, config.ScopeService)
	if err != nil {
		writeCLIError(stderr, err)
		return exitUsage
	}
	result := map[string]any{"status": "ok", "config": cfg.SafeMap()}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		writeCLIError(stderr, errors.New("could not write config-check output"))
		return exitRuntime
	}
	return exitSuccess
}

func executeMigration(ctx context.Context, args []string, lookup config.LookupEnv, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = io.WriteString(stderr, "usage: oneissuer migrate {up|status|version}\n")
		return exitUsage
	}
	command := postgres.MigrationCommand(args[0])
	if command != postgres.MigrationUp && command != postgres.MigrationStatus && command != postgres.MigrationVersion {
		_, _ = io.WriteString(stderr, "usage: oneissuer migrate {up|status|version}\n")
		return exitUsage
	}
	cfg, err := config.LoadFrom(lookup, config.ScopeDatabase)
	if err != nil {
		writeCLIError(stderr, err)
		return exitUsage
	}
	if err := postgres.RunMigrationCommand(ctx, cfg.Database.URL.UnsafeValue(), command, stdout); err != nil {
		writeCLIError(stderr, err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return exitCanceled
		}
		return exitRuntime
	}
	return exitSuccess
}

func parseNoFlags(name string, args []string, stderr io.Writer) (int, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: oneissuer %s\n", name)
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSuccess, true
		}
		return exitUsage, true
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return exitUsage, true
	}
	return exitSuccess, false
}

func writeCLIError(stderr io.Writer, err error) {
	_, _ = fmt.Fprintf(stderr, "oneissuer: %s\n", err.Error())
}
