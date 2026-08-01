package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/moby/moby/client"
	"github.com/oneissuer/oneissuer/internal/httpserver"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	productionmigrations "github.com/oneissuer/oneissuer/migrations"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgresIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL integration test in short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	// The bound includes a first-run image pull on a clean developer/CI host.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	container, databaseURL := startPostgres(ctx, t)
	defer func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer terminateCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(terminateCtx)); err != nil {
			t.Errorf("terminate PostgreSQL container: %v", err)
		}
	}()

	store, err := postgres.Open(ctx, databaseURL, 4)
	if err != nil {
		t.Fatalf("postgres.Open() error = %v", err)
	}
	defer store.Close()
	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Store.Ping() error = %v", err)
	}
	if stats := store.Stats(); stats.Max != 4 || stats.Total < 1 {
		t.Fatalf("unexpected pool stats: %#v", stats)
	}

	t.Run("wrong credentials are safely classified", func(t *testing.T) {
		invalidURL, parseErr := url.Parse(databaseURL)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		invalidURL.User = url.UserPassword("oneissuer", "wrong-password-never-print")
		connectCtx, connectCancel := context.WithTimeout(ctx, 5*time.Second)
		defer connectCancel()
		_, openErr := postgres.Open(connectCtx, invalidURL.String(), 1)
		if openErr == nil {
			t.Fatal("postgres.Open() with bad password succeeded")
		}
		if postgres.ErrorClass(openErr) != string(postgres.ErrorKindAuth) {
			t.Fatalf("bad password class = %q, error = %v", postgres.ErrorClass(openErr), openErr)
		}
		if strings.Contains(openErr.Error(), "wrong-password") || strings.Contains(openErr.Error(), databaseURL) {
			t.Fatalf("database error leaked credentials: %v", openErr)
		}
	})

	t.Run("production migration initialization is explicit and idempotent", func(t *testing.T) {
		if checkErr := store.CheckMigrations(ctx); checkErr == nil || !strings.Contains(checkErr.Error(), "migrate up") {
			t.Fatalf("CheckMigrations() before up = %v", checkErr)
		}
		var output bytes.Buffer
		if migrationErr := postgres.RunMigrationCommand(ctx, databaseURL, postgres.MigrationUp, &output); migrationErr != nil {
			t.Fatalf("first migration up error = %v", migrationErr)
		}
		if migrationErr := postgres.RunMigrationCommand(ctx, databaseURL, postgres.MigrationUp, io.Discard); migrationErr != nil {
			t.Fatalf("second migration up error = %v", migrationErr)
		}
		if !strings.Contains(output.String(), "version 10") {
			t.Fatalf("migration output = %q", output.String())
		}
		if checkErr := store.CheckMigrations(ctx); checkErr != nil {
			t.Fatalf("CheckMigrations() after up = %v", checkErr)
		}

		output.Reset()
		if statusErr := postgres.RunMigrationCommand(ctx, databaseURL, postgres.MigrationStatus, &output); statusErr != nil {
			t.Fatalf("migration status error = %v", statusErr)
		}
		if !strings.Contains(output.String(), "current_version=10 expected_version=10 status=current") {
			t.Fatalf("migration status = %q", output.String())
		}
	})

	t.Run("real phase two authority upgrades safely to phase three", func(t *testing.T) {
		testPhaseTwoUpgrade(ctx, t, databaseURL)
	})

	t.Run("test-only migration supports down and up", func(t *testing.T) {
		database := openSQLDatabase(ctx, t, databaseURL)
		defer func() { _ = database.Close() }()
		migrationFS := os.DirFS("testdata/migrations")
		if migrationErr := postgres.MigrateUp(ctx, database, migrationFS, "."); migrationErr != nil {
			t.Fatalf("MigrateUp() error = %v", migrationErr)
		}
		if migrationErr := postgres.MigrateUp(ctx, database, migrationFS, "."); migrationErr != nil {
			t.Fatalf("idempotent MigrateUp() error = %v", migrationErr)
		}
		assertTableExists(ctx, t, database, true)
		if migrationErr := postgres.MigrateDown(ctx, database, migrationFS, "."); migrationErr != nil {
			t.Fatalf("MigrateDown() error = %v", migrationErr)
		}
		assertTableExists(ctx, t, database, false)
		if migrationErr := postgres.MigrateUp(ctx, database, migrationFS, "."); migrationErr != nil {
			t.Fatalf("MigrateUp() after down error = %v", migrationErr)
		}
		assertTableExists(ctx, t, database, true)
		if migrationErr := postgres.MigrateDown(ctx, database, migrationFS, "."); migrationErr != nil {
			t.Fatalf("final MigrateDown() cleanup error = %v", migrationErr)
		}
		assertTableExists(ctx, t, database, false)
	})

	t.Run("all production migrations support test down and up", func(t *testing.T) {
		database := openSQLDatabase(ctx, t, databaseURL)
		defer func() { _ = database.Close() }()
		for range 10 {
			if migrationErr := postgres.MigrateDown(ctx, database, productionmigrations.FS, "."); migrationErr != nil {
				t.Fatalf("production MigrateDown() error = %v", migrationErr)
			}
		}
		var usersExists bool
		if err := database.QueryRowContext(ctx, `SELECT to_regclass('public.users') IS NOT NULL`).Scan(&usersExists); err != nil {
			t.Fatal(err)
		}
		if usersExists {
			t.Fatal("users table remained after complete test-only down")
		}
		if migrationErr := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); migrationErr != nil {
			t.Fatalf("production MigrateUp() after down error = %v", migrationErr)
		}
		if migrationErr := postgres.MigrateUp(ctx, database, productionmigrations.FS, "."); migrationErr != nil {
			t.Fatalf("production repeated MigrateUp() error = %v", migrationErr)
		}
	})

	t.Run("HTTP live ready outage and automatic recovery", func(t *testing.T) {
		metrics := observability.NewMetrics(observability.NewBuildInfo("integration", "integration", "integration"))
		readiness := httpserver.NewReadiness(metrics.SetReady)
		readiness.Set(true)
		handler := httpserver.NewHandler(httpserver.HandlerOptions{
			Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
			Readiness:          readiness,
			Database:           store,
			DatabaseErrorClass: postgres.ErrorClass,
			Metrics:            metrics,
			Gatherer:           metrics.Gatherer(),
			ReadinessTimeout:   500 * time.Millisecond,
		})
		assertHTTPStatus(t, handler, "/health/ready", http.StatusOK)

		dockerClient, clientErr := client.New(client.FromEnv)
		if clientErr != nil {
			t.Fatalf("create Docker client for fault injection: %v", clientErr)
		}
		defer func() { _ = dockerClient.Close() }()
		if _, pauseErr := dockerClient.ContainerPause(ctx, container.GetContainerID(), client.ContainerPauseOptions{}); pauseErr != nil {
			t.Fatalf("pause PostgreSQL container: %v", pauseErr)
		}
		paused := true
		defer func() {
			if paused {
				_, _ = dockerClient.ContainerUnpause(context.Background(), container.GetContainerID(), client.ContainerUnpauseOptions{})
			}
		}()
		if !waitUntil(10*time.Second, func() bool {
			pingCtx, pingCancel := context.WithTimeout(ctx, 200*time.Millisecond)
			defer pingCancel()
			return store.Ping(pingCtx) != nil
		}) {
			t.Fatal("pool did not observe PostgreSQL outage")
		}
		assertHTTPStatus(t, handler, "/health/live", http.StatusOK)
		assertHTTPStatus(t, handler, "/health/ready", http.StatusServiceUnavailable)

		if _, unpauseErr := dockerClient.ContainerUnpause(ctx, container.GetContainerID(), client.ContainerUnpauseOptions{}); unpauseErr != nil {
			t.Fatalf("unpause PostgreSQL container: %v", unpauseErr)
		}
		paused = false
		var lastPingError error
		if !waitUntil(30*time.Second, func() bool {
			pingCtx, pingCancel := context.WithTimeout(ctx, time.Second)
			defer pingCancel()
			lastPingError = store.Ping(pingCtx)
			return lastPingError == nil
		}) {
			state, stateErr := container.State(ctx)
			rootCause := lastPingError
			for errors.Unwrap(rootCause) != nil {
				rootCause = errors.Unwrap(rootCause)
			}
			logReader, logsErr := container.Logs(ctx)
			containerLogs := []byte(nil)
			if logsErr == nil {
				containerLogs, _ = io.ReadAll(logReader)
				_ = logReader.Close()
			}
			t.Fatalf("pool did not recover after PostgreSQL restart: last_ping=%v root_cause=%v container_state=%+v state_error=%v logs_error=%v logs=%s", lastPingError, rootCause, state, stateErr, logsErr, containerLogs)
		}
		assertHTTPStatus(t, handler, "/health/ready", http.StatusOK)
	})

	t.Run("phase two identity client session and audit lifecycle", func(t *testing.T) {
		testPhaseTwoLifecycle(ctx, t, store, databaseURL)
	})

	t.Run("phase three Consent and atomic Authorization Code lifecycle", func(t *testing.T) {
		testPhaseThreeAuthorizationLifecycle(ctx, t, store, databaseURL)
	})

	store.Close()
	if stats := store.Stats(); stats.Total != 0 || stats.Acquired != 0 {
		t.Fatalf("pool connections remained after Close: %#v", stats)
	}
}

func startPostgres(ctx context.Context, t *testing.T) (testcontainers.Container, string) {
	t.Helper()
	request := testcontainers.ContainerRequest{
		Image:        "postgres:17.5-alpine3.22",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "oneissuer",
			"POSTGRES_PASSWORD": "integration-only-password",
			"POSTGRES_DB":       "oneissuer",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: request,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start PostgreSQL container: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("PostgreSQL host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("PostgreSQL mapped port: %v", err)
	}
	return container, fmt.Sprintf("postgresql://oneissuer:integration-only-password@%s:%s/oneissuer?sslmode=disable", host, port.Port())
}

func openSQLDatabase(ctx context.Context, t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	configuration, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("pgx.ParseConfig() error = %v", err)
	}
	database := stdlib.OpenDB(*configuration)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		t.Fatalf("database.PingContext() error = %v", err)
	}
	return database
}

func assertTableExists(ctx context.Context, t *testing.T, database *sql.DB, want bool) {
	t.Helper()
	var exists bool
	if err := database.QueryRowContext(ctx, `SELECT to_regclass('public.phase_one_migration_test_marker') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("query test table existence: %v", err)
	}
	if exists != want {
		t.Fatalf("test table exists = %v, want %v", exists, want)
	}
}

func assertHTTPStatus(t *testing.T, handler http.Handler, path string, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != want {
		t.Fatalf("GET %s status = %d, want %d: %s", path, response.Code, want, response.Body)
	}
}

func waitUntil(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
