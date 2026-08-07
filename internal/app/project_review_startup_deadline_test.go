package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/keystore"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	productionmigrations "github.com/oneissuer/oneissuer/migrations"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestServeIntegrationBoundsBootstrapHasAdminByStartupTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL startup deadline integration test in short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	testCtx, cancelTest := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelTest()
	_, databaseURL := serveStartupPostgres(testCtx, t)

	database := serveStartupOpenDatabase(testCtx, t, databaseURL)
	t.Cleanup(func() { _ = database.Close() })
	if err := postgres.MigrateUp(testCtx, database, productionmigrations.FS, "."); err != nil {
		t.Fatalf("production migrations: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "active.jwk")
	if _, err := keystore.Generate(keyPath, 2048, rand.Reader); err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	httpAddr := serveStartupAvailableAddr(t)
	cfg, err := config.LoadFrom(serveStartupLookup(map[string]string{
		"ONEISSUER_ENV":              "test",
		"ONEISSUER_DATABASE_URL":     databaseURL,
		"ONEISSUER_SIGNING_KEY_FILE": keyPath,
		"ONEISSUER_HTTP_ADDR":        httpAddr,
	}), config.ScopeService)
	if err != nil {
		t.Fatalf("load integration config: %v", err)
	}

	key := 781000000 + time.Now().UnixNano()%1000000
	suffix := fmt.Sprintf("%d", key)
	functionName := "oneissuer_startup_audit_barrier_fn_" + suffix
	triggerName := "oneissuer_startup_audit_barrier_tr_" + suffix
	if _, err := database.ExecContext(testCtx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	PERFORM pg_advisory_xact_lock(%d);
	RETURN NEW;
END
$$`, functionName, key)); err != nil {
		t.Fatalf("create startup audit barrier function: %v", err)
	}
	if _, err := database.ExecContext(testCtx, fmt.Sprintf(`CREATE TRIGGER %s AFTER INSERT ON audit_events
	FOR EACH ROW WHEN (NEW.event_type = 'signing_key_loaded') EXECUTE FUNCTION %s()`, triggerName, functionName)); err != nil {
		_, _ = database.ExecContext(context.Background(), fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName))
		t.Fatalf("create startup audit barrier trigger: %v", err)
	}
	triggerCleaned := false
	cleanupTrigger := func() error {
		if triggerCleaned {
			return nil
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var cleanupErrs []error
		if _, err := database.ExecContext(cleanupCtx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON audit_events", triggerName)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("drop startup audit trigger: %w", err))
		}
		if _, err := database.ExecContext(cleanupCtx, fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName)); err != nil {
			cleanupErrs = append(cleanupErrs, fmt.Errorf("drop startup audit function: %w", err))
		}
		if len(cleanupErrs) == 0 {
			triggerCleaned = true
		}
		return errors.Join(cleanupErrs...)
	}
	t.Cleanup(func() {
		if err := cleanupTrigger(); err != nil {
			t.Errorf("cleanup startup audit barrier: %v", err)
		}
	})

	advisoryConn, err := database.Conn(testCtx)
	if err != nil {
		t.Fatalf("reserve startup advisory connection: %v", err)
	}
	advisoryHeld := false
	if _, err := advisoryConn.ExecContext(testCtx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		_ = advisoryConn.Close()
		t.Fatalf("acquire startup advisory lock: %v", err)
	}
	advisoryHeld = true
	releaseAdvisory := func() error {
		if !advisoryHeld {
			return nil
		}
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := advisoryConn.ExecContext(releaseCtx, `SELECT pg_advisory_unlock($1)`, key)
		if err == nil {
			advisoryHeld = false
		}
		return err
	}
	advisoryCleaned := false
	cleanupAdvisory := func() {
		if advisoryCleaned {
			return
		}
		if err := releaseAdvisory(); err != nil {
			t.Errorf("release startup advisory lock: %v", err)
		}
		if err := advisoryConn.Close(); err != nil {
			t.Errorf("close startup advisory connection: %v", err)
		}
		advisoryCleaned = true
	}
	t.Cleanup(cleanupAdvisory)

	serveCtx, cancelServe := context.WithCancel(testCtx)
	defer cancelServe()
	serveResult := make(chan error, 1)
	started := time.Now()
	go func() {
		serveResult <- Serve(serveCtx, cfg, observability.NewBuildInfo("startup-deadline-integration", "test", "test"), nil)
	}()

	observationCtx, cancelObservation := context.WithTimeout(testCtx, startupTimeout-2*time.Second)
	defer cancelObservation()
	auditWaiter, err := serveStartupWaitForAuditBarrier(observationCtx, database)
	if err != nil {
		cleanupAdvisory()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("Serve did not enter signing_key_loaded audit barrier: %v", err)
	}
	if auditWaiter.waitEventType != "Lock" || auditWaiter.waitEvent != "advisory" {
		cleanupAdvisory()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("signing_key_loaded audit had unexpected advisory wait state: %+v", auditWaiter)
	}
	var blocker *sql.Conn
	var blockerTx *sql.Tx
	lockCtx, cancelLock := context.WithCancel(testCtx)
	lockResult := make(chan error, 1)
	lockStarted := false
	lockResultConsumed := false
	lockCleaned := false
	cleanupLock := func() error {
		if lockCleaned {
			return nil
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		cancelLock()
		var cleanupErrs []error
		if lockStarted && !lockResultConsumed {
			select {
			case <-lockResult:
				lockResultConsumed = true
			case <-cleanupCtx.Done():
				cleanupErrs = append(cleanupErrs, errors.New("users lock goroutine did not stop"))
			}
		}
		if blockerTx != nil {
			if err := blockerTx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("rollback users lock transaction: %w", err))
			}
		}
		if blocker != nil {
			if err := blocker.Close(); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("close users lock connection: %w", err))
			}
		}
		lockCleaned = true
		return errors.Join(cleanupErrs...)
	}
	t.Cleanup(func() {
		if err := cleanupLock(); err != nil {
			t.Errorf("cleanup users lock: %v", err)
		}
	})
	blocker, err = database.Conn(testCtx)
	if err != nil {
		cleanupAdvisory()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("reserve users lock connection: %v", err)
	}
	blockerTx, err = blocker.BeginTx(testCtx, nil)
	if err != nil {
		_ = blocker.Close()
		cleanupAdvisory()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("begin users lock transaction: %v", err)
	}
	var blockerPID int
	if err := blockerTx.QueryRowContext(testCtx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		_ = blockerTx.Rollback()
		_ = blocker.Close()
		cleanupAdvisory()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("read users lock backend pid: %v", err)
	}
	lockStarted = true
	go func() {
		_, lockErr := blockerTx.ExecContext(lockCtx, `LOCK TABLE users IN ACCESS EXCLUSIVE MODE`)
		lockResult <- lockErr
	}()
	initialGranted, err := serveStartupWaitForUsersLock(observationCtx, database, blockerPID, false)
	if err != nil {
		_ = cleanupLock()
		cleanupAdvisory()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("ACCESS EXCLUSIVE users lock request not visible: %v", err)
	}
	if initialGranted {
		t.Log("ACCESS EXCLUSIVE users lock was already granted before advisory release")
	}
	if err := releaseAdvisory(); err != nil {
		_ = cleanupLock()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("release startup audit barrier: %v", err)
	}
	if _, err := serveStartupWaitForUsersLock(observationCtx, database, blockerPID, true); err != nil {
		_ = cleanupLock()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("ACCESS EXCLUSIVE users lock was not granted after audit barrier release: %v", err)
	}
	lockErr := serveStartupAwaitLock(lockResult)
	lockResultConsumed = true
	if err := lockErr; err != nil {
		_ = cleanupLock()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("ACCESS EXCLUSIVE users lock failed: %v", err)
	}
	if err := serveStartupWaitForAudit(observationCtx, database); err != nil {
		_ = cleanupLock()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("signing_key_loaded audit did not commit after barrier release: %v", err)
	}
	waiter, err := serveStartupWaitForHasAdmin(observationCtx, database, blockerPID)
	if err != nil {
		_ = cleanupLock()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("Serve HasAdmin query did not enter a PostgreSQL lock wait: %v", err)
	}
	if waiter.waitEventType != "Lock" || waiter.waitEvent != "relation" {
		_ = cleanupLock()
		cancelServe()
		_ = serveStartupAwaitResult(serveResult)
		t.Fatalf("HasAdmin waiter had unexpected PostgreSQL wait state: %+v", waiter)
	}
	if !serveStartupCanBind(httpAddr) {
		t.Errorf("HTTP listener %s was already open while HasAdmin was blocked", httpAddr)
	}

	var serveErr error
	select {
	case serveErr = <-serveResult:
	case <-time.After(startupTimeout + 5*time.Second):
		cancelServe()
		_ = cleanupLock()
		serveErr = serveStartupAwaitResult(serveResult)
		t.Fatalf("Serve exceeded startup deadline while HasAdmin was blocked: %v", serveErr)
	}
	elapsed := time.Since(started)
	if elapsed < startupTimeout-2*time.Second || elapsed > startupTimeout+5*time.Second {
		t.Fatalf("Serve returned after %s, want approximately startupTimeout=%s", elapsed, startupTimeout)
	}
	if serveErr == nil {
		t.Fatal("Serve succeeded while HasAdmin was blocked")
	}
	if !errors.Is(serveErr, context.DeadlineExceeded) {
		t.Fatalf("Serve error = %v, want context deadline exceeded", serveErr)
	}
	if got := postgres.ErrorClass(serveErr); got != string(postgres.ErrorKindCanceled) {
		t.Fatalf("Serve error class = %q, want %q: %v", got, postgres.ErrorKindCanceled, serveErr)
	}
	if !strings.Contains(serveErr.Error(), "check bootstrap state") {
		t.Fatalf("Serve error = %v, want bootstrap state classification", serveErr)
	}

	if err := cleanupLock(); err != nil {
		t.Fatalf("cleanup users lock: %v", err)
	}
	cleanupAdvisory()
	if err := cleanupTrigger(); err != nil {
		t.Fatalf("cleanup startup audit barrier: %v", err)
	}
	if !serveStartupCanBind(httpAddr) {
		t.Fatalf("HTTP listener %s was opened after startup failure", httpAddr)
	}
	var signingKeyLoaded, totalAudit, users int64
	if err := database.QueryRowContext(testCtx, `
		SELECT count(*) FILTER (WHERE event_type = 'signing_key_loaded'), count(*)
		FROM audit_events`).Scan(&signingKeyLoaded, &totalAudit); err != nil {
		t.Fatalf("query startup audit side effects: %v", err)
	}
	if err := database.QueryRowContext(testCtx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("query user side effects: %v", err)
	}
	if signingKeyLoaded != 1 || totalAudit != 1 || users != 0 {
		t.Fatalf("startup side effects signing_key_loaded=%d total_audit=%d users=%d, want 1/1/0", signingKeyLoaded, totalAudit, users)
	}
	if err := serveStartupWaitForNoHasAdmin(testCtx, database); err != nil {
		t.Fatal(err)
	}
}

type serveStartupWaiter struct {
	pid           int
	state         string
	waitEventType string
	waitEvent     string
	query         string
}

func serveStartupWaitForAuditBarrier(ctx context.Context, database *sql.DB) (serveStartupWaiter, error) {
	for {
		var waiter serveStartupWaiter
		queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := database.QueryRowContext(queryCtx, `
			SELECT pid, state, wait_event_type, wait_event, query
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND pid <> pg_backend_pid()
			  AND state = 'active'
			  AND wait_event_type = 'Lock'
			  AND wait_event = 'advisory'
			  AND query ILIKE '%audit_events%'
			ORDER BY query_start
			LIMIT 1`).Scan(&waiter.pid, &waiter.state, &waiter.waitEventType, &waiter.waitEvent, &waiter.query)
		cancel()
		if err == nil {
			return waiter, nil
		}
		if ctx.Err() != nil {
			return serveStartupWaiter{}, fmt.Errorf("wait for signing_key_loaded audit barrier: %w", ctx.Err())
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return serveStartupWaiter{}, fmt.Errorf("poll signing_key_loaded audit barrier: %w", err)
		}
		select {
		case <-ctx.Done():
			return serveStartupWaiter{}, fmt.Errorf("wait for signing_key_loaded audit barrier: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func serveStartupWaitForUsersLock(ctx context.Context, database *sql.DB, pid int, requireGranted bool) (bool, error) {
	for {
		var granted bool
		queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := database.QueryRowContext(queryCtx, `
			SELECT granted
			FROM pg_locks
			WHERE locktype = 'relation'
			  AND pid = $1
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			  AND relation = 'public.users'::regclass
			  AND mode = 'AccessExclusiveLock'
			ORDER BY granted DESC
			LIMIT 1`, pid).Scan(&granted)
		cancel()
		if err == nil && (!requireGranted || granted) {
			return granted, nil
		}
		if ctx.Err() != nil {
			if requireGranted {
				return false, fmt.Errorf("wait for users Access EXCLUSIVE lock to be granted: %w", ctx.Err())
			}
			return false, fmt.Errorf("users AccessExclusiveLock request not visible: %w", ctx.Err())
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return false, fmt.Errorf("poll users Access EXCLUSIVE lock: %w", err)
		}
		select {
		case <-ctx.Done():
			if requireGranted {
				return false, fmt.Errorf("wait for users Access EXCLUSIVE lock to be granted: %w", ctx.Err())
			}
			return false, fmt.Errorf("users AccessExclusiveLock request not visible: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func serveStartupAwaitLock(results <-chan error) error {
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		return errors.New("users lock result was not delivered")
	}
}

func serveStartupWaitForAudit(ctx context.Context, database *sql.DB) error {
	for {
		var count int64
		queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := database.QueryRowContext(queryCtx, `SELECT count(*) FROM audit_events WHERE event_type = 'signing_key_loaded'`).Scan(&count)
		cancel()
		if err == nil && count > 0 {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("wait for signing_key_loaded audit: %w", ctx.Err())
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("poll signing_key_loaded audit: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for signing_key_loaded audit: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func serveStartupWaitForHasAdmin(ctx context.Context, database *sql.DB, blockerPID int) (serveStartupWaiter, error) {
	for {
		var waiter serveStartupWaiter
		queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := database.QueryRowContext(queryCtx, `
			SELECT pid, state, wait_event_type, wait_event, query
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND pid <> pg_backend_pid()
			  AND state = 'active'
			  AND wait_event_type = 'Lock'
			  AND wait_event = 'relation'
			  AND $1 = ANY(pg_blocking_pids(pid))
			  AND query ILIKE '%FROM users WHERE role%'
			ORDER BY query_start
			LIMIT 1`, blockerPID).Scan(&waiter.pid, &waiter.state, &waiter.waitEventType, &waiter.waitEvent, &waiter.query)
		cancel()
		if err == nil {
			return waiter, nil
		}
		if ctx.Err() != nil {
			return serveStartupWaiter{}, fmt.Errorf("wait for HasAdmin lock state: %w", ctx.Err())
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return serveStartupWaiter{}, fmt.Errorf("poll HasAdmin lock state: %w", err)
		}
		select {
		case <-ctx.Done():
			return serveStartupWaiter{}, fmt.Errorf("wait for HasAdmin lock state: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func serveStartupHasAdminWaiter(ctx context.Context, database *sql.DB) (bool, error) {
	var active bool
	err := database.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND pid <> pg_backend_pid()
			  AND state = 'active'
			  AND query ILIKE '%FROM users WHERE role%'
		)`).Scan(&active)
	return active, err
}

func serveStartupWaitForNoHasAdmin(ctx context.Context, database *sql.DB) error {
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		active, err := serveStartupHasAdminWaiter(checkCtx, database)
		if err != nil {
			return fmt.Errorf("check HasAdmin activity after Serve returned: %w", err)
		}
		if !active {
			return nil
		}
		select {
		case <-checkCtx.Done():
			return fmt.Errorf("HasAdmin query remained active after Serve returned")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func serveStartupAwaitResult(results <-chan error) error {
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		return errors.New("Serve result was not delivered after cancellation")
	}
}

func serveStartupLookup(values map[string]string) config.LookupEnv {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func serveStartupAvailableAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve HTTP address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release HTTP address reservation: %v", err)
	}
	return addr
}

func serveStartupCanBind(addr string) bool {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func serveStartupOpenDatabase(ctx context.Context, t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	configuration, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("pgx.ParseConfig: %v", err)
	}
	database := stdlib.OpenDB(*configuration)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		t.Fatalf("database ping: %v", err)
	}
	return database
}

func serveStartupPostgres(ctx context.Context, t *testing.T) (testcontainers.Container, string) {
	t.Helper()
	request := testcontainers.ContainerRequest{
		Image:        "postgres:17.10-alpine3.23@sha256:8189a1f6e40904781fc9e2612687877791d21679866db58b1de996b31fc312e4",
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
	t.Cleanup(func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer terminateCancel()
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(terminateCtx)); err != nil {
			t.Errorf("terminate PostgreSQL container: %v", err)
		}
	})
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
