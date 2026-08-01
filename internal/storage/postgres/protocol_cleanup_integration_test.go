package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/storage/postgres"
)

const protocolCleanupAdvisoryLock int64 = 918273645

type protocolCleanupResult struct {
	deleted int64
	err     error
}

// testProtocolCleanupRollback proves that cancellation (the shutdown path) and
// an operation deadline cannot commit the Access-metadata deletion that runs
// before the dependent Authorization Code deletion in the cleanup transaction.
func testProtocolCleanupRollback(ctx context.Context, t *testing.T, store *postgres.Store, database *sql.DB, cutoff time.Time) {
	t.Helper()

	var initialCodes, initialAccess int
	if err := database.QueryRowContext(ctx, `
		SELECT (SELECT count(*)::int FROM authorization_codes),
		       (SELECT count(*)::int FROM access_tokens)`).Scan(&initialCodes, &initialAccess); err != nil {
		t.Fatalf("count protocol metadata before interrupted cleanup: %v", err)
	}
	if initialCodes == 0 || initialAccess == 0 {
		t.Fatalf("interrupted cleanup fixture codes=%d access=%d, want both non-zero", initialCodes, initialAccess)
	}

	blocker, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve cleanup advisory-lock connection: %v", err)
	}
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, protocolCleanupAdvisoryLock); err != nil {
		_ = blocker.Close()
		t.Fatalf("acquire cleanup advisory lock: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE FUNCTION oneissuer_test_block_protocol_cleanup() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(918273645);
			RETURN OLD;
		END
		$$`); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		t.Fatalf("create protocol cleanup blocking function: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		CREATE TRIGGER oneissuer_test_block_protocol_cleanup
		BEFORE DELETE ON authorization_codes
		FOR EACH ROW EXECUTE FUNCTION oneissuer_test_block_protocol_cleanup()`); err != nil {
		_, _ = blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		t.Fatalf("create protocol cleanup blocking trigger: %v", err)
	}

	cleanedUp := false
	cleanupFaultInjection := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = blocker.ExecContext(cleanupCtx, `SELECT pg_advisory_unlock($1)`, protocolCleanupAdvisoryLock)
		_ = blocker.Close()
		_, _ = database.ExecContext(cleanupCtx, `DROP TRIGGER IF EXISTS oneissuer_test_block_protocol_cleanup ON authorization_codes`)
		_, _ = database.ExecContext(cleanupCtx, `DROP FUNCTION IF EXISTS oneissuer_test_block_protocol_cleanup()`)
	}
	t.Cleanup(func() {
		if !cleanedUp {
			cleanupFaultInjection()
		}
	})

	waitForBlockedDelete := func(label string) {
		t.Helper()
		if !waitUntil(3*time.Second, func() bool {
			queryCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
			defer cancel()
			var waiting bool
			err := database.QueryRowContext(queryCtx, `
				SELECT EXISTS (
					SELECT 1 FROM pg_stat_activity
					WHERE datname=current_database()
					  AND state='active'
					  AND wait_event_type='Lock'
					  AND query LIKE '%DELETE FROM authorization_codes%'
				)`).Scan(&waiting)
			return err == nil && waiting
		}) {
			t.Fatalf("%s cleanup never reached the blocked Code deletion", label)
		}
	}
	assertMetadataUnchanged := func(label string) {
		t.Helper()
		var codes, access int
		if err := database.QueryRowContext(ctx, `
			SELECT (SELECT count(*)::int FROM authorization_codes),
			       (SELECT count(*)::int FROM access_tokens)`).Scan(&codes, &access); err != nil {
			t.Fatalf("count protocol metadata after %s cleanup: %v", label, err)
		}
		if codes != initialCodes || access != initialAccess {
			t.Fatalf("%s cleanup left partial state codes=%d/%d access=%d/%d", label, codes, initialCodes, access, initialAccess)
		}
	}

	canceledCtx, cancelCleanup := context.WithCancel(ctx)
	canceledResult := make(chan protocolCleanupResult, 1)
	go func() {
		deleted, cleanupErr := store.CleanupProtocolArtifacts(canceledCtx, cutoff)
		canceledResult <- protocolCleanupResult{deleted: deleted, err: cleanupErr}
	}()
	waitForBlockedDelete("canceled")
	cancelCleanup()
	result := <-canceledResult
	if result.deleted != 0 || !errors.Is(result.err, context.Canceled) || postgres.ErrorClass(result.err) != string(postgres.ErrorKindCanceled) {
		t.Fatalf("canceled cleanup deleted=%d error=%v class=%q", result.deleted, result.err, postgres.ErrorClass(result.err))
	}
	assertMetadataUnchanged("canceled")

	deadlineCtx, cancelDeadline := context.WithTimeout(ctx, time.Second)
	defer cancelDeadline()
	deadlineResult := make(chan protocolCleanupResult, 1)
	go func() {
		deleted, cleanupErr := store.CleanupProtocolArtifacts(deadlineCtx, cutoff)
		deadlineResult <- protocolCleanupResult{deleted: deleted, err: cleanupErr}
	}()
	waitForBlockedDelete("deadline")
	result = <-deadlineResult
	if result.deleted != 0 || !errors.Is(result.err, context.DeadlineExceeded) || postgres.ErrorClass(result.err) != string(postgres.ErrorKindCanceled) {
		t.Fatalf("deadline cleanup deleted=%d error=%v class=%q", result.deleted, result.err, postgres.ErrorClass(result.err))
	}
	assertMetadataUnchanged("deadline")

	cleanupFaultInjection()
	cleanedUp = true
}
