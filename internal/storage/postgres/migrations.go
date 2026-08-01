package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	productionmigration "github.com/oneissuer/oneissuer/migrations"
	"github.com/pressly/goose/v3"
)

const migrationTable = "goose_db_version"

var (
	migrationLock = &sync.Mutex{}
	// migrate and serve intentionally share the exact same compile-time source.
	productionMigrations fs.FS = productionmigration.FS
	migrationNamePattern       = regexp.MustCompile(`^(\d{5})_[a-z0-9_]+\.sql$`)
)

// MigrationState is the read-only migration compatibility result.
type MigrationState struct {
	Initialized bool
	Current     int64
	Expected    int64
}

// MigrationCommand identifies a supported CLI migration action.
type MigrationCommand string

const (
	// MigrationUp initializes metadata and applies every pending migration.
	MigrationUp MigrationCommand = "up"
	// MigrationStatus reports the current and expected migration versions.
	MigrationStatus MigrationCommand = "status"
	// MigrationVersion prints only the current database version.
	MigrationVersion MigrationCommand = "version"
)

// RunMigrationCommand opens one stdlib pgx connection and executes a migration
// command. Neither driver errors nor the database URL are written to output.
func RunMigrationCommand(ctx context.Context, databaseURL string, command MigrationCommand, output io.Writer) error {
	if output == nil {
		output = io.Discard
	}
	database, err := openMigrationDatabase(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	switch command {
	case MigrationUp:
		if err := MigrateUp(ctx, database, productionMigrations, "."); err != nil {
			return err
		}
		state, err := readMigrationStateSQL(ctx, database, expectedVersion(productionMigrations))
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(output, "migration complete: version %d\n", state.Current)
		return nil
	case MigrationStatus:
		state, err := readMigrationStateSQL(ctx, database, expectedVersion(productionMigrations))
		if err != nil {
			return err
		}
		status := "current"
		if state.Current < state.Expected {
			status = "pending"
		} else if state.Current > state.Expected {
			status = "incompatible"
		}
		_, _ = fmt.Fprintf(output, "current_version=%d expected_version=%d status=%s\n", state.Current, state.Expected, status)
		return nil
	case MigrationVersion:
		state, err := readMigrationStateSQL(ctx, database, expectedVersion(productionMigrations))
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(output, "%d\n", state.Current)
		return nil
	default:
		return fmt.Errorf("unsupported migration command")
	}
}

func openMigrationDatabase(ctx context.Context, databaseURL string) (*sql.DB, error) {
	pgxConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, wrapError("migration configuration", ErrorKindConfig, err)
	}
	database := stdlib.OpenDB(*pgxConfig)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, wrapError("migration connection", ErrorKindUnavailable, err)
	}
	return database, nil
}

// CheckMigrations performs the serve-time read-only compatibility check. It
// never creates or changes the Goose metadata table.
func (s *Store) CheckMigrations(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return &MigrationError{Reason: "database is unavailable"}
	}

	var initialized bool
	err := s.pool.QueryRow(ctx, `SELECT to_regclass('`+migrationTable+`') IS NOT NULL`).Scan(&initialized)
	if err != nil {
		return &MigrationError{Reason: "migration state could not be read", cause: err}
	}
	if !initialized {
		return &MigrationError{Reason: "migration metadata is not initialized; run oneissuer migrate up"}
	}

	current, err := currentVersion(ctx, s.pool)
	if err != nil {
		return err
	}
	expected := expectedVersion(productionMigrations)
	if current < expected {
		return &MigrationError{Reason: "database migrations are pending; run oneissuer migrate up"}
	}
	if current > expected {
		return &MigrationError{Reason: "database migration version is newer than this binary"}
	}
	return nil
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func currentVersion(ctx context.Context, query rowQuerier) (int64, error) {
	var version int64
	// Goose records every Up and Down operation. For each migration version, the
	// latest row decides whether it is currently applied; the highest applied
	// version is the current linear schema version.
	err := query.QueryRow(ctx, `
		SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied), 0)
		FROM (
			SELECT DISTINCT ON (version_id) version_id, is_applied
			FROM `+migrationTable+`
			ORDER BY version_id, id DESC
		) AS latest`).Scan(&version)
	if err != nil {
		return 0, &MigrationError{Reason: "migration version could not be read", cause: err}
	}
	return version, nil
}

func readMigrationStateSQL(ctx context.Context, database *sql.DB, expected int64) (MigrationState, error) {
	var initialized bool
	if err := database.QueryRowContext(ctx, `SELECT to_regclass('`+migrationTable+`') IS NOT NULL`).Scan(&initialized); err != nil {
		return MigrationState{}, &MigrationError{Reason: "migration state could not be read", cause: err}
	}
	if !initialized {
		return MigrationState{}, &MigrationError{Reason: "migration metadata is not initialized; run oneissuer migrate up"}
	}

	var current int64
	err := database.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version_id) FILTER (WHERE is_applied), 0)
		FROM (
			SELECT DISTINCT ON (version_id) version_id, is_applied
			FROM `+migrationTable+`
			ORDER BY version_id, id DESC
		) AS latest`).Scan(&current)
	if err != nil {
		return MigrationState{}, &MigrationError{Reason: "migration version could not be read", cause: err}
	}
	return MigrationState{Initialized: true, Current: current, Expected: expected}, nil
}

// MigrateUp applies migrations from the provided filesystem. Production calls
// this with the embedded production FS; integration tests may use test-only SQL files.
func MigrateUp(ctx context.Context, database *sql.DB, migrationFS fs.FS, directory string) error {
	if expectedVersion(migrationFS) == 0 {
		return runGoose(migrationFS, func() error {
			_, err := goose.EnsureDBVersionContext(ctx, database)
			return err
		})
	}
	return runGoose(migrationFS, func() error {
		return goose.UpContext(ctx, database, directory)
	})
}

// MigrateDown rolls back exactly one migration from the provided filesystem.
func MigrateDown(ctx context.Context, database *sql.DB, migrationFS fs.FS, directory string) error {
	return runGoose(migrationFS, func() error {
		return goose.DownContext(ctx, database, directory)
	})
}

func runGoose(migrationFS fs.FS, operation func() error) error {
	migrationLock.Lock()
	defer migrationLock.Unlock()

	goose.SetBaseFS(migrationFS)
	defer goose.SetBaseFS(nil)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return &MigrationError{Reason: "migration dialect could not be configured", cause: err}
	}
	if err := operation(); err != nil {
		return &MigrationError{Reason: "migration execution failed", cause: err}
	}
	return nil
}

func expectedVersion(migrationFS fs.FS) int64 {
	var latest int64
	_ = fs.WalkDir(migrationFS, ".", func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		matches := migrationNamePattern.FindStringSubmatch(entry.Name())
		if len(matches) != 2 {
			return nil
		}
		version, parseErr := strconv.ParseInt(matches[1], 10, 64)
		if parseErr == nil && version > latest && version < math.MaxInt64 {
			latest = version
		}
		return nil
	})
	return latest
}

// MigrationError is intentionally free of SQL text, connection details, and
// driver messages. Its cause remains available to errors.Is/errors.As.
type MigrationError struct {
	Reason string
	cause  error
}

func (e *MigrationError) Error() string {
	if e == nil || e.Reason == "" {
		return "database migration check failed"
	}
	return e.Reason
}

func (e *MigrationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// IsMigrationError allows callers to avoid exposing an underlying driver
// failure while still distinguishing migration failures.
func IsMigrationError(err error) bool {
	var migrationError *MigrationError
	return errors.As(err, &migrationError)
}
