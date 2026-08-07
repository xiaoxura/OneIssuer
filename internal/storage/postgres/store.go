// Package postgres owns OneIssuer's PostgreSQL pool, system queries, migration
// state, and privacy-safe error classification.
package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

// Store wraps the pool and generated sqlc system queries.
type Store struct {
	pool          *pgxpool.Pool
	queries       *sqlcgen.Queries
	auditObserver AuditObserver
}

// AuditObserver receives only fixed event/result labels after a database write
// or transaction has committed successfully.
type AuditObserver interface {
	AuditEvent(event, result string)
	AuditWriteFailure(event string)
}

// Open creates a bounded pool and verifies a real connection before returning.
func Open(ctx context.Context, databaseURL string, maxConns int32) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, wrapError("configuration", ErrorKindConfig, err)
	}
	poolConfig.MaxConns = maxConns

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, wrapError("pool creation", ErrorKindUnavailable, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, wrapError("startup ping", ErrorKindUnavailable, err)
	}

	return &Store{pool: pool, queries: sqlcgen.New(pool)}, nil
}

// SetAuditObserver installs the process-wide audit metric observer. It must be
// called during startup before the Store is shared with request goroutines.
func (s *Store) SetAuditObserver(observer AuditObserver) {
	if s != nil {
		s.auditObserver = observer
	}
}

// Ping executes the sqlc-generated SELECT 1 query used by readiness checks.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.queries == nil {
		return &Error{Operation: "readiness ping", Kind: ErrorKindUnavailable}
	}
	value, err := s.queries.Ping(ctx)
	if err != nil {
		return wrapError("readiness ping", ErrorKindQuery, err)
	}
	if value != 1 {
		return &Error{Operation: "readiness ping", Kind: ErrorKindQuery}
	}
	return nil
}

// Close releases all pool connections. pgxpool.Close is idempotent.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Stats returns a privacy-safe snapshot for the Prometheus collector.
func (s *Store) Stats() observability.DatabasePoolStats {
	if s == nil || s.pool == nil {
		return observability.DatabasePoolStats{}
	}
	stats := s.pool.Stat()
	return observability.DatabasePoolStats{
		Max:          stats.MaxConns(),
		Total:        stats.TotalConns(),
		Idle:         stats.IdleConns(),
		Acquired:     stats.AcquiredConns(),
		Constructing: stats.ConstructingConns(),
	}
}
