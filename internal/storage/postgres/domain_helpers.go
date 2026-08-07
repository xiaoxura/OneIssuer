package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/storage/postgres/sqlcgen"
)

const maxTransactionAttempts = 2

// inTx executes one transaction and permits exactly one retry when the
// operation is aborted by PostgreSQL's serialization/deadlock detector. The
// commit boundary is deliberately outside the retry decision: a commit error
// may be ambiguous, so the caller must never receive a second clear response.
// reset is called before every attempt so callers can discard values produced
// by a rolled-back attempt (response, audit events, counters, or candidates).
func (s *Store) inTx(ctx context.Context, options pgx.TxOptions, operation func(*sqlcgen.Queries) error, reset ...func()) error {
	if s == nil || s.pool == nil {
		return wrapError("transaction", ErrorKindUnavailable, errors.New("store unavailable"))
	}
	resetValues := func() {
		for _, resetAttempt := range reset {
			if resetAttempt != nil {
				resetAttempt()
			}
		}
	}
	for attempt := 0; attempt < maxTransactionAttempts; attempt++ {
		resetValues()

		tx, err := s.pool.BeginTx(ctx, options)
		if err != nil {
			return wrapError("begin transaction", ErrorKindQuery, err)
		}
		operationErr := operation(s.queries.WithTx(tx))
		if operationErr != nil {
			_ = tx.Rollback(context.Background())
			if attempt == 0 && isRetryableTransactionError(operationErr) {
				continue
			}
			resetValues()
			s.observeAuditWriteFailure(operationErr)
			return operationErr
		}
		if err := tx.Commit(ctx); err != nil {
			resetValues()
			return wrapError("commit transaction", ErrorKindQuery, err)
		}
		return nil
	}
	// The loop always returns on its final attempt. Keep a defensive error in
	// place should the attempt policy change without updating this function.
	return wrapError("transaction retry exhausted", ErrorKindQuery, errors.New("transaction retry exhausted"))
}

func (s *Store) inTxWithAudit(ctx context.Context, options pgx.TxOptions, events []audit.Event, operation func(*sqlcgen.Queries) error, reset ...func()) error {
	if err := s.inTx(ctx, options, operation, reset...); err != nil {
		return err
	}
	s.observeAuditEvents(events)
	return nil
}

func (s *Store) observeAuditEvents(events []audit.Event) {
	if s == nil || s.auditObserver == nil {
		return
	}
	for _, event := range events {
		s.auditObserver.AuditEvent(string(event.Type), string(event.Result))
	}
}

func (s *Store) observeAuditWriteFailure(err error) {
	if s == nil || s.auditObserver == nil {
		return
	}
	var appendErr *auditAppendError
	if errors.As(err, &appendErr) {
		s.auditObserver.AuditWriteFailure(appendErr.event)
	}
}

type auditAppendError struct {
	event string
	err   error
}

func (e *auditAppendError) Error() string { return e.err.Error() }

func (e *auditAppendError) Unwrap() error { return e.err }

func timestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}

func cursorTimestamp(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return timestamp(value)
}

func optionalTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time.UTC()
	return &result
}

func requiredTime(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func mapUser(row sqlcgen.User) identity.User {
	return identity.User{
		ID: row.ID, Subject: row.Subject, Username: row.Username,
		UsernameNormalized: row.UsernameNormalized, DisplayName: row.DisplayName,
		Email: row.Email, EmailNormalized: row.EmailNormalized, EmailVerified: row.EmailVerified,
		Status: identity.Status(row.Status), Role: identity.Role(row.Role),
		CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: requiredTime(row.UpdatedAt), Version: row.Version,
		LastLoginAt: optionalTime(row.LastLoginAt),
	}
}

func insertAudit(ctx context.Context, queries *sqlcgen.Queries, event audit.Event) error {
	if err := event.Validate(); err != nil {
		return &auditAppendError{event: string(event.Type), err: err}
	}
	var targetType *string
	if event.TargetType != nil {
		value := string(*event.TargetType)
		targetType = &value
	}
	var requestID *string
	if event.RequestID != "" {
		value := event.RequestID
		requestID = &value
	}
	if err := queries.CreateAuditEvent(ctx, sqlcgen.CreateAuditEventParams{
		ID: event.ID, EventType: string(event.Type), Result: string(event.Result),
		ActorUserID: event.ActorUserID, TargetType: targetType, TargetID: event.TargetID,
		RequestID: requestID, ChangedFields: event.ChangedFields, OccurredAt: timestamp(event.OccurredAt),
	}); err != nil {
		return &auditAppendError{event: string(event.Type), err: wrapError("append audit event", ErrorKindQuery, err)}
	}
	return nil
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func isConstraint(err error, code string) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == code
}

func isRetryableTransactionError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	return postgresError.Code == "40001" || postgresError.Code == "40P01"
}

func pointerString(value string) *string {
	if value == "" {
		return nil
	}
	result := value
	return &result
}
