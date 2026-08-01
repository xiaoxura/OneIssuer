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

func (s *Store) inTx(ctx context.Context, options pgx.TxOptions, operation func(*sqlcgen.Queries) error) error {
	if s == nil || s.pool == nil {
		return wrapError("transaction", ErrorKindUnavailable, errors.New("store unavailable"))
	}
	tx, err := s.pool.BeginTx(ctx, options)
	if err != nil {
		return wrapError("begin transaction", ErrorKindQuery, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := operation(s.queries.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return wrapError("commit transaction", ErrorKindQuery, err)
	}
	return nil
}

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
		CreatedAt: requiredTime(row.CreatedAt), UpdatedAt: requiredTime(row.UpdatedAt), Version: requiredTime(row.UpdatedAt),
		LastLoginAt: optionalTime(row.LastLoginAt),
	}
}

func insertAudit(ctx context.Context, queries *sqlcgen.Queries, event audit.Event) error {
	if err := event.Validate(); err != nil {
		return err
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
		return wrapError("append audit event", ErrorKindQuery, err)
	}
	return nil
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func isConstraint(err error, code string) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == code
}

func pointerString(value string) *string {
	if value == "" {
		return nil
	}
	result := value
	return &result
}
