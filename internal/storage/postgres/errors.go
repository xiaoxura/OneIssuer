package postgres

import (
	"context"
	"errors"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
)

// ErrorKind is a stable, privacy-safe PostgreSQL failure category.
type ErrorKind string

const (
	// ErrorKindCanceled represents context cancellation or deadline expiry.
	ErrorKindCanceled ErrorKind = "canceled"
	// ErrorKindConfig represents invalid driver or pool configuration.
	ErrorKindConfig ErrorKind = "configuration"
	// ErrorKindAuth represents a PostgreSQL authentication rejection.
	ErrorKindAuth ErrorKind = "authentication"
	// ErrorKindUnavailable represents an unreachable or stopping database.
	ErrorKindUnavailable ErrorKind = "unavailable"
	// ErrorKindQuery represents a database query failure.
	ErrorKindQuery ErrorKind = "query"
	// ErrorKindUnknown is the safe fallback category.
	ErrorKindUnknown ErrorKind = "unknown"
)

// Error wraps the driver cause while keeping Error() safe for logs and CLI
// output. Callers can use errors.Is/errors.As without printing the cause.
type Error struct {
	Operation string
	Kind      ErrorKind
	cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return "postgres operation failed"
	}
	return "postgres " + e.Operation + " failed (" + string(e.Kind) + ")"
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func wrapError(operation string, fallback ErrorKind, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Operation: operation, Kind: classify(err, fallback), cause: err}
}

func classify(err error, fallback ErrorKind) ErrorKind {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrorKindCanceled
	}

	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		if len(pgError.Code) >= 2 && pgError.Code[:2] == "28" {
			return ErrorKindAuth
		}
		switch pgError.Code {
		case "57P01", "57P02", "57P03", "08000", "08001", "08003", "08004", "08006", "08007", "08P01":
			return ErrorKindUnavailable
		default:
			return fallback
		}
	}

	var networkError net.Error
	if errors.As(err, &networkError) {
		return ErrorKindUnavailable
	}
	return fallback
}

// ErrorClass returns a bounded category for logs and metrics.
func ErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	var postgresError *Error
	if errors.As(err, &postgresError) {
		return string(postgresError.Kind)
	}
	return string(classify(err, ErrorKindUnknown))
}
