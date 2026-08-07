package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestErrorDoesNotExposeCause(t *testing.T) {
	t.Parallel()

	secret := "postgres://alice:do-not-print@db/app"
	cause := errors.New(secret)
	err := wrapError("connect", ErrorKindUnavailable, cause)
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Error() leaked cause: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause is not available through errors.Is")
	}
}

func TestErrorClass(t *testing.T) {
	t.Parallel()

	if got := ErrorClass(context.DeadlineExceeded); got != string(ErrorKindCanceled) {
		t.Fatalf("ErrorClass(deadline) = %q", got)
	}
	if got := ErrorClass(errors.New("other")); got != string(ErrorKindUnknown) {
		t.Fatalf("ErrorClass(other) = %q", got)
	}
}

func TestExpectedVersion(t *testing.T) {
	t.Parallel()

	if got := expectedVersion(productionMigrations); got != 15 {
		t.Fatalf("expectedVersion(production) = %d", got)
	}
}

func TestRetryableTransactionError(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		code string
		want bool
	}{
		{name: "serialization failure", code: "40001", want: true},
		{name: "deadlock detected", code: "40P01", want: true},
		{name: "unique violation", code: "23505", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := &Error{Operation: "query", Kind: ErrorKindQuery, cause: &pgconn.PgError{Code: test.code}}
			if got := isRetryableTransactionError(err); got != test.want {
				t.Fatalf("isRetryableTransactionError(%s) = %v, want %v", test.code, got, test.want)
			}
		})
	}

	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := &Error{
			Operation: "query", Kind: ErrorKindCanceled,
			cause: errors.Join(cause, &pgconn.PgError{Code: "40001"}),
		}
		if got := isRetryableTransactionError(err); got {
			t.Fatalf("isRetryableTransactionError(%v) = true, want false", cause)
		}
	}
}
