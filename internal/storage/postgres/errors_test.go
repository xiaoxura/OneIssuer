package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
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

	if got := expectedVersion(productionMigrations); got != 10 {
		t.Fatalf("expectedVersion(production) = %d", got)
	}
}
