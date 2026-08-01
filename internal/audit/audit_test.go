package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditWhitelistRejectsSensitiveOrArbitraryFields(t *testing.T) {
	t.Parallel()
	target := uuid.New()
	if _, err := New(LoginSucceeded, ResultSuccess, nil, TargetUser, &target, "request-1", []string{"password"}, time.Now()); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("password audit field error=%v", err)
	}
	event, err := New(SessionRevoked, ResultSuccess, nil, TargetSession, &target, "request-1", []string{"revoked", "revoked"}, time.Now())
	if err != nil || len(event.ChangedFields) != 1 {
		t.Fatalf("safe event=%+v err=%v", event, err)
	}
	if _, err := New(LoginFailed, ResultRejected, nil, "", nil, "unsafe request id", nil, time.Now()); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("unsafe request ID error=%v", err)
	}
}
