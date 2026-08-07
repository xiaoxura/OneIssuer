package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/httpserver"
	"github.com/oneissuer/oneissuer/internal/observability"
)

func TestServeFailsClosedOnSigningKeyBeforeDatabaseOrListener(t *testing.T) {
	t.Parallel()

	privatePath := filepath.Join(t.TempDir(), "must-not-appear-in-error.jwk")
	cfg := config.Config{
		OIDC:     config.OIDCConfig{SigningKeyFile: privatePath},
		Database: config.DatabaseConfig{URL: config.SecretURL{}, MaxConns: 1},
	}
	err := Serve(context.Background(), cfg, observability.NewBuildInfo("", "", ""), nil)
	if err == nil || !strings.Contains(err.Error(), "signing key store startup check") {
		t.Fatalf("Serve() error = %v", err)
	}
	if strings.Contains(err.Error(), privatePath) || strings.Contains(err.Error(), "database") {
		t.Fatalf("startup check order/path safety error = %v", err)
	}
}

type startupAuditRecorder struct {
	event audit.Event
	err   error
}

func (r *startupAuditRecorder) AppendAudit(_ context.Context, event audit.Event) error {
	r.event = event
	return r.err
}

func TestAppendSigningKeyLoadedUsesValueFreeFixedEvent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 1, 9, 30, 0, 0, time.UTC)
	recorder := &startupAuditRecorder{}
	if err := appendSigningKeyLoaded(context.Background(), recorder, now); err != nil {
		t.Fatalf("appendSigningKeyLoaded() error = %v", err)
	}
	event := recorder.event
	if event.Type != audit.SigningKeyLoaded || event.Result != audit.ResultSuccess || !event.OccurredAt.Equal(now) {
		t.Fatalf("unexpected startup event: %+v", event)
	}
	if event.ActorUserID != nil || event.TargetType != nil || event.TargetID != nil || event.RequestID != "" || len(event.ChangedFields) != 0 {
		t.Fatalf("startup event contains contextual values: %+v", event)
	}
}

func TestAppendSigningKeyLoadedFailsClosedOnAuditError(t *testing.T) {
	t.Parallel()

	want := errors.New("audit unavailable")
	err := appendSigningKeyLoaded(context.Background(), &startupAuditRecorder{err: want}, time.Now())
	if !errors.Is(err, want) {
		t.Fatalf("appendSigningKeyLoaded() error = %v, want %v", err, want)
	}
}

func TestSuperviseHTTPWaitsForInflightRequestAndDisablesReadinessFirst(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var startOnce sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		startOnce.Do(func() { close(requestStarted) })
		<-releaseRequest
		writer.WriteHeader(http.StatusNoContent)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	readiness := httpserver.NewReadiness(nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- superviseHTTP(ctx, server, listener, readiness, time.Second, nil)
	}()
	waitFor(t, time.Second, readiness.IsReady, "server never became ready")

	requestResult := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String()) //nolint:noctx // test request lifetime is bounded below
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			requestErr = response.Body.Close()
		}
		requestResult <- requestErr
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}

	cancel()
	waitFor(t, time.Second, func() bool { return !readiness.IsReady() }, "readiness was not disabled")
	select {
	case err := <-result:
		t.Fatalf("shutdown completed before in-flight request: %v", err)
	default:
	}
	close(releaseRequest)
	if err := <-requestResult; err != nil {
		t.Fatalf("in-flight request failed: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("superviseHTTP() error = %v", err)
	}
}

func TestSuperviseHTTPForcesCloseAfterTimeout(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	readiness := httpserver.NewReadiness(nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- superviseHTTP(ctx, server, listener, readiness, 20*time.Millisecond, nil)
	}()
	waitFor(t, time.Second, readiness.IsReady, "server never became ready")
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String()) //nolint:noctx // force-close terminates this test request
		if response != nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		_ = requestErr
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("superviseHTTP() error = %v, want ErrShutdownTimeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown timeout was not bounded")
	}
}

func TestCleanupOperationsReceiveIndependentBoundedContexts(t *testing.T) {
	t.Parallel()

	parent := context.Background()
	firstStarted := time.Now()
	runCleanupOperation(parent, 10*time.Millisecond, "sessions", nil, nil, "unused", func(ctx context.Context) (int64, error) {
		<-ctx.Done()
		return 3, ctx.Err()
	})
	if elapsed := time.Since(firstStarted); elapsed < 5*time.Millisecond || elapsed > time.Second {
		t.Fatalf("first cleanup timeout elapsed in %s", elapsed)
	}

	secondRanWithLiveContext := false
	runCleanupOperation(parent, time.Second, "auth_transactions", nil, nil, "unused", func(ctx context.Context) (int64, error) {
		secondRanWithLiveContext = ctx.Err() == nil
		return 1, nil
	})
	if !secondRanWithLiveContext {
		t.Fatal("a later cleanup operation inherited the previous operation's canceled context")
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}
