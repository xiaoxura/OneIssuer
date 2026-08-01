package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/httpserver"
)

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
