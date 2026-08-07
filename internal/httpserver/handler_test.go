package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type fakePinger struct {
	err atomic.Value
}

type pingError struct{ message string }

func (e *pingError) Error() string { return e.message }

func (p *fakePinger) Ping(context.Context) error {
	value := p.err.Load()
	if value == nil {
		return nil
	}
	return value.(error)
}

func (p *fakePinger) setError(err error) {
	if err == nil {
		p.err.Store(error(&pingError{}))
		return
	}
	p.err.Store(err)
}

func testHandler(t *testing.T, ready bool, pinger Pinger) (http.Handler, *observability.Metrics, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	logger := observability.NewLogger(logs, config.LogConfig{Level: config.LogLevelDebug, Format: config.LogFormatJSON})
	metrics := observability.NewMetrics(observability.NewBuildInfo("test", "test", "test"))
	readiness := NewReadiness(metrics.SetReady)
	readiness.Set(ready)
	return NewHandler(HandlerOptions{
		Logger:             logger,
		Readiness:          readiness,
		Database:           pinger,
		DatabaseErrorClass: func(error) string { return "unavailable" },
		Metrics:            metrics,
		Gatherer:           metrics.Gatherer(),
	}), metrics, logs
}

func TestHealthContractsAndRequestIDs(t *testing.T) {
	t.Parallel()

	handler, _, _ := testHandler(t, true, &fakePinger{})
	tests := []struct {
		name       string
		method     string
		path       string
		requestID  string
		wantStatus int
		wantBody   string
	}{
		{"live", http.MethodGet, "/health/live", "external-123", http.StatusOK, `{"status":"ok"}`},
		{"ready", http.MethodGet, "/health/ready", "", http.StatusOK, `{"status":"ready"}`},
		{"unknown", http.MethodGet, "/not/implemented", "", http.StatusNotFound, `"code":"not_found"`},
		{"method", http.MethodPost, "/health/live", "", http.StatusMethodNotAllowed, `"code":"method_not_allowed"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(test.method, test.path, nil)
			if test.requestID != "" {
				request.Header.Set(requestIDHeader, test.requestID)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if !strings.Contains(strings.TrimSpace(response.Body.String()), test.wantBody) {
				t.Fatalf("body = %q, want containing %q", response.Body.String(), test.wantBody)
			}
			gotRequestID := response.Header().Get(requestIDHeader)
			if !ValidRequestID(gotRequestID) {
				t.Fatalf("response request ID is invalid: %q", gotRequestID)
			}
			if test.requestID != "" && gotRequestID != test.requestID {
				t.Fatalf("request ID = %q, want propagated %q", gotRequestID, test.requestID)
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" ||
				response.Header().Get("Referrer-Policy") != "same-origin" {
				t.Fatalf("security headers are missing or browser-form incompatible: %v", response.Header())
			}
			if test.name == "method" && !headerContainsToken(response.Header(), "Allow", http.MethodGet) {
				t.Fatal("405 response is missing Allow: GET")
			}
		})
	}
}

func TestInvalidRequestIDsAreReplaced(t *testing.T) {
	t.Parallel()

	handler, _, _ := testHandler(t, true, &fakePinger{})
	for _, invalid := range []string{"contains spaces", strings.Repeat("a", 129), "bad/header", ""} {
		request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
		request.Header.Set(requestIDHeader, invalid)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		got := response.Header().Get(requestIDHeader)
		if !ValidRequestID(got) || got == invalid {
			t.Errorf("invalid request ID %q was not replaced: %q", invalid, got)
		}
	}
}

func TestFormActionPolicyKeepsSelfAndOnlyValidHTTPOrigins(t *testing.T) {
	t.Parallel()
	header := make(http.Header)
	setFormActionPolicy(header,
		"https://client.example.test/callback",
		"javascript:alert(1)",
		"https://client.example.test/other",
		"http://user:pass@client.example.test/callback",
	)
	policy := header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "form-action 'self' https://client.example.test") {
		t.Fatalf("valid callback origin missing from CSP: %q", policy)
	}
	if strings.Contains(policy, "javascript:") || strings.Contains(policy, "user:pass") || strings.Count(policy, "https://client.example.test") != 1 {
		t.Fatalf("invalid or duplicate form action source in CSP: %q", policy)
	}
}

func TestReadyFailureDoesNotAffectLiveOrLeakCause(t *testing.T) {
	t.Parallel()

	pinger := &fakePinger{}
	pinger.setError(errors.New("database db.internal user alice secret-password"))
	handler, _, logs := testHandler(t, true, pinger)

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d, want 503", ready.Code)
	}
	if strings.Contains(ready.Body.String(), "db.internal") || strings.Contains(logs.String(), "secret-password") {
		t.Fatalf("readiness leaked internal cause; body=%s logs=%s", ready.Body, logs)
	}
	var body statusResponse
	if err := json.Unmarshal(ready.Body.Bytes(), &body); err != nil || body.Status != "unavailable" || body.RequestID == "" {
		t.Fatalf("unexpected ready body: %s (%v)", ready.Body, err)
	}

	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("live status = %d, want 200", live.Code)
	}
}

func TestNotReadySkipsDatabase(t *testing.T) {
	t.Parallel()

	called := &atomic.Bool{}
	pinger := pingerFunc(func(context.Context) error {
		called.Store(true)
		return nil
	})
	handler, _, _ := testHandler(t, false, pinger)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable || called.Load() {
		t.Fatalf("status=%d database_called=%v", response.Code, called.Load())
	}
}

type pingerFunc func(context.Context) error

func (f pingerFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestPanicRecoveryDoesNotLeakPanicValue(t *testing.T) {
	t.Parallel()

	const secret = "panic-secret-value"
	logs := &bytes.Buffer{}
	logger := observability.NewLogger(logs, config.LogConfig{Level: config.LogLevelDebug, Format: config.LogFormatJSON})
	handler := requestIDMiddleware(recoveryMiddleware(logger, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(secret)
	})))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"code":"internal_error"`) {
		t.Fatalf("unexpected panic response: %d %s", response.Code, response.Body)
	}
	if strings.Contains(response.Body.String(), secret) || strings.Contains(logs.String(), secret) {
		t.Fatalf("panic secret leaked; body=%s logs=%s", response.Body, logs)
	}
	if strings.Contains(logs.String(), "stack") || strings.Contains(logs.String(), secret) {
		t.Fatalf("panic recovery log leaked stack or panic value: %s", logs.String())
	}
}

func TestMetricsAreParseableAndUseBoundedRoute(t *testing.T) {
	t.Parallel()

	handler, _, _ := testHandler(t, true, &fakePinger{})
	unmatched := httptest.NewRecorder()
	handler.ServeHTTP(unmatched, httptest.NewRequest("CUSTOM-VERB", "/users/private-email@example.test", nil))

	metricsResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("metrics status = %d: %s", metricsResponse.Code, metricsResponse.Body)
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(metricsResponse.Body.String()))
	if err != nil {
		t.Fatalf("metrics parser error = %v", err)
	}
	if families["oneissuer_http_requests_total"] == nil {
		t.Fatal("required request metric is missing")
	}
	if strings.Contains(metricsResponse.Body.String(), "private-email") {
		t.Fatal("raw URL appeared in metrics")
	}
	if !strings.Contains(metricsResponse.Body.String(), `method="OTHER",route="unmatched",status_class="4xx"`) {
		t.Fatalf("bounded unmatched labels missing: %s", metricsResponse.Body)
	}
}

func TestTrustedProxyParsing(t *testing.T) {
	t.Parallel()

	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	var captured ProxyInfo
	handler := trustedProxyMiddleware(trusted, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		captured = RequestProxyInfo(request.Context())
		writer.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.2:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.3")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "id.example.test")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !captured.Trusted || captured.ClientIP.String() != "203.0.113.9" || captured.Scheme != "https" || captured.Host != "id.example.test" {
		t.Fatalf("unexpected trusted proxy info: %#v", captured)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if captured.Trusted || captured.ClientIP.String() != "192.0.2.10" {
		t.Fatalf("untrusted peer header took effect: %#v", captured)
	}
}

func TestReadinessPingHasIndependentTimeout(t *testing.T) {
	t.Parallel()

	logs := io.Discard
	logger := slog.New(slog.NewTextHandler(logs, nil))
	readiness := NewReadiness(nil)
	readiness.Set(true)
	handler := NewHandler(HandlerOptions{
		Logger:    logger,
		Readiness: readiness,
		Database: pingerFunc(func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}),
		ReadinessTimeout: 10 * time.Millisecond,
	})

	started := time.Now()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable || time.Since(started) > time.Second {
		t.Fatalf("readiness timeout contract failed: status=%d duration=%s", response.Code, time.Since(started))
	}
}
