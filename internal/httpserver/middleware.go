package httpserver

import (
	"bytes"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// RequestMetrics is implemented by observability.Metrics.
type RequestMetrics interface {
	RequestStarted()
	RequestCompleted(method, route string, status int, duration time.Duration)
}

func accessLogAndMetricsMiddleware(logger *slog.Logger, metrics RequestMetrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		methodLabel := metricMethod(request.Method)
		route := routeLabel(request.URL.Path)
		if metrics != nil {
			metrics.RequestStarted()
		}

		next.ServeHTTP(recorder, request)
		duration := time.Since(started)
		if metrics != nil {
			metrics.RequestCompleted(methodLabel, route, recorder.status, duration)
		}
		if logger != nil {
			logger.InfoContext(request.Context(), "http request completed",
				slog.String("request_id", RequestID(request.Context())),
				slog.String("method", request.Method),
				slog.String("route", route),
				slog.Int("status", recorder.status),
				slog.Float64("duration_ms", float64(duration.Microseconds())/1000),
			)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}

func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func routeLabel(path string) string {
	switch path {
	case "/health/live", "/health/ready", "/metrics", "/login", "/register", "/logout", "/auth/complete",
		"/api/v1/me", "/api/v1/me/sessions", "/api/v1/me/sessions/revoke-others",
		"/api/admin/v1/me", "/api/admin/v1/users", "/api/admin/v1/clients",
		"/api/admin/v1/sessions", "/api/admin/v1/audit-events":
		return path
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 6 && strings.Join(parts[:4], "/") == "api/v1/me/sessions" && parts[5] == "revoke" {
		return "/api/v1/me/sessions/{id}/revoke"
	}
	if len(parts) == 5 && strings.Join(parts[:4], "/") == "api/admin/v1/users" {
		return "/api/admin/v1/users/{id}"
	}
	if len(parts) == 6 && strings.Join(parts[:4], "/") == "api/admin/v1/users" && parts[5] == "revoke-sessions" {
		return "/api/admin/v1/users/{id}/revoke-sessions"
	}
	if len(parts) == 5 && strings.Join(parts[:4], "/") == "api/admin/v1/clients" {
		return "/api/admin/v1/clients/{id}"
	}
	if len(parts) == 7 && strings.Join(parts[:4], "/") == "api/admin/v1/clients" && parts[5] == "secrets" && parts[6] == "rotate" {
		return "/api/admin/v1/clients/{id}/secrets/rotate"
	}
	if len(parts) == 6 && strings.Join(parts[:4], "/") == "api/admin/v1/sessions" && parts[5] == "revoke" {
		return "/api/admin/v1/sessions/{id}/revoke"
	}
	return "unmatched"
}

func recoveryMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		buffer := newBufferedResponse()
		defer func() {
			if recover() != nil {
				if logger != nil {
					logger.ErrorContext(request.Context(), "panic recovered",
						slog.String("request_id", RequestID(request.Context())),
						slog.String("stack", string(debug.Stack())),
					)
				}
				setSecurityHeaders(writer.Header())
				writeError(writer, request, http.StatusInternalServerError, "internal_error", "internal server error")
				return
			}
			buffer.flushTo(writer)
		}()
		next.ServeHTTP(buffer, request)
	})
}

type bufferedResponse struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (r *bufferedResponse) Header() http.Header {
	return r.header
}

func (r *bufferedResponse) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
}

func (r *bufferedResponse) Write(body []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(body)
}

func (r *bufferedResponse) flushTo(writer http.ResponseWriter) {
	for key, values := range r.header {
		writer.Header().Del(key)
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(r.status)
	_, _ = writer.Write(r.body.Bytes())
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(writer.Header())
		next.ServeHTTP(writer, request)
	})
}

func setSecurityHeaders(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Cache-Control", "no-store")
	// Account/admin APIs are same-origin only; intentionally emit no CORS opt-in.
	header.Del("Access-Control-Allow-Origin")
}

func headerContainsToken(header http.Header, key, token string) bool {
	for _, value := range header.Values(key) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}
