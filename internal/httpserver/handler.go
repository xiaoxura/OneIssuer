// Package httpserver implements OneIssuer's health, metrics, authentication,
// account, administration, request middleware, and bounded net/http contracts.
package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const defaultReadinessTimeout = time.Second

// Pinger is the only database behavior needed by HTTP readiness.
type Pinger interface {
	Ping(context.Context) error
}

// HandlerOptions contains the concrete dependencies for OneIssuer HTTP routes.
type HandlerOptions struct {
	Logger             *slog.Logger
	Readiness          *Readiness
	Database           Pinger
	DatabaseErrorClass func(error) string
	Metrics            RequestMetrics
	Gatherer           prometheus.Gatherer
	TrustedProxies     []netip.Prefix
	ReadinessTimeout   time.Duration
	Application        http.Handler
}

// NewHandler builds middleware in the documented outer-to-inner order:
// request ID, trusted proxy, access log/metrics, panic recovery, security
// headers, then the router.
func NewHandler(options HandlerOptions) http.Handler {
	if options.Readiness == nil {
		options.Readiness = NewReadiness(nil)
	}
	if options.ReadinessTimeout <= 0 {
		options.ReadinessTimeout = defaultReadinessTimeout
	}
	if options.Gatherer == nil {
		options.Gatherer = prometheus.NewRegistry()
	}

	router := &router{
		logger:             options.Logger,
		readiness:          options.Readiness,
		database:           options.Database,
		databaseErrorClass: options.DatabaseErrorClass,
		readinessTimeout:   options.ReadinessTimeout,
		metricsHandler: promhttp.HandlerFor(options.Gatherer, promhttp.HandlerOpts{
			ErrorHandling: promhttp.HTTPErrorOnError,
		}),
		application: options.Application,
	}

	var handler http.Handler = router
	handler = securityHeadersMiddleware(handler)
	handler = recoveryMiddleware(options.Logger, handler)
	handler = accessLogAndMetricsMiddleware(options.Logger, options.Metrics, handler)
	handler = trustedProxyMiddleware(options.TrustedProxies, handler)
	handler = requestIDMiddleware(handler)
	return handler
}

type router struct {
	logger             *slog.Logger
	readiness          *Readiness
	database           Pinger
	databaseErrorClass func(error) string
	readinessTimeout   time.Duration
	metricsHandler     http.Handler
	application        http.Handler
}

func (r *router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/health/live":
		if !requireGET(writer, request) {
			return
		}
		writeJSON(writer, http.StatusOK, statusResponse{Status: "ok"})
	case "/health/ready":
		if !requireGET(writer, request) {
			return
		}
		r.ready(writer, request)
	case "/metrics":
		if !requireGET(writer, request) {
			return
		}
		r.metricsHandler.ServeHTTP(writer, request)
	default:
		if r.application != nil {
			r.application.ServeHTTP(writer, request)
			return
		}
		writeError(writer, request, http.StatusNotFound, "not_found", "resource not found")
	}
}

func requireGET(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet {
		return true
	}
	writer.Header().Set("Allow", http.MethodGet)
	writeError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	return false
}

func (r *router) ready(writer http.ResponseWriter, request *http.Request) {
	requestID := RequestID(request.Context())
	if !r.readiness.IsReady() || r.database == nil {
		writeJSON(writer, http.StatusServiceUnavailable, statusResponse{Status: "unavailable", RequestID: requestID})
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), r.readinessTimeout)
	defer cancel()
	if err := r.database.Ping(ctx); err != nil {
		errorClass := "unknown"
		if r.databaseErrorClass != nil {
			errorClass = r.databaseErrorClass(err)
		}
		if r.logger != nil {
			r.logger.WarnContext(request.Context(), "readiness dependency check failed",
				slog.String("request_id", requestID),
				slog.String("dependency", "database"),
				slog.String("error_class", errorClass),
			)
		}
		writeJSON(writer, http.StatusServiceUnavailable, statusResponse{Status: "unavailable", RequestID: requestID})
		return
	}
	writeJSON(writer, http.StatusOK, statusResponse{Status: "ready"})
}
