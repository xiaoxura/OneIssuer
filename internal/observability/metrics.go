package observability

import (
	"strconv"
	"time"

	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// DatabasePoolStats is a privacy-safe snapshot of pgxpool state.
type DatabasePoolStats struct {
	Max          int32
	Total        int32
	Idle         int32
	Acquired     int32
	Constructing int32
}

// Metrics owns OneIssuer's private Prometheus registry and instruments only
// bounded labels.
type Metrics struct {
	registry           *prometheus.Registry
	httpRequests       *prometheus.CounterVec
	httpDuration       *prometheus.HistogramVec
	inFlight           prometheus.Gauge
	readiness          prometheus.Gauge
	registrations      *prometheus.CounterVec
	logins             *prometheus.CounterVec
	passwordRehash     *prometheus.CounterVec
	sessionsCreated    *prometheus.CounterVec
	sessionsRevoked    *prometheus.CounterVec
	clientOperations   *prometheus.CounterVec
	authTransactions   *prometheus.CounterVec
	authorizations     *prometheus.CounterVec
	tokenOperations    *prometheus.CounterVec
	auditEvents        *prometheus.CounterVec
	auditWriteFailures *prometheus.CounterVec
	cleanupOperations  *prometheus.CounterVec
	cleanupRows        *prometheus.CounterVec
	cleanupDuration    *prometheus.HistogramVec
	sessionsActive     prometheus.Gauge
	rpLogout           *prometheus.CounterVec
}

// NewMetrics creates an isolated registry, including Go runtime and process
// collectors plus the bounded Phase 1 through Phase 4 application metrics.
func NewMetrics(build BuildInfo) *Metrics {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		registry: registry,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oneissuer",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total HTTP requests partitioned by bounded route and status class.",
		}, []string{"method", "route", "status_class"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "oneissuer",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency partitioned by bounded route.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "route"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "oneissuer",
			Subsystem: "http",
			Name:      "in_flight_requests",
			Help:      "Current number of in-flight HTTP requests.",
		}),
		readiness: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "oneissuer",
			Name:      "readiness_status",
			Help:      "Whether the process currently accepts readiness traffic (1 ready, 0 not ready).",
		}),
		registrations:      prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "identity", Name: "registrations_total", Help: "Identity registrations by bounded result."}, []string{"result"}),
		logins:             prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "identity", Name: "logins_total", Help: "Identity logins by bounded result."}, []string{"result"}),
		passwordRehash:     prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "identity", Name: "password_rehash_total", Help: "Password rehash operations by bounded result."}, []string{"result"}),
		sessionsCreated:    prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "sessions", Name: "created_total", Help: "Login sessions created by bounded result."}, []string{"result"}),
		sessionsRevoked:    prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "sessions", Name: "revoked_total", Help: "Login sessions revoked by bounded reason."}, []string{"reason"}),
		clientOperations:   prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "client", Name: "operations_total", Help: "Client registry operations by bounded operation and result."}, []string{"operation", "result"}),
		authTransactions:   prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "auth", Name: "transactions_total", Help: "Authorization transaction operations by bounded operation and result."}, []string{"operation", "result"}),
		authorizations:     prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "oidc", Name: "authorization_total", Help: "OIDC authorization decisions by bounded operation and result."}, []string{"operation", "result"}),
		tokenOperations:    prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "oidc", Name: "token_operations_total", Help: "OIDC Token and UserInfo operations by bounded operation and result."}, []string{"operation", "result"}),
		auditEvents:        prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "audit", Name: "events_total", Help: "Audit event appends by bounded event and result."}, []string{"event", "result"}),
		auditWriteFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "audit", Name: "write_failures_total", Help: "Failed audit append operations by bounded event."}, []string{"event"}),
		cleanupOperations:  prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "cleanup", Name: "operations_total", Help: "Cleanup operations by bounded operation and result."}, []string{"operation", "result"}),
		cleanupRows:        prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "cleanup", Name: "rows_total", Help: "Rows committed by bounded cleanup operations, including partial progress before a later failure."}, []string{"operation"}),
		cleanupDuration:    prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: "oneissuer", Subsystem: "cleanup", Name: "duration_seconds", Help: "Cleanup operation duration by bounded operation.", Buckets: prometheus.DefBuckets}, []string{"operation"}),
		sessionsActive:     prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "oneissuer", Subsystem: "sessions", Name: "active", Help: "Current active, unexpired login sessions."}),
		rpLogout:           prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "rp_logout", Name: "total", Help: "RP-Initiated Logout outcomes by bounded result."}, []string{"result"}),
	}

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "oneissuer",
		Name:      "build_info",
		Help:      "Static OneIssuer build information.",
	}, []string{"version", "commit", "build_time", "go_version"})
	buildInfo.WithLabelValues(build.Version, build.Commit, build.BuildTime, build.GoVersion).Set(1)

	// Pre-initialize the phase-three protocol matrix. CounterVec collectors do
	// not expose a metric family until at least one label set has been observed;
	// creating every bounded combination here makes a freshly started process
	// observable without manufacturing protocol traffic first.
	for _, operation := range []string{"issue", "deny"} {
		for _, result := range []string{"success", "rejected", "failure"} {
			metrics.authorizations.WithLabelValues(operation, result).Add(0)
		}
	}
	for _, operation := range []string{"exchange", "issuance", "refresh", "revoke", "introspect", "userinfo"} {
		for _, result := range []string{"success", "rejected", "failure", "active", "inactive"} {
			metrics.tokenOperations.WithLabelValues(operation, result).Add(0)
		}
	}
	for _, result := range []string{"started", "confirmable", "confirmed", "canceled", "capacity", "invalid", "rejected", "failure"} {
		metrics.rpLogout.WithLabelValues(result).Add(0)
	}
	for _, operation := range []string{"sessions", "auth_transactions", "protocol_artifacts", "refresh_artifacts", "logout_transactions", "active_sessions"} {
		for _, result := range []string{"success", "failure", "canceled"} {
			metrics.cleanupOperations.WithLabelValues(operation, result).Add(0)
		}
		metrics.cleanupRows.WithLabelValues(operation).Add(0)
		metrics.cleanupDuration.WithLabelValues(operation)
	}

	registry.MustRegister(
		buildInfo,
		metrics.httpRequests,
		metrics.httpDuration,
		metrics.inFlight,
		metrics.readiness,
		metrics.registrations,
		metrics.logins,
		metrics.passwordRehash,
		metrics.sessionsCreated,
		metrics.sessionsRevoked,
		metrics.clientOperations,
		metrics.authTransactions,
		metrics.authorizations,
		metrics.tokenOperations,
		metrics.auditEvents,
		metrics.auditWriteFailures,
		metrics.cleanupOperations,
		metrics.cleanupRows,
		metrics.cleanupDuration,
		metrics.sessionsActive,
		metrics.rpLogout,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return metrics
}

func bounded(value string, allowed map[string]bool) string {
	if allowed[value] {
		return value
	}
	return "other"
}

var resultLabels = map[string]bool{"success": true, "rejected": true, "failure": true}

// IdentityRegistration implements authn.Metrics with a fixed result enum.
func (m *Metrics) IdentityRegistration(result string) {
	m.registrations.WithLabelValues(bounded(result, resultLabels)).Inc()
}

// IdentityLogin records a bounded login outcome.
func (m *Metrics) IdentityLogin(result string) {
	m.logins.WithLabelValues(bounded(result, resultLabels)).Inc()
}

// PasswordRehash records a bounded password-rehash outcome.
func (m *Metrics) PasswordRehash(result string) {
	m.passwordRehash.WithLabelValues(bounded(result, resultLabels)).Inc()
}

// SessionCreated records a bounded session-creation outcome.
func (m *Metrics) SessionCreated(result string) {
	m.sessionsCreated.WithLabelValues(bounded(result, resultLabels)).Inc()
}

// SessionRevoked records a bounded revocation reason.
func (m *Metrics) SessionRevoked(reason string) {
	m.sessionsRevoked.WithLabelValues(bounded(reason, map[string]bool{
		"logout": true, "user": true, "others": true, "admin": true,
		"user_disabled": true, "role_changed": true, "rotation": true, "expired": true,
	})).Inc()
}

// ClientOperation records bounded client-registry labels.
func (m *Metrics) ClientOperation(operation, result string) {
	m.clientOperations.WithLabelValues(
		bounded(operation, map[string]bool{"create": true, "update": true, "rotate_secret": true, "validate_secret": true}),
		bounded(result, resultLabels),
	).Inc()
}

// AuthTransaction records bounded authorization-transaction labels.
func (m *Metrics) AuthTransaction(operation, result string) {
	m.authTransactions.WithLabelValues(
		bounded(operation, map[string]bool{"create": true, "resolve": true, "consume": true, "reject": true, "expire": true, "cleanup": true}),
		bounded(result, resultLabels),
	).Inc()
}

// Authorization records bounded consent/Code issuance outcomes.
func (m *Metrics) Authorization(operation, result string) {
	m.authorizations.WithLabelValues(
		bounded(operation, map[string]bool{"issue": true, "deny": true}),
		bounded(result, resultLabels),
	).Inc()
}

// Token records bounded Code exchange, committed issuance, and UserInfo
// outcomes. No Client, Subject, scope, kid, jti, or error value is a label.
func (m *Metrics) Token(operation, result string) {
	m.tokenOperations.WithLabelValues(
		bounded(operation, map[string]bool{"exchange": true, "issuance": true, "refresh": true, "revoke": true, "introspect": true, "userinfo": true}),
		bounded(result, map[string]bool{"success": true, "rejected": true, "failure": true, "active": true, "inactive": true}),
	).Inc()
}

// RPLogout records only the fixed hosted-flow outcome vocabulary.
func (m *Metrics) RPLogout(result string) {
	m.rpLogout.WithLabelValues(bounded(result, map[string]bool{
		"started": true, "confirmable": true, "confirmed": true, "canceled": true,
		"capacity": true, "invalid": true, "rejected": true, "failure": true,
	})).Inc()
}

// AuditEvent records bounded audit-event labels.
func (m *Metrics) AuditEvent(event, result string) {
	event = boundedAuditEvent(event)
	m.auditEvents.WithLabelValues(
		event, bounded(result, resultLabels),
	).Inc()
}

// AuditWriteFailure records an append failure even when a rejected request is
// deliberately allowed to return its uniform authentication error.
func (m *Metrics) AuditWriteFailure(event string) {
	m.auditWriteFailures.WithLabelValues(boundedAuditEvent(event)).Inc()
}

func boundedAuditEvent(event string) string {
	if event == "" || !audit.ValidEventType(event) {
		return "other"
	}
	return event
}

// Cleanup records one independently bounded cleanup operation. Rows are added
// only when at least one batch committed; a later deadline may therefore report
// both progress and a failure result without losing that progress.
func (m *Metrics) Cleanup(operation, result string, rows int64, duration time.Duration) {
	operation = bounded(operation, map[string]bool{
		"sessions": true, "auth_transactions": true, "protocol_artifacts": true,
		"refresh_artifacts": true, "logout_transactions": true, "active_sessions": true,
	})
	result = bounded(result, map[string]bool{"success": true, "failure": true, "canceled": true})
	m.cleanupOperations.WithLabelValues(operation, result).Inc()
	if rows > 0 {
		m.cleanupRows.WithLabelValues(operation).Add(float64(rows))
	}
	m.cleanupDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// SetActiveSessions updates the active session gauge.
func (m *Metrics) SetActiveSessions(count int64) { m.sessionsActive.Set(float64(count)) }

// Gatherer exposes the registry without using prometheus.DefaultGatherer.
func (m *Metrics) Gatherer() prometheus.Gatherer {
	return m.registry
}

// RequestStarted increments the in-flight request count.
func (m *Metrics) RequestStarted() {
	m.inFlight.Inc()
}

// RequestCompleted records one request using pre-sanitized, bounded labels.
func (m *Metrics) RequestCompleted(method, route string, status int, duration time.Duration) {
	m.inFlight.Dec()
	statusClass := strconv.Itoa(status/100) + "xx"
	m.httpRequests.WithLabelValues(method, route, statusClass).Inc()
	m.httpDuration.WithLabelValues(method, route).Observe(duration.Seconds())
}

// SetReady updates the process readiness gauge.
func (m *Metrics) SetReady(ready bool) {
	if ready {
		m.readiness.Set(1)
		return
	}
	m.readiness.Set(0)
}

// RegisterDatabasePool exports bounded pgxpool state labels. The callback is
// sampled during each scrape and must not perform I/O.
func (m *Metrics) RegisterDatabasePool(snapshot func() DatabasePoolStats) error {
	return m.registry.Register(newDatabasePoolCollector(snapshot))
}

type databasePoolCollector struct {
	description *prometheus.Desc
	snapshot    func() DatabasePoolStats
}

func newDatabasePoolCollector(snapshot func() DatabasePoolStats) *databasePoolCollector {
	return &databasePoolCollector{
		description: prometheus.NewDesc(
			"oneissuer_database_pool_connections",
			"PostgreSQL connection pool state.",
			[]string{"state"},
			nil,
		),
		snapshot: snapshot,
	}
}

func (c *databasePoolCollector) Describe(channel chan<- *prometheus.Desc) {
	channel <- c.description
}

func (c *databasePoolCollector) Collect(channel chan<- prometheus.Metric) {
	if c.snapshot == nil {
		return
	}
	stats := c.snapshot()
	for state, value := range map[string]int32{
		"max":          stats.Max,
		"total":        stats.Total,
		"idle":         stats.Idle,
		"acquired":     stats.Acquired,
		"constructing": stats.Constructing,
	} {
		channel <- prometheus.MustNewConstMetric(c.description, prometheus.GaugeValue, float64(value), state)
	}
}
