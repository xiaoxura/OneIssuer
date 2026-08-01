package observability

import (
	"strconv"
	"time"

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
	registry         *prometheus.Registry
	httpRequests     *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	inFlight         prometheus.Gauge
	readiness        prometheus.Gauge
	registrations    *prometheus.CounterVec
	logins           *prometheus.CounterVec
	passwordRehash   *prometheus.CounterVec
	sessionsCreated  *prometheus.CounterVec
	sessionsRevoked  *prometheus.CounterVec
	clientOperations *prometheus.CounterVec
	authTransactions *prometheus.CounterVec
	authorizations   *prometheus.CounterVec
	tokenOperations  *prometheus.CounterVec
	auditEvents      *prometheus.CounterVec
	sessionsActive   prometheus.Gauge
}

// NewMetrics creates an isolated registry, including Go runtime and process
// collectors plus the phase-one through phase-three application metrics.
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
		registrations:    prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "identity", Name: "registrations_total", Help: "Identity registrations by bounded result."}, []string{"result"}),
		logins:           prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "identity", Name: "logins_total", Help: "Identity logins by bounded result."}, []string{"result"}),
		passwordRehash:   prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "identity", Name: "password_rehash_total", Help: "Password rehash operations by bounded result."}, []string{"result"}),
		sessionsCreated:  prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "sessions", Name: "created_total", Help: "Login sessions created by bounded result."}, []string{"result"}),
		sessionsRevoked:  prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "sessions", Name: "revoked_total", Help: "Login sessions revoked by bounded reason."}, []string{"reason"}),
		clientOperations: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "client", Name: "operations_total", Help: "Client registry operations by bounded operation and result."}, []string{"operation", "result"}),
		authTransactions: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "auth", Name: "transactions_total", Help: "Authorization transaction operations by bounded operation and result."}, []string{"operation", "result"}),
		authorizations:   prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "oidc", Name: "authorization_total", Help: "OIDC authorization decisions by bounded operation and result."}, []string{"operation", "result"}),
		tokenOperations:  prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "oidc", Name: "token_operations_total", Help: "OIDC Token and UserInfo operations by bounded operation and result."}, []string{"operation", "result"}),
		auditEvents:      prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "oneissuer", Subsystem: "audit", Name: "events_total", Help: "Audit event appends by bounded event and result."}, []string{"event", "result"}),
		sessionsActive:   prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "oneissuer", Subsystem: "sessions", Name: "active", Help: "Current active, unexpired login sessions."}),
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
	for _, operation := range []string{"exchange", "issuance", "userinfo"} {
		for _, result := range []string{"success", "rejected", "failure"} {
			metrics.tokenOperations.WithLabelValues(operation, result).Add(0)
		}
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
		metrics.sessionsActive,
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
		bounded(operation, map[string]bool{"exchange": true, "issuance": true, "userinfo": true}),
		bounded(result, resultLabels),
	).Inc()
}

// AuditEvent records bounded audit-event labels.
func (m *Metrics) AuditEvent(event, result string) {
	m.auditEvents.WithLabelValues(
		bounded(event, map[string]bool{
			"admin_bootstrap": true, "user": true, "login": true, "session": true,
			"client": true, "auth_transaction": true,
		}), bounded(result, resultLabels),
	).Inc()
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
