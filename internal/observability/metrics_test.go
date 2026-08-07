package observability

import (
	"testing"
	"time"

	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsExposeRequiredFamilies(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics(NewBuildInfo("test", "commit", "now"))
	metrics.RequestStarted()
	metrics.RequestCompleted("GET", "/health/live", 200, 10*time.Millisecond)
	metrics.SetReady(true)
	metrics.AuditEvent(string(audit.SigningKeyLoaded), string(audit.ResultSuccess))
	metrics.AuditWriteFailure(string(audit.LoginFailed))
	metrics.Cleanup("sessions", "failure", 250, 20*time.Millisecond)
	if err := metrics.RegisterDatabasePool(func() DatabasePoolStats {
		return DatabasePoolStats{Max: 10, Total: 2, Idle: 1, Acquired: 1}
	}); err != nil {
		t.Fatalf("RegisterDatabasePool() error = %v", err)
	}

	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	found := make(map[string]bool, len(families))
	for _, family := range families {
		found[family.GetName()] = true
	}
	for _, name := range []string{
		"oneissuer_build_info",
		"oneissuer_http_requests_total",
		"oneissuer_http_request_duration_seconds",
		"oneissuer_http_in_flight_requests",
		"oneissuer_database_pool_connections",
		"oneissuer_readiness_status",
		"oneissuer_oidc_authorization_total",
		"oneissuer_oidc_token_operations_total",
		"oneissuer_audit_events_total",
		"oneissuer_audit_write_failures_total",
		"oneissuer_cleanup_operations_total",
		"oneissuer_cleanup_rows_total",
		"oneissuer_cleanup_duration_seconds",
	} {
		if !found[name] {
			t.Errorf("metric family %q is missing", name)
		}
	}
	if value := testutil.ToFloat64(metrics.readiness); value != 1 {
		t.Fatalf("readiness gauge = %v, want 1", value)
	}
}

func TestAuditAndCleanupMetricsUseFixedLabelsAndRetainPartialProgress(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics(NewBuildInfo("test", "commit", "now"))
	metrics.AuditEvent(string(audit.LoginFailed), string(audit.ResultRejected))
	metrics.AuditEvent("client-controlled-event", "client-controlled-result")
	metrics.AuditWriteFailure(string(audit.LoginFailed))
	metrics.AuditWriteFailure("client-controlled-event")
	metrics.Cleanup("sessions", "failure", 250, time.Second)
	metrics.Cleanup("refresh_artifacts", "success", 3, time.Second)
	metrics.Cleanup("logout_transactions", "canceled", 0, time.Second)
	metrics.Cleanup("client-controlled-operation", "client-controlled-result", -1, time.Millisecond)

	if got := testutil.ToFloat64(metrics.auditEvents.WithLabelValues(string(audit.LoginFailed), "rejected")); got != 1 {
		t.Fatalf("login audit counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.auditEvents.WithLabelValues("other", "other")); got != 1 {
		t.Fatalf("folded audit counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.auditWriteFailures.WithLabelValues(string(audit.LoginFailed))); got != 1 {
		t.Fatalf("audit write failure counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.auditWriteFailures.WithLabelValues("other")); got != 1 {
		t.Fatalf("folded audit write failure counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupOperations.WithLabelValues("sessions", "failure")); got != 1 {
		t.Fatalf("cleanup failure counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupRows.WithLabelValues("sessions")); got != 250 {
		t.Fatalf("partial cleanup row counter = %v, want 250", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupRows.WithLabelValues("other")); got != 0 {
		t.Fatalf("negative row count changed the counter: %v", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupOperations.WithLabelValues("refresh_artifacts", "success")); got != 1 {
		t.Fatalf("refresh cleanup operation counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupRows.WithLabelValues("refresh_artifacts")); got != 3 {
		t.Fatalf("refresh cleanup rows = %v, want 3", got)
	}
	if got := testutil.ToFloat64(metrics.cleanupOperations.WithLabelValues("logout_transactions", "canceled")); got != 1 {
		t.Fatalf("logout cleanup operation counter = %v, want 1", got)
	}
}

func TestMetricsPreinitializeBoundedOIDCMatrix(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics(NewBuildInfo("test", "commit", "now"))
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	wantSeries := map[string]int{
		"oneissuer_oidc_authorization_total":    2 * 3,
		"oneissuer_oidc_token_operations_total": 6 * 5,
	}
	for _, family := range families {
		want, ok := wantSeries[family.GetName()]
		if !ok {
			continue
		}
		if got := len(family.GetMetric()); got != want {
			t.Errorf("metric family %q has %d series, want %d", family.GetName(), got, want)
		}
		delete(wantSeries, family.GetName())
	}
	for name := range wantSeries {
		t.Errorf("metric family %q is missing before protocol traffic", name)
	}
}

func TestOIDCMetricsFoldUnrecognizedLabelsWithoutLeakingInput(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics(NewBuildInfo("test", "commit", "now"))
	const operationCanary = "client-controlled-operation-canary"
	const resultCanary = "client-controlled-result-canary"
	metrics.Authorization(operationCanary, resultCanary)
	metrics.Token(operationCanary, resultCanary)

	if value := testutil.ToFloat64(metrics.authorizations.WithLabelValues("other", "other")); value != 1 {
		t.Fatalf("folded authorization counter = %v, want 1", value)
	}
	if value := testutil.ToFloat64(metrics.tokenOperations.WithLabelValues("other", "other")); value != 1 {
		t.Fatalf("folded token counter = %v, want 1", value)
	}
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetValue() == operationCanary || label.GetValue() == resultCanary {
					t.Fatalf("metric %q leaked a client-controlled label: %s=%q", family.GetName(), label.GetName(), label.GetValue())
				}
			}
		}
	}
}
