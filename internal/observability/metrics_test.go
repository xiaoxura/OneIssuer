package observability

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsExposeRequiredFamilies(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics(NewBuildInfo("test", "commit", "now"))
	metrics.RequestStarted()
	metrics.RequestCompleted("GET", "/health/live", 200, 10*time.Millisecond)
	metrics.SetReady(true)
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
	} {
		if !found[name] {
			t.Errorf("metric family %q is missing", name)
		}
	}
	if value := testutil.ToFloat64(metrics.readiness); value != 1 {
		t.Fatalf("readiness gauge = %v, want 1", value)
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
		"oneissuer_oidc_token_operations_total": 3 * 3,
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
