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
	} {
		if !found[name] {
			t.Errorf("metric family %q is missing", name)
		}
	}
	if value := testutil.ToFloat64(metrics.readiness); value != 1 {
		t.Fatalf("readiness gauge = %v, want 1", value)
	}
}
