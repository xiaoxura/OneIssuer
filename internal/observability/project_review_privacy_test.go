package observability

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"

	"github.com/oneissuer/oneissuer/internal/config"
)

func TestProjectReviewNonStructuredLogsRedactPhaseFourCredentialsAtBoundaries(t *testing.T) {
	t.Parallel()

	r1 := projectReviewOpaque(t, "r1_")
	lookup := projectReviewOpaque(t, "lt1_")
	csrf := projectReviewOpaque(t, "lc1_")
	message := "start=" + r1 + "|" + lookup + "/" + csrf + "=end"

	var output bytes.Buffer
	logger := NewLogger(&output, config.LogConfig{Level: config.LogLevelDebug, Format: config.LogFormatText})
	logger.Info(message, slog.String("non_sensitive_context", "adjacent:"+r1+":"+lookup+":"+csrf))
	logger.Error("operation failed", slog.Any("err", projectReviewError{message: "wrapped " + message}))

	line := output.String()
	for _, test := range []struct {
		name       string
		credential string
	}{{"refresh", r1}, {"logout lookup", lookup}, {"logout csrf", csrf}} {
		if strings.Contains(line, test.credential) {
			t.Fatalf("non-structured log leaked generated %s credential", test.name)
		}
	}
	if strings.Count(line, "[REDACTED]") < 6 {
		t.Fatalf("expected message, attribute, and error credentials to be redacted")
	}
}

func TestProjectReviewMetricsDoNotExposeActiveRefreshFamilyGauge(t *testing.T) {
	t.Parallel()

	families, err := NewMetrics(NewBuildInfo("test", "commit", "now")).Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		name := strings.ToLower(family.GetName())
		if strings.Contains(name, "active") && (strings.Contains(name, "refresh") || strings.Contains(name, "famil")) {
			t.Fatalf("stale active refresh-family metric is still registered: %q", family.GetName())
		}
	}
}

func projectReviewOpaque(t *testing.T, prefix string) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}

type projectReviewError struct{ message string }

func (e projectReviewError) Error() string { return e.message }
