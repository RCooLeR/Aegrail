package bootstrap

import (
	"testing"
	"time"
)

func TestEnvDurationExtendedParsesDaySuffix(t *testing.T) {
	t.Setenv("AEGRAIL_TEST_RETENTION", "180d")

	got := envDurationExtended("AEGRAIL_TEST_RETENTION", time.Hour)
	want := 180 * 24 * time.Hour
	if got != want {
		t.Fatalf("envDurationExtended = %s, want %s", got, want)
	}
}

func TestLoadConfigDefaultsRetentionToSixMonths(t *testing.T) {
	t.Setenv("AEGRAIL_RETENTION_EVENTS", "")
	t.Setenv("AEGRAIL_RETENTION_RESOLVED_FINDINGS", "")
	t.Setenv("AEGRAIL_RETENTION_MODEL_REPORTS", "")
	t.Setenv("AEGRAIL_RETENTION_AUTH_EVENTS", "")

	config := LoadConfig()
	want := 180 * 24 * time.Hour
	if config.Hub.RetentionEvents != want ||
		config.Hub.RetentionResolvedFindings != want ||
		config.Hub.RetentionModelReports != want ||
		config.Hub.RetentionAuthEvents != want {
		t.Fatalf("retention defaults = events %s, resolved %s, reports %s, auth %s; want all %s",
			config.Hub.RetentionEvents,
			config.Hub.RetentionResolvedFindings,
			config.Hub.RetentionModelReports,
			config.Hub.RetentionAuthEvents,
			want,
		)
	}
}
