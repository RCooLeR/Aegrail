package postgres

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeTrafficBackfillBatchBoundsUpgradeWork(t *testing.T) {
	until := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	since, gotUntil, limit, err := normalizeTrafficBackfillBatch(until.Add(-30*24*time.Hour), until, 50_000)
	if err != nil {
		t.Fatalf("normalizeTrafficBackfillBatch returned error: %v", err)
	}
	if !since.Equal(until.Add(-30*24*time.Hour)) || !gotUntil.Equal(until) {
		t.Fatalf("window = %s..%s", since, gotUntil)
	}
	if limit != maximumTrafficBackfillBatchSize {
		t.Fatalf("limit = %d, want %d", limit, maximumTrafficBackfillBatchSize)
	}

	_, _, _, err = normalizeTrafficBackfillBatch(until.Add(-30*24*time.Hour-time.Nanosecond), until, 1)
	if err == nil || !strings.Contains(err.Error(), "must not exceed 30 days") {
		t.Fatalf("oversized window error = %v", err)
	}
}
