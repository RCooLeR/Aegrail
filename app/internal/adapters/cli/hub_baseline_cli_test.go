package cli

import (
	"testing"
	"time"
)

func TestParseLookbackSupportsDaysDurationAndTimestamp(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC) }

	parsed, err := parseLookback("7d", now)
	if err != nil {
		t.Fatalf("parseLookback day duration returned error: %v", err)
	}
	if want := now().Add(-7 * 24 * time.Hour); !parsed.Equal(want) {
		t.Fatalf("7d = %s, want %s", parsed, want)
	}

	parsed, err = parseLookback("2026-05-11T10:00:00Z", now)
	if err != nil {
		t.Fatalf("parseLookback timestamp returned error: %v", err)
	}
	if want := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC); !parsed.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", parsed, want)
	}
}
