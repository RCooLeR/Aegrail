package postgres

import (
	"testing"
	"time"
)

func TestTrafficTimelineBucketAdaptsToDashboardWindows(t *testing.T) {
	tests := []struct {
		window time.Duration
		stride string
		label  string
	}{
		{15 * time.Minute, "1 minute", "minute"},
		{30 * time.Minute, "1 minute", "minute"},
		{time.Hour, "1 minute", "minute"},
		{3 * time.Hour, "5 minutes", "5 minutes"},
		{6 * time.Hour, "5 minutes", "5 minutes"},
		{12 * time.Hour, "30 minutes", "30 minutes"},
		{24 * time.Hour, "30 minutes", "30 minutes"},
		{3 * 24 * time.Hour, "1 hour", "hour"},
		{7 * 24 * time.Hour, "6 hours", "6 hours"},
		{10 * 24 * time.Hour, "6 hours", "6 hours"},
		{14 * 24 * time.Hour, "6 hours", "6 hours"},
		{30 * 24 * time.Hour, "1 day", "day"},
	}

	for _, test := range tests {
		stride, label := trafficTimelineBucket(test.window)
		if stride != test.stride || label != test.label {
			t.Fatalf("trafficTimelineBucket(%s) = %q, %q; want %q, %q", test.window, stride, label, test.stride, test.label)
		}
	}
}
