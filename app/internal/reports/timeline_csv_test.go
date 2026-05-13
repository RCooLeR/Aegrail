package reports

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestWriteTimelineCSVSortsAndEncodesTimelineEvents(t *testing.T) {
	generatedAt := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	older := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	report := BuildTimelineCSVReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		TimelineCSVScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.TimelineEvent{
			{
				ID:              "evt-new",
				BatchID:         "batch-1",
				AppSlug:         "main-web",
				ServiceSlug:     "frontend",
				HostSlug:        "web-02",
				Hostname:        "web-02.local",
				AgentExternalID: "agt_web_02",
				EventTime:       newer,
				ReceivedAt:      newer.Add(2 * time.Second),
				EventType:       "file.created",
				Target:          "/var/www/app/uploads/avatar.php",
				Severity:        domain.SeverityHigh,
				Message:         "created PHP file in uploads",
				Region:          "eu-central",
				Labels:          map[string]string{"site_slug": "example-com"},
				Payload:         map[string]any{"relative_path": "uploads/avatar.php"},
				CreatedAt:       newer.Add(time.Second),
			},
			{
				ID:              "evt-old",
				BatchID:         "batch-1",
				AppSlug:         "main-web",
				ServiceSlug:     "frontend",
				HostSlug:        "web-01",
				Hostname:        "web-01.local",
				AgentExternalID: "agt_web_01",
				EventTime:       older,
				ReceivedAt:      older.Add(2 * time.Second),
				EventType:       "log.access",
				Target:          "/wp-login.php",
				Severity:        domain.SeverityMedium,
				Message:         "admin login",
				Labels:          map[string]string{"site_slug": "example-com"},
				Payload:         map[string]any{"status_code": float64(200)},
				CreatedAt:       older.Add(time.Second),
			},
		},
		generatedAt,
	)

	var encoded bytes.Buffer
	if err := WriteTimelineCSV(&encoded, report); err != nil {
		t.Fatalf("WriteTimelineCSV returned error: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(encoded.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll returned error: %v\n%s", err, encoded.String())
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want header plus two events:\n%s", len(rows), encoded.String())
	}
	if got, want := rows[0][0], "event_time"; got != want {
		t.Fatalf("header[0] = %q, want %q", got, want)
	}
	if got, want := rows[1][15], "evt-old"; got != want {
		t.Fatalf("first event id = %q, want %q", got, want)
	}
	if got, want := rows[2][15], "evt-new"; got != want {
		t.Fatalf("second event id = %q, want %q", got, want)
	}
	if got, want := rows[1][17], `{"site_slug":"example-com"}`; got != want {
		t.Fatalf("labels = %q, want %q", got, want)
	}
	if got, want := rows[2][18], `{"relative_path":"uploads/avatar.php"}`; got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if got, want := rows[1][19], "2026-05-12T14:00:00Z"; got != want {
		t.Fatalf("report generated time = %q, want %q", got, want)
	}
}
