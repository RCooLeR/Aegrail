package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/reports"
)

func TestWriteHubFindingsReportSupportsJSONAndMarkdownFormats(t *testing.T) {
	report := reports.BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		reports.HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production"},
		[]domain.HubFinding{
			{
				ID:           "finding-1",
				RuleID:       "file-php-in-writable-path",
				RuleVersion:  "2026-05-13.1",
				DedupeKey:    "dedupe-1",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceHigh,
				Title:        "PHP file under writable path",
				Summary:      "web-01 file.created wp-content/uploads/avatar.php",
				EventIDs:     []domain.ID{"evt-file"},
				FirstEventAt: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
				LastEventAt:  time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
				Metadata: map[string]any{
					"risk": map[string]any{
						"score": 90,
						"band":  "critical",
					},
				},
				CreatedAt: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
				UpdatedAt: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
			},
		},
		time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC),
	)

	var jsonOutput bytes.Buffer
	if err := writeHubFindingsReport(&jsonOutput, "json", report, false); err != nil {
		t.Fatalf("writeHubFindingsReport(json) returned error: %v", err)
	}
	var decoded reports.HubFindingsJSONReport
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v\n%s", err, jsonOutput.String())
	}
	if decoded.FindingCount != 1 || decoded.Findings[0].RiskScore != 90 {
		t.Fatalf("decoded report = %#v, want one scored finding", decoded)
	}

	var markdownOutput bytes.Buffer
	if err := writeHubFindingsReport(&markdownOutput, "md", report, false); err != nil {
		t.Fatalf("writeHubFindingsReport(md) returned error: %v", err)
	}
	if !strings.Contains(markdownOutput.String(), "# Aegrail Technical Findings Report") ||
		!strings.Contains(markdownOutput.String(), "- Risk: critical (90)") {
		t.Fatalf("markdown output = %q, want technical report", markdownOutput.String())
	}

	var summaryOutput bytes.Buffer
	if err := writeHubFindingsReport(&summaryOutput, "manager-markdown", report, false); err != nil {
		t.Fatalf("writeHubFindingsReport(manager-markdown) returned error: %v", err)
	}
	if !strings.Contains(summaryOutput.String(), "# Aegrail Manager Summary") ||
		!strings.Contains(summaryOutput.String(), "Aegrail found 1 persisted finding(s)") {
		t.Fatalf("summary output = %q, want manager summary", summaryOutput.String())
	}
}

func TestWriteHubFindingsReportRejectsUnsupportedFormat(t *testing.T) {
	err := writeHubFindingsReport(&bytes.Buffer{}, "html", reports.HubFindingsJSONReport{}, false)
	if err == nil || !strings.Contains(err.Error(), `unsupported report format "html"`) {
		t.Fatalf("error = %v, want unsupported format", err)
	}
}

func TestWriteTimelineReportSupportsCSVFormat(t *testing.T) {
	report := reports.TimelineCSVReport{
		GeneratedAt: time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC),
		Scope: reports.TimelineCSVScope{
			Organization: "acme",
			Project:      "customer-site",
			Environment:  "production",
		},
		Events: []reports.TimelineCSVRecord{
			{
				ID:          "evt-1",
				BatchID:     "batch-1",
				App:         "main-web",
				Service:     "frontend",
				Host:        "web-01",
				Agent:       "agt_web_01",
				EventTime:   time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
				ReceivedAt:  time.Date(2026, 5, 12, 12, 0, 2, 0, time.UTC),
				Type:        "log.access",
				Target:      "/wp-login.php",
				Severity:    "medium",
				LabelsJSON:  "{}",
				PayloadJSON: "{}",
			},
		},
	}

	var csvOutput bytes.Buffer
	if err := writeTimelineReport(&csvOutput, "csv", report); err != nil {
		t.Fatalf("writeTimelineReport(csv) returned error: %v", err)
	}
	if !strings.Contains(csvOutput.String(), "event_time,received_time,organization") ||
		!strings.Contains(csvOutput.String(), "evt-1,batch-1") {
		t.Fatalf("csv output = %q, want timeline CSV", csvOutput.String())
	}
}

func TestWriteTimelineReportRejectsUnsupportedFormat(t *testing.T) {
	err := writeTimelineReport(&bytes.Buffer{}, "json", reports.TimelineCSVReport{})
	if err == nil || !strings.Contains(err.Error(), `unsupported report format "json"`) {
		t.Fatalf("error = %v, want unsupported format", err)
	}
}
