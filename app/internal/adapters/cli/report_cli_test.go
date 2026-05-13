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
}

func TestWriteHubFindingsReportRejectsUnsupportedFormat(t *testing.T) {
	err := writeHubFindingsReport(&bytes.Buffer{}, "html", reports.HubFindingsJSONReport{}, false)
	if err == nil || !strings.Contains(err.Error(), `unsupported report format "html"`) {
		t.Fatalf("error = %v, want unsupported format", err)
	}
}
