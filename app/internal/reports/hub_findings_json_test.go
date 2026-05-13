package reports

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestBuildHubFindingsJSONReportSortsAndEncodesFindings(t *testing.T) {
	generatedAt := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	older := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	report := BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test", Commit: "abc123"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.HubFinding{
			{
				ID:           "finding-old",
				RuleID:       "web-to-file-change",
				RuleVersion:  "2026-05-12.1",
				DedupeKey:    "corr-old",
				Severity:     domain.SeverityMedium,
				Confidence:   domain.ConfidenceMedium,
				Title:        "Suspicious web activity followed by file change",
				Summary:      "web-01 log.access /admin -> web-01 file.modified index.php",
				EventIDs:     []domain.ID{"evt-old-1", "evt-old-2"},
				FirstEventAt: older,
				LastEventAt:  older.Add(5 * time.Minute),
				CreatedAt:    older,
				UpdatedAt:    older,
			},
			{
				ID:           "finding-new",
				RuleID:       "probable-incident-chain",
				RuleVersion:  "2026-05-12.1",
				DedupeKey:    "corr-new",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceHigh,
				Title:        "Probable incident chain",
				Summary:      "web-02 log.access /wp-login.php -> web-02 file.created avatar.php -> db-01 db.role_changed users:42",
				Description:  "Aegrail correlated 3 timeline event(s).",
				EventIDs:     []domain.ID{"evt-login", "evt-file", "evt-db"},
				FirstEventAt: newer,
				LastEventAt:  newer.Add(8 * time.Minute),
				Metadata: map[string]any{
					"source": "hub.correlation",
					"risk": map[string]any{
						"score": 92,
						"band":  "critical",
					},
				},
				CreatedAt: newer,
				UpdatedAt: newer,
			},
		},
		generatedAt,
	)

	if report.FindingCount != 2 {
		t.Fatalf("FindingCount = %d, want 2", report.FindingCount)
	}
	if report.Findings[0].ID != "finding-new" {
		t.Fatalf("first finding = %s, want finding-new", report.Findings[0].ID)
	}
	if got, want := report.Findings[0].EventIDs, []string{"evt-login", "evt-file", "evt-db"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("event ids = %#v, want %#v", got, want)
	}
	if report.Findings[0].RiskScore != 92 || report.Findings[0].RiskBand != "critical" {
		t.Fatalf("risk fields = %d/%s, want 92/critical", report.Findings[0].RiskScore, report.Findings[0].RiskBand)
	}

	var encoded bytes.Buffer
	if err := WriteHubFindingsJSON(&encoded, report, true); err != nil {
		t.Fatalf("WriteHubFindingsJSON returned error: %v", err)
	}
	var decoded HubFindingsJSONReport
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v\n%s", err, encoded.String())
	}
	if decoded.Scope.Organization != "acme" || decoded.Tool.Binary != "aegrail" || decoded.Findings[0].RuleID != "probable-incident-chain" || decoded.Findings[0].RiskScore != 92 {
		t.Fatalf("decoded report = %#v", decoded)
	}
}
