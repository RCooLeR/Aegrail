package reports

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
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
					"operator_action": map[string]any{
						"primary_action":              "Open the linked timeline and confirm expected work.",
						"safe_to_acknowledge_when":    "the full timeline has a confirmed authorized explanation",
						"recommended_status_expected": "acknowledged",
					},
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
	if report.Findings[0].OperatorAction["recommended_status_expected"] != "acknowledged" {
		t.Fatalf("operator action = %#v, want top-level operator guidance", report.Findings[0].OperatorAction)
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

func TestWriteHubFindingsMarkdownRanksFindingsAndIncludesEvidence(t *testing.T) {
	generatedAt := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	older := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	report := BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test", Commit: "abc123"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.HubFinding{
			{
				ID:           "finding-new-low",
				RuleID:       "web-tor-request-observed",
				RuleVersion:  "2026-05-13.1",
				DedupeKey:    "corr-low",
				Severity:     domain.SeverityLow,
				Confidence:   domain.ConfidenceLow,
				Title:        "Tor-marked request observed",
				Summary:      "web-01 log.access /",
				EventIDs:     []domain.ID{"evt-low"},
				FirstEventAt: newer,
				LastEventAt:  newer,
				Metadata: map[string]any{
					"risk": map[string]any{
						"score": 18,
						"band":  "informational",
					},
				},
				CreatedAt: newer,
				UpdatedAt: newer,
			},
			{
				ID:           "finding-old-critical",
				RuleID:       "probable-incident-chain",
				RuleVersion:  "2026-05-13.1",
				DedupeKey:    "corr-critical",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceHigh,
				Title:        "Probable incident chain",
				Summary:      "web-02 log.access /wp-login.php -> web-02 file.created avatar.php -> db-01 db.role_changed users:42",
				Description:  "Aegrail correlated 3 timeline event(s).",
				EventIDs:     []domain.ID{"evt-login", "evt-file", "evt-db"},
				FirstEventAt: older,
				LastEventAt:  older.Add(8 * time.Minute),
				Metadata: map[string]any{
					"events": []map[string]any{
						{
							"event_id":   "evt-login",
							"event_time": older.Format(time.RFC3339),
							"host":       "web-02",
							"type":       "log.access",
							"target":     "/wp-login.php",
						},
					},
					"operator_action": map[string]any{
						"primary_action":           "Open the linked timeline and confirm expected work.",
						"safe_to_acknowledge_when": "the full timeline has a confirmed authorized explanation",
						"escalate_when":            "no owner can explain the change",
					},
					"deployment_context": map[string]any{
						"active":            true,
						"severity_adjusted": false,
						"original_severity": "high",
						"adjusted_severity": "high",
						"deployments": []map[string]any{
							{
								"id":         "dep-1",
								"version":    "v1.8.2",
								"commit_sha": "a91f72c",
								"actor":      "github-actions",
								"started_at": older.Add(-time.Minute).Format(time.RFC3339),
							},
						},
					},
					"risk": map[string]any{
						"score": 92,
						"band":  "critical",
						"factors": []map[string]any{
							{"id": "rule:incident_chain", "points": 12, "reason": "probable multi-step incident chain"},
						},
					},
				},
				CreatedAt: older,
				UpdatedAt: older,
			},
		},
		generatedAt,
	)

	var encoded bytes.Buffer
	if err := WriteHubFindingsMarkdown(&encoded, report); err != nil {
		t.Fatalf("WriteHubFindingsMarkdown returned error: %v", err)
	}
	markdown := encoded.String()
	assertContains(t, markdown, "# Aegrail Technical Findings Report")
	assertContains(t, markdown, "- Organization: acme")
	assertContains(t, markdown, "| critical | 1 |")
	assertContains(t, markdown, "- Risk: critical (92)")
	assertContains(t, markdown, "- evt-login | 2026-05-12T12:00:00Z | web-02 | log.access | /wp-login.php")
	assertContains(t, markdown, "- Deployment: v1.8.2, actor github-actions")
	assertContains(t, markdown, "- Primary action: Open the linked timeline and confirm expected work.")
	assertContains(t, markdown, "- +12 rule:incident_chain: probable multi-step incident chain")

	criticalIndex := strings.Index(markdown, "### 1. Probable incident chain")
	lowIndex := strings.Index(markdown, "### 2. Tor-marked request observed")
	if criticalIndex < 0 || lowIndex < 0 || criticalIndex > lowIndex {
		t.Fatalf("markdown findings are not risk-ranked:\n%s", markdown)
	}
}

func TestWriteHubFindingsManagerMarkdownSummarizesPriorityAndStatus(t *testing.T) {
	generatedAt := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	eventTime := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	report := BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.HubFinding{
			{
				ID:           "finding-critical",
				RuleID:       "probable-incident-chain",
				RuleVersion:  "2026-05-13.1",
				DedupeKey:    "corr-critical",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceHigh,
				Title:        "Probable incident chain",
				Summary:      "web-02 log.access /wp-login.php -> web-02 file.created avatar.php",
				EventIDs:     []domain.ID{"evt-login", "evt-file", "evt-db"},
				FirstEventAt: eventTime,
				LastEventAt:  eventTime.Add(5 * time.Minute),
				Status:       "acknowledged",
				Metadata: map[string]any{
					"risk": map[string]any{
						"score": 92,
						"band":  "critical",
					},
				},
				CreatedAt: eventTime,
				UpdatedAt: eventTime,
			},
			{
				ID:           "finding-medium",
				RuleID:       "wordpress-option-security-changed",
				RuleVersion:  "2026-05-13.1",
				DedupeKey:    "corr-medium",
				Severity:     domain.SeverityMedium,
				Confidence:   domain.ConfidenceMedium,
				Title:        "WordPress tracked option changed",
				Summary:      "wp option changed",
				EventIDs:     []domain.ID{"evt-option"},
				FirstEventAt: eventTime.Add(time.Hour),
				LastEventAt:  eventTime.Add(time.Hour),
				Metadata: map[string]any{
					"deployment_context": map[string]any{"active": true},
					"risk": map[string]any{
						"score": 46,
						"band":  "medium",
					},
				},
				CreatedAt: eventTime.Add(time.Hour),
				UpdatedAt: eventTime.Add(time.Hour),
			},
		},
		generatedAt,
	)

	var encoded bytes.Buffer
	if err := WriteHubFindingsManagerMarkdown(&encoded, report); err != nil {
		t.Fatalf("WriteHubFindingsManagerMarkdown returned error: %v", err)
	}
	markdown := encoded.String()
	assertContains(t, markdown, "# Aegrail Manager Summary")
	assertContains(t, markdown, "Aegrail found 2 persisted finding(s)")
	assertContains(t, markdown, "1 finding(s) are critical or high risk")
	assertContains(t, markdown, "- Acknowledged: 1")
	assertContains(t, markdown, "- Open: 1")
	assertContains(t, markdown, "- Findings with active deployment context: 1")
	assertContains(t, markdown, "- finding-critical: Probable incident chain, critical (92), status acknowledged")
	assertContains(t, markdown, "Start incident triage for critical and high-risk findings")
}

func TestWriteFindingReviewMarkdownShowsDeterministicAndModelSideBySide(t *testing.T) {
	generatedAt := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)
	eventTime := generatedAt.Add(-time.Hour)

	report := BuildFindingReviewReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail-hub", Version: "test"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.HubFinding{
			{
				ID:           "finding-1",
				RuleID:       "browser-script-domain-new",
				RuleVersion:  "2026-05-17.1",
				DedupeKey:    "script-domain",
				Severity:     domain.SeverityMedium,
				Confidence:   domain.ConfidenceMedium,
				Title:        "New browser script domain",
				Summary:      "A new script domain was observed.",
				EventIDs:     []domain.ID{"evt-1"},
				FirstEventAt: eventTime,
				LastEventAt:  eventTime,
				Metadata: map[string]any{
					"operator_action": map[string]any{
						"primary_action": "Verify the script owner before allowlisting.",
					},
					"risk": map[string]any{"score": 46, "band": "medium"},
				},
				CreatedAt: eventTime,
				UpdatedAt: eventTime,
			},
		},
		[]domain.ModelAnalysisReport{
			{
				ID:                    "model-1",
				Status:                "completed",
				ModelName:             "qwen2.5-coder:14b",
				PromptTemplateVersion: "2026-05-17.1",
				EvidenceBundleSHA256:  "bundle-sha",
				SourceFindingIDs:      []domain.ID{"finding-1"},
				Analysis:              "This looks like a third-party script drift. Verify ownership and deployment context before allowlisting.",
				GeneratedAt:           generatedAt.Add(-time.Minute),
				CreatedAt:             generatedAt,
			},
		},
		generatedAt,
	)

	var encoded bytes.Buffer
	if err := WriteFindingReviewMarkdown(&encoded, report); err != nil {
		t.Fatalf("WriteFindingReviewMarkdown returned error: %v", err)
	}
	markdown := encoded.String()
	assertContains(t, markdown, "# Aegrail Finding Review")
	assertContains(t, markdown, "| Finding | Deterministic Hub View | Latest Model Analysis |")
	assertContains(t, markdown, "Verify the script owner before allowlisting")
	assertContains(t, markdown, "qwen2.5-coder:14b")
}

func assertContains(t *testing.T, value string, want string) {
	t.Helper()
	if !strings.Contains(value, want) {
		t.Fatalf("value does not contain %q:\n%s", want, value)
	}
}
