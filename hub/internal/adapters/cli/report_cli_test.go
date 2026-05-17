package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/reports"
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

func TestWriteEvidenceBundleReportSupportsJSONFormat(t *testing.T) {
	bundle := reports.EvidenceBundle{
		Schema:       reports.EvidenceBundleSchema,
		BundleSHA256: "abc123",
		Findings: []reports.EvidenceBundleFinding{
			{ID: "finding-1", RuleID: "file-php-in-writable-path"},
		},
	}

	var jsonOutput bytes.Buffer
	if err := writeEvidenceBundleReport(&jsonOutput, "json", bundle, false); err != nil {
		t.Fatalf("writeEvidenceBundleReport(json) returned error: %v", err)
	}
	if !strings.Contains(jsonOutput.String(), `"schema": "aegrail.evidence_bundle.v1"`) ||
		!strings.Contains(jsonOutput.String(), `"bundle_sha256": "abc123"`) {
		t.Fatalf("json output = %q, want evidence bundle JSON", jsonOutput.String())
	}
}

func TestWriteEvidenceBundleReportRejectsUnsupportedFormat(t *testing.T) {
	err := writeEvidenceBundleReport(&bytes.Buffer{}, "markdown", reports.EvidenceBundle{}, false)
	if err == nil || !strings.Contains(err.Error(), `unsupported report format "markdown"`) {
		t.Fatalf("error = %v, want unsupported format", err)
	}
}

func TestWriteFindingReviewReportSupportsMarkdownAndJSON(t *testing.T) {
	report := reports.FindingReviewReport{
		GeneratedAt:  time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC),
		Tool:         reports.ToolInfo{Name: "Aegrail", Binary: "aegrail-hub", Version: "test"},
		Scope:        reports.HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production"},
		FindingCount: 1,
		Items: []reports.FindingReviewItem{
			{
				Finding: reports.HubFindingJSONRecord{
					ID:         "finding-1",
					RuleID:     "file-php-in-writable-path",
					Severity:   "high",
					Confidence: "high",
					Title:      "PHP file under writable path",
					Summary:    "upload PHP was created",
				},
				ModelReport: &reports.FindingReviewModelSummary{
					ID:              "model-1",
					Status:          "completed",
					ModelName:       "qwen2.5-coder:14b",
					AnalysisExcerpt: "Looks suspicious unless it is an expected deployment artifact.",
				},
			},
		},
	}

	var markdown bytes.Buffer
	if err := writeFindingReviewReport(&markdown, "markdown", report, false); err != nil {
		t.Fatalf("writeFindingReviewReport(markdown) returned error: %v", err)
	}
	if !strings.Contains(markdown.String(), "# Aegrail Finding Review") || !strings.Contains(markdown.String(), "qwen2.5-coder:14b") {
		t.Fatalf("markdown output = %q, want finding review", markdown.String())
	}

	var jsonOutput bytes.Buffer
	if err := writeFindingReviewReport(&jsonOutput, "json", report, true); err != nil {
		t.Fatalf("writeFindingReviewReport(json) returned error: %v", err)
	}
	if !strings.Contains(jsonOutput.String(), `"finding_count":1`) || !strings.Contains(jsonOutput.String(), `"model_report"`) {
		t.Fatalf("json output = %q, want compact finding review JSON", jsonOutput.String())
	}
}

func TestWriteModelAnalysisReportListSupportsTableAndJSON(t *testing.T) {
	report := domain.ModelAnalysisReport{
		ID:                    "model-report-1",
		ReportSchema:          reports.ModelAnalysisReportSchema,
		Status:                reports.ModelAnalysisStatusCompleted,
		ModelName:             "qwen3:30b",
		PromptTemplateID:      reports.ModelAnalysisPromptTemplateID,
		PromptTemplateVersion: reports.ModelAnalysisPromptTemplateVersion,
		EvidenceBundleSHA256:  "abcdef1234567890",
		SourceFindingIDs:      []domain.ID{"finding-1"},
		GeneratedAt:           time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC),
		CreatedAt:             time.Date(2026, 5, 13, 10, 0, 1, 0, time.UTC),
	}

	var table bytes.Buffer
	if err := writeModelAnalysisReportList(&table, "table", []domain.ModelAnalysisReport{report}); err != nil {
		t.Fatalf("writeModelAnalysisReportList(table) returned error: %v", err)
	}
	if !strings.Contains(table.String(), "model-report-1") || !strings.Contains(table.String(), "qwen3:30b") {
		t.Fatalf("table output = %q, want saved report row", table.String())
	}

	var jsonOutput bytes.Buffer
	if err := writeModelAnalysisReportList(&jsonOutput, "json", []domain.ModelAnalysisReport{report}); err != nil {
		t.Fatalf("writeModelAnalysisReportList(json) returned error: %v", err)
	}
	if !strings.Contains(jsonOutput.String(), `"count":1`) || !strings.Contains(jsonOutput.String(), `"id":"model-report-1"`) {
		t.Fatalf("json output = %q, want saved report JSON", jsonOutput.String())
	}
}

func TestWriteModelAnalysisReportDetailSupportsJSONAndSummary(t *testing.T) {
	report := domain.ModelAnalysisReport{
		ID:                             "model-report-1",
		ReportSchema:                   reports.ModelAnalysisReportSchema,
		Status:                         reports.ModelAnalysisStatusFailed,
		ModelName:                      "qwen3:30b",
		PromptTemplateID:               reports.ModelAnalysisPromptTemplateID,
		PromptTemplateVersion:          reports.ModelAnalysisPromptTemplateVersion,
		PromptTemplateSHA256:           "prompt-template-sha",
		PromptSHA256:                   "prompt-sha",
		EvidenceBundleSchema:           reports.EvidenceBundleSchema,
		EvidenceBundleSHA256:           "bundle-sha",
		EvidenceBundleRedactionVersion: reports.EvidenceBundleRedactionVersion,
		SourceFindingIDs:               []domain.ID{"finding-1"},
		Error:                          "model failed",
		GeneratedAt:                    time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC),
		CreatedAt:                      time.Date(2026, 5, 13, 10, 0, 1, 0, time.UTC),
	}

	var jsonOutput bytes.Buffer
	if err := writeModelAnalysisReportDetail(&jsonOutput, "json", report); err != nil {
		t.Fatalf("writeModelAnalysisReportDetail(json) returned error: %v", err)
	}
	if !strings.Contains(jsonOutput.String(), `"status": "failed"`) || !strings.Contains(jsonOutput.String(), `"evidence_bundle_sha256": "bundle-sha"`) {
		t.Fatalf("json output = %q, want saved report detail", jsonOutput.String())
	}

	var summary bytes.Buffer
	if err := writeModelAnalysisReportDetail(&summary, "summary", report); err != nil {
		t.Fatalf("writeModelAnalysisReportDetail(summary) returned error: %v", err)
	}
	if !strings.Contains(summary.String(), "Error: model failed") {
		t.Fatalf("summary output = %q, want report error", summary.String())
	}
}

func TestWriteTimelineReportRejectsUnsupportedFormat(t *testing.T) {
	err := writeTimelineReport(&bytes.Buffer{}, "json", reports.TimelineCSVReport{})
	if err == nil || !strings.Contains(err.Error(), `unsupported report format "json"`) {
		t.Fatalf("error = %v, want unsupported format", err)
	}
}
