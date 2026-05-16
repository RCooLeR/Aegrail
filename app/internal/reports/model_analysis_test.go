package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/adapters/modeltest"
	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/ports"
)

func TestGenerateModelAnalysisReportUsesFakeGatewayAndStoresProvenance(t *testing.T) {
	generatedAt := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	bundle := modelAnalysisTestBundle(t, generatedAt)
	gateway := modeltest.NewGateway()
	gateway.GenerateResponse.Text = `{"executive_summary":"Aegrail observed one high-risk finding."}`
	gateway.GenerateResponse.TotalDuration = 1500 * time.Millisecond
	gateway.GenerateResponse.PromptEvalCount = 42
	gateway.GenerateResponse.EvalCount = 12

	report, err := GenerateModelAnalysisReport(context.Background(), gateway, bundle, ModelAnalysisOptions{}, generatedAt)
	if err != nil {
		t.Fatalf("GenerateModelAnalysisReport returned error: %v", err)
	}
	if report.Status != ModelAnalysisStatusCompleted || report.Analysis == "" {
		t.Fatalf("report = %#v, want completed generated analysis", report)
	}
	if report.Notice == "" || !strings.Contains(report.Notice, "Deterministic Aegrail findings") {
		t.Fatalf("notice = %q, want deterministic source warning", report.Notice)
	}
	if report.EvidenceBundle.SHA256 != bundle.BundleSHA256 || report.PromptTemplate.Version != ModelAnalysisPromptTemplateVersion || report.PromptTemplate.SHA256 == "" || report.PromptSHA256 == "" {
		t.Fatalf("report provenance = %#v, want bundle and prompt provenance", report)
	}
	if len(report.SourceFindingIDs) != 1 || report.SourceFindingIDs[0] != "finding-1" {
		t.Fatalf("source finding ids = %#v, want finding-1", report.SourceFindingIDs)
	}
	if report.Stats == nil || report.Stats.TotalDurationMillis != 1500 || report.Stats.PromptEvalCount != 42 || report.Stats.EvalCount != 12 {
		t.Fatalf("stats = %#v, want model response stats", report.Stats)
	}
	if len(gateway.GenerateRequests) != 1 {
		t.Fatalf("generate requests = %d, want 1", len(gateway.GenerateRequests))
	}
	request := gateway.GenerateRequests[0]
	if request.System == "" || !strings.Contains(request.Prompt, EvidenceBundleSchema) || !strings.Contains(request.Prompt, bundle.BundleSHA256) {
		t.Fatalf("request = %#v, want system prompt and evidence bundle content", request)
	}
	if request.Options["temperature"] != 0 {
		t.Fatalf("request options = %#v, want deterministic temperature", request.Options)
	}

	var encoded bytes.Buffer
	if err := WriteModelAnalysisReportJSON(&encoded, report, true); err != nil {
		t.Fatalf("WriteModelAnalysisReportJSON returned error: %v", err)
	}
	var decoded ModelAnalysisReport
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v\n%s", err, encoded.String())
	}
	if decoded.Schema != ModelAnalysisReportSchema || decoded.Status != ModelAnalysisStatusCompleted {
		t.Fatalf("decoded report = %#v, want model analysis JSON", decoded)
	}
}

func TestGenerateModelAnalysisReportRecordsOfflineState(t *testing.T) {
	generatedAt := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	bundle := modelAnalysisTestBundle(t, generatedAt)
	gateway := modeltest.NewGateway()
	gateway.HealthResult.Offline = true

	report, err := GenerateModelAnalysisReport(context.Background(), gateway, bundle, ModelAnalysisOptions{}, generatedAt)
	if err != nil {
		t.Fatalf("GenerateModelAnalysisReport returned error: %v", err)
	}
	if report.Status != ModelAnalysisStatusOffline || !strings.Contains(report.Error, ports.ErrModelGatewayOffline.Error()) {
		t.Fatalf("report = %#v, want offline report", report)
	}
	if len(gateway.GenerateRequests) != 0 {
		t.Fatalf("generate requests = %d, want no model call while offline", len(gateway.GenerateRequests))
	}
	if report.EvidenceBundle.SHA256 != bundle.BundleSHA256 || report.PromptTemplate.Version == "" {
		t.Fatalf("report provenance = %#v, want provenance even when offline", report)
	}
}

func TestFormatModelAnalysisResponseUsesStructuredFormat(t *testing.T) {
	raw := `{
  "executive_summary": "A suspicious file deployment was detected after a privileged login.",
  "incident_chain": [
    {
      "step": "Unexpected PHP file appeared in uploads.",
      "evidence": ["finding:evt-file", "file:modules/demo.log"],
      "likelihood": "high",
      "impact": "Potential webshell risk.",
      "inference": "Observed file change and user mismatch."
    }
  ],
  "priority_findings": [
    {
      "priority": "critical",
      "finding_id": "file-upload",
      "observation": "Executable uploaded outside managed releases.",
      "investigation_recommendation": "Verify upload source and remove file.",
      "requires_human_verification": true
    }
  ],
  "recommended_next_checks": [
    "Confirm whether the file was created by a deployment task.",
    "Rotate credentials used during the upload window."
  ],
  "uncertainty_and_gaps": [
    "No server logs after 15 minutes."
  ]
}`
	report := formatModelAnalysisResponse(raw)
	requireContains(t, report, `<div class="model-analysis-report">`)
	requireContains(t, report, "<h4>Executive Summary</h4>")
	requireContains(t, report, "Unexpected PHP file")
	requireContains(t, report, "<h4>Probable Incident Chain</h4>")
	requireContains(t, report, "[critical] file-upload")
	requireContains(t, report, "<h4>Recommended Next Checks</h4>")
	requireContains(t, report, "server logs")
}

func TestFormatModelAnalysisResponseFallsBackForFreeText(t *testing.T) {
	raw := "Looks like we may have a file and db signal; cannot infer a clean chain."
	report := formatModelAnalysisResponse(raw)
	requireContains(t, report, "<h4>Analysis</h4>")
	requireContains(t, report, "Looks like we may have")
}

func TestFormatModelAnalysisResponseSupportsCodeFence(t *testing.T) {
	raw := "```json\n" + strings.TrimSpace(`{
  "executive_summary": "Check the cache artifacts.",
  "operator_insight": {
    "operator_summary": "This appears like cache churn with no direct authentication impact.",
    "likely_real_issue": "false",
    "false_positive_risk": "true",
    "platform_expected_behavior": "Cron-driven cache rebuild is normal in this stack.",
    "suspicious_indicators": ["No executable uploads seen"],
    "recommended_operator_response": "Validate deployment window and ignore if only cache dirs changed.",
    "normal_operations_checks": ["Compare deployment timestamps", "Confirm cache purge job owner"]
  },
  "incident_chain": [],
  "priority_findings": [],
  "recommended_next_checks": ["Review cache ignore rules."],
  "uncertainty_and_gaps": []
}`) + "\n```"
	report := formatModelAnalysisResponse(raw)
	requireContains(t, report, "<h4>Executive Summary</h4>")
	requireContains(t, report, "Check the cache artifacts.")
	requireContains(t, report, "<h4>Operator Insight</h4>")
	requireContains(t, report, "Likely real issue")
	requireContains(t, report, "<h4>Recommended Next Checks</h4>")
}

func TestBuildModelAnalysisPromptAddsContext(t *testing.T) {
	bundle := modelAnalysisTestBundle(t, time.Now())
	prompt, err := BuildModelAnalysisPrompt(bundle, ModelAnalysisOptions{
		AppKind:           "wordpress",
		FindingRuleID:     "wordpress-admin-user-added",
		FindingID:         "finding-1",
		FindingTitle:      "Admin account added",
		FindingSummary:    "A high-privilege account was created.",
		FindingSeverity:   "high",
		FindingConfidence: "high",
	})
	if err != nil {
		t.Fatalf("BuildModelAnalysisPrompt returned error: %v", err)
	}
	if !strings.Contains(prompt.User, "Application platform: WordPress") {
		t.Fatalf("platform context was not included: %q", prompt.User)
	}
	if !strings.Contains(prompt.User, "\"finding:ID\"") {
		t.Fatalf("schema appears to have been damaged")
	}
	if !strings.Contains(prompt.User, "Issue type: identity_and_access") || !strings.Contains(prompt.User, "Issue guidance") {
		t.Fatalf("issue context was not included: %q", prompt.User)
	}
	if !strings.Contains(prompt.User, "Identity/access perspective") {
		t.Fatalf("issue profile was not included: %q", prompt.User)
	}
}

func TestParseModelAnalysisStructuredRejectsBadJSON(t *testing.T) {
	raw := "{\"executive_summary\": \"Missing end"
	if _, ok := parseModelAnalysisStructured(raw); ok {
		t.Fatalf("expected parse failure")
	}
}

func requireContains(t *testing.T, got string, needle string) {
	t.Helper()
	if !strings.Contains(got, needle) {
		t.Fatalf("result missing %q in:\n%s", needle, got)
	}
}

func modelAnalysisTestBundle(t *testing.T, generatedAt time.Time) EvidenceBundle {
	t.Helper()
	report := BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.HubFinding{{
			ID:           "finding-1",
			RuleID:       "file-php-in-writable-path",
			RuleVersion:  "2026-05-13.1",
			Severity:     domain.SeverityHigh,
			Confidence:   domain.ConfidenceHigh,
			Title:        "PHP executable in writable path",
			Summary:      "web-01 created wp-content/uploads/avatar.php",
			EventIDs:     []domain.ID{"evt-file"},
			FirstEventAt: generatedAt,
			LastEventAt:  generatedAt,
			CreatedAt:    generatedAt,
			UpdatedAt:    generatedAt,
		}},
		generatedAt,
	)
	bundle, err := BuildEvidenceBundle(report, EvidenceBundleOptions{})
	if err != nil {
		t.Fatalf("BuildEvidenceBundle returned error: %v", err)
	}
	return bundle
}
