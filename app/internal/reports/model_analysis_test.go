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
	gateway.GenerateResponse.Text = "## Executive Summary\nAegrail observed one high-risk finding."
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
