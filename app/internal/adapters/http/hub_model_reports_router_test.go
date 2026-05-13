package httpadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
)

func TestHubRouterListsAndShowsModelAnalysisReports(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	reports := newHTTPTestModelAnalysisReportRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, ModelReports: reports}), HubOptions{})

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/reports/model-analysis?org=acme&project=customer-site&environment=production&app=main-web", nil)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)

	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listResponse.Code, listResponse.Body.String())
	}
	var listBody struct {
		Count   int `json:"count"`
		Reports []struct {
			ID                    string   `json:"id"`
			Status                string   `json:"status"`
			ModelName             string   `json:"model_name"`
			PromptTemplateVersion string   `json:"prompt_template_version"`
			SourceFindingIDs      []string `json:"source_finding_ids"`
		} `json:"reports"`
	}
	if err := json.NewDecoder(listResponse.Body).Decode(&listBody); err != nil {
		t.Fatalf("Decode list returned error: %v", err)
	}
	if listBody.Count != 1 || listBody.Reports[0].ID != "model-report-1" || listBody.Reports[0].SourceFindingIDs[0] != "finding-1" {
		t.Fatalf("list body = %#v, want saved model report", listBody)
	}

	showRequest := httptest.NewRequest(http.MethodGet, "/api/v1/reports/model-analysis/model-report-1?org=acme&project=customer-site&environment=production&app=main-web", nil)
	showResponse := httptest.NewRecorder()
	router.ServeHTTP(showResponse, showRequest)

	if showResponse.Code != http.StatusOK {
		t.Fatalf("show status = %d body = %s", showResponse.Code, showResponse.Body.String())
	}
	var showBody struct {
		Report struct {
			ID                   string `json:"id"`
			EvidenceBundleSHA256 string `json:"evidence_bundle_sha256"`
			Analysis             string `json:"analysis"`
		} `json:"report"`
	}
	if err := json.NewDecoder(showResponse.Body).Decode(&showBody); err != nil {
		t.Fatalf("Decode show returned error: %v", err)
	}
	if showBody.Report.ID != "model-report-1" || showBody.Report.EvidenceBundleSHA256 != "bundle-sha" || showBody.Report.Analysis == "" {
		t.Fatalf("show body = %#v, want report detail", showBody)
	}
}

type httpTestModelAnalysisReportRepository struct {
	reports map[domain.ID]domain.ModelAnalysisReport
}

func newHTTPTestModelAnalysisReportRepository() *httpTestModelAnalysisReportRepository {
	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	return &httpTestModelAnalysisReportRepository{
		reports: map[domain.ID]domain.ModelAnalysisReport{
			"model-report-1": {
				ID:                             "model-report-1",
				OrganizationID:                 "org-1",
				ProjectID:                      "project-1",
				EnvironmentID:                  "env-1",
				AppID:                          "app-1",
				ReportSchema:                   "aegrail.model_analysis_report.v1",
				Status:                         "completed",
				ModelProvider:                  "fake",
				ModelName:                      "fake-investigation",
				PromptTemplateID:               "aegrail.incident_analysis",
				PromptTemplateVersion:          "2026-05-13.1",
				PromptTemplateSHA256:           "template-sha",
				PromptSHA256:                   "prompt-sha",
				EvidenceBundleSchema:           "aegrail.evidence_bundle.v1",
				EvidenceBundleSHA256:           "bundle-sha",
				EvidenceBundleRedactionVersion: "2026-05-13.1",
				EvidenceBundleGeneratedAt:      now,
				SourceFindingIDs:               []domain.ID{"finding-1"},
				Analysis:                       "generated analysis",
				TotalDurationMillis:            1500,
				PromptEvalCount:                42,
				EvalCount:                      12,
				GeneratedAt:                    now,
				Metadata:                       map[string]any{"notice": "advisory"},
				CreatedAt:                      now.Add(time.Second),
			},
		},
	}
}

func (r *httpTestModelAnalysisReportRepository) SaveModelAnalysisReport(ctx context.Context, report domain.ModelAnalysisReport) (domain.ModelAnalysisReport, error) {
	r.reports[report.ID] = report
	return report, nil
}

func (r *httpTestModelAnalysisReportRepository) ListModelAnalysisReports(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.ModelAnalysisReport, error) {
	var reports []domain.ModelAnalysisReport
	for _, report := range r.reports {
		if report.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && report.AppID != appID {
			continue
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func (r *httpTestModelAnalysisReportRepository) GetModelAnalysisReport(ctx context.Context, reportID domain.ID, environmentID domain.ID, appID domain.ID) (domain.ModelAnalysisReport, error) {
	report, ok := r.reports[reportID]
	if !ok || report.EnvironmentID != environmentID {
		return domain.ModelAnalysisReport{}, fmt.Errorf("model analysis report %q was not found", reportID)
	}
	if appID != "" && report.AppID != appID {
		return domain.ModelAnalysisReport{}, fmt.Errorf("model analysis report %q was not found", reportID)
	}
	return report, nil
}
