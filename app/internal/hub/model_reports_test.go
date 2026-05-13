package hub

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestSaveListGetModelAnalysisReports(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	reports := newMemoryModelAnalysisReportRepository()
	hub := New(Dependencies{Inventory: inventory, ModelReports: reports})
	ctx := context.Background()
	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)

	if _, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme", Name: "Acme"}); err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	if _, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site", Name: "Customer Site"}); err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	if _, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production", Name: "Production"}); err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	if _, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"}); err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}

	saved, err := hub.SaveModelAnalysisReport(ctx, SaveModelAnalysisReportInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Report: domain.ModelAnalysisReport{
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
			GeneratedAt:                    now,
		},
	})
	if err != nil {
		t.Fatalf("SaveModelAnalysisReport returned error: %v", err)
	}
	if saved.ID == "" || saved.OrganizationID == "" || saved.ProjectID == "" || saved.EnvironmentID == "" || saved.AppID == "" {
		t.Fatalf("saved report = %#v, want resolved scope ids", saved)
	}

	listed, err := hub.ListModelAnalysisReports(ctx, ListModelAnalysisReportsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
	})
	if err != nil {
		t.Fatalf("ListModelAnalysisReports returned error: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != saved.ID || listed[0].EvidenceBundleSHA256 != "bundle-sha" {
		t.Fatalf("listed reports = %#v, want saved report", listed)
	}

	got, err := hub.GetModelAnalysisReport(ctx, GetModelAnalysisReportInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		ReportID:         string(saved.ID),
	})
	if err != nil {
		t.Fatalf("GetModelAnalysisReport returned error: %v", err)
	}
	if got.ID != saved.ID || got.Analysis != "generated analysis" {
		t.Fatalf("got report = %#v, want saved detail", got)
	}
}

type memoryModelAnalysisReportRepository struct {
	reports map[domain.ID]domain.ModelAnalysisReport
}

func newMemoryModelAnalysisReportRepository() *memoryModelAnalysisReportRepository {
	return &memoryModelAnalysisReportRepository{reports: map[domain.ID]domain.ModelAnalysisReport{}}
}

func (r *memoryModelAnalysisReportRepository) SaveModelAnalysisReport(_ context.Context, report domain.ModelAnalysisReport) (domain.ModelAnalysisReport, error) {
	if report.ID == "" {
		report.ID = domain.ID(fmt.Sprintf("model-report-%d", len(r.reports)+1))
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = report.GeneratedAt.Add(time.Second)
	}
	if report.Metadata == nil {
		report.Metadata = map[string]any{}
	}
	r.reports[report.ID] = report
	return report, nil
}

func (r *memoryModelAnalysisReportRepository) ListModelAnalysisReports(_ context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.ModelAnalysisReport, error) {
	var reports []domain.ModelAnalysisReport
	for _, report := range r.reports {
		if report.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && report.AppID != appID {
			continue
		}
		reports = append(reports, report)
		if limit > 0 && len(reports) >= limit {
			break
		}
	}
	return reports, nil
}

func (r *memoryModelAnalysisReportRepository) GetModelAnalysisReport(_ context.Context, reportID domain.ID, environmentID domain.ID, appID domain.ID) (domain.ModelAnalysisReport, error) {
	report, ok := r.reports[reportID]
	if !ok || report.EnvironmentID != environmentID {
		return domain.ModelAnalysisReport{}, fmt.Errorf("model analysis report %q was not found", reportID)
	}
	if appID != "" && report.AppID != appID {
		return domain.ModelAnalysisReport{}, fmt.Errorf("model analysis report %q was not found", reportID)
	}
	return report, nil
}
