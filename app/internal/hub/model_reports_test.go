package hub

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/adapters/modeltest"
	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/reports"
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

func TestGenerateModelAnalysisReportForFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	modelReports := newMemoryModelAnalysisReportRepository()
	model := modeltest.NewGateway()
	model.GenerateResponse.Text = "Review the new administrator account and confirm the deployment window."
	hub := New(Dependencies{
		Meta: domain.AppMeta{
			Name:    "Aegrail",
			Binary:  "aegrail",
			Version: "test",
		},
		Inventory:    inventory,
		Findings:     findings,
		ModelReports: modelReports,
		Model:        model,
	})
	ctx := context.Background()
	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)

	org, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme", Name: "Acme"})
	if err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	project, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site", Name: "Customer Site"})
	if err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production", Name: "Production"})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	savedFindings, err := findings.SaveHubFindings(ctx, []domain.HubFinding{
		{
			OrganizationID: org.ID,
			ProjectID:      project.ID,
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         "wordpress-admin-user-added",
			RuleVersion:    "2026-05-12.1",
			DedupeKey:      "wp-user-admin",
			Severity:       domain.SeverityHigh,
			Confidence:     domain.ConfidenceHigh,
			Title:          "WordPress administrator added",
			Summary:        "User roman@example.test became an administrator.",
			EventIDs:       []domain.ID{"event-1"},
			FirstEventAt:   now.Add(-time.Minute),
			LastEventAt:    now,
			Metadata: map[string]any{
				"email": "roman@example.test",
				"risk":  map[string]any{"score": 80, "band": "high"},
			},
		},
	})
	if err != nil {
		t.Fatalf("SaveHubFindings returned error: %v", err)
	}

	generated, err := hub.GenerateModelAnalysisReport(ctx, GenerateModelAnalysisReportInput{
		OrganizationSlug:    "acme",
		ProjectSlug:         "customer-site",
		EnvironmentSlug:     "production",
		AppSlug:             "main-web",
		FindingID:           string(savedFindings[0].ID),
		MaxEventsPerFinding: 4,
		GeneratedAt:         now,
	})
	if err != nil {
		t.Fatalf("GenerateModelAnalysisReport returned error: %v", err)
	}
	if generated.ID == "" || generated.Status != reports.ModelAnalysisStatusCompleted || generated.Analysis == "" {
		t.Fatalf("generated report = %#v, want completed saved report", generated)
	}
	if generated.AppID != app.ID || len(generated.SourceFindingIDs) != 1 || generated.SourceFindingIDs[0] != savedFindings[0].ID {
		t.Fatalf("generated scope/source = app %q ids %#v, want app %q finding %q", generated.AppID, generated.SourceFindingIDs, app.ID, savedFindings[0].ID)
	}
	if len(model.GenerateRequests) != 1 || !strings.Contains(model.GenerateRequests[0].Prompt, "wordpress-admin-user-added") {
		t.Fatalf("generate requests = %#v, want one evidence-backed prompt", model.GenerateRequests)
	}
}

func TestAnalyzeModelAnalysisQueueGeneratesMissingOpenFindingReports(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	modelReports := newMemoryModelAnalysisReportRepository()
	model := modeltest.NewGateway()
	hub := New(Dependencies{
		Meta: domain.AppMeta{
			Name:    "Aegrail",
			Binary:  "aegrail",
			Version: "test",
		},
		Inventory:    inventory,
		Findings:     findings,
		ModelReports: modelReports,
		Model:        model,
	})
	ctx := context.Background()
	now := time.Date(2026, 5, 13, 11, 0, 0, 0, time.UTC)

	org, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme", Name: "Acme"})
	if err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	project, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site", Name: "Customer Site"})
	if err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production", Name: "Production"})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	_, err = findings.SaveHubFindings(ctx, []domain.HubFinding{
		{
			OrganizationID: org.ID,
			ProjectID:      project.ID,
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         "wordpress-admin-user-added",
			RuleVersion:    "2026-05-12.1",
			DedupeKey:      "wp-user-admin",
			Severity:       domain.SeverityHigh,
			Confidence:     domain.ConfidenceHigh,
			Title:          "WordPress administrator added",
			Summary:        "User roman@example.test became an administrator.",
			EventIDs:       []domain.ID{"event-1"},
			FirstEventAt:   now.Add(-time.Minute),
			LastEventAt:    now,
		},
	})
	if err != nil {
		t.Fatalf("SaveHubFindings returned error: %v", err)
	}

	first, err := hub.AnalyzeModelAnalysisQueue(ctx, AnalyzeModelAnalysisQueueInput{
		Limit:       10,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("AnalyzeModelAnalysisQueue returned error: %v", err)
	}
	if first.Generated != 1 || first.Skipped != 0 || len(model.GenerateRequests) != 1 {
		t.Fatalf("first queue result = %#v requests=%d, want one generated report", first, len(model.GenerateRequests))
	}

	second, err := hub.AnalyzeModelAnalysisQueue(ctx, AnalyzeModelAnalysisQueueInput{
		Limit:       10,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("second AnalyzeModelAnalysisQueue returned error: %v", err)
	}
	if second.Generated != 0 || second.Skipped != 1 || len(model.GenerateRequests) != 1 {
		t.Fatalf("second queue result = %#v requests=%d, want existing report skipped", second, len(model.GenerateRequests))
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

func (r *memoryModelAnalysisReportRepository) FindModelAnalysisReportByEvidence(_ context.Context, environmentID domain.ID, appID domain.ID, findingID domain.ID, evidenceBundleSHA256 string) (domain.ModelAnalysisReport, bool, error) {
	for _, report := range r.reports {
		if report.EnvironmentID != environmentID || report.EvidenceBundleSHA256 != evidenceBundleSHA256 {
			continue
		}
		if appID != "" && report.AppID != appID {
			continue
		}
		for _, sourceFindingID := range report.SourceFindingIDs {
			if sourceFindingID == findingID {
				return report, true, nil
			}
		}
	}
	return domain.ModelAnalysisReport{}, false, nil
}
