package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/adapters/modeltest"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestAnalyzeModelAnalysisQueueUsesScopeRepositoryAndLimit(t *testing.T) {
	ctx := context.Background()
	inventory := newMemoryInventoryRepository()
	org, project, environment, app := saveModelQueueScope(t, ctx, inventory, "acme", "site", "prod", "main-web")
	findings := &scopedModelQueueFindingRepository{
		memoryHubFindingRepository: newMemoryHubFindingRepository(),
		scopes: []ports.ModelAnalysisQueueScope{
			{Organization: org, Project: project, Environment: environment},
		},
	}
	if _, err := findings.SaveHubFindings(ctx, []domain.HubFinding{
		modelQueueFinding(org, project, environment, app, "admin-user-added", time.Date(2026, 5, 17, 9, 0, 0, 0, time.UTC)),
	}); err != nil {
		t.Fatalf("SaveHubFindings returned error: %v", err)
	}
	model := modeltest.NewGateway()
	hub := New(Dependencies{
		Meta:         domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		Inventory:    inventory,
		Findings:     findings,
		ModelReports: newMemoryModelAnalysisReportRepository(),
		Model:        model,
	})

	result, err := hub.AnalyzeModelAnalysisQueue(ctx, AnalyzeModelAnalysisQueueInput{Limit: 1})
	if err != nil {
		t.Fatalf("AnalyzeModelAnalysisQueue returned error: %v", err)
	}
	if findings.scopeCalls != 1 || findings.lastLimit != 1 {
		t.Fatalf("scope repository calls=%d limit=%d, want one call with limit 1", findings.scopeCalls, findings.lastLimit)
	}
	if result.Scopes != 1 || result.Generated != 1 || len(model.GenerateRequests) != 1 {
		t.Fatalf("result=%#v model requests=%d, want one scoped generated report", result, len(model.GenerateRequests))
	}
}

func TestAnalyzeModelAnalysisQueueFallbackStopsAtScopeLimit(t *testing.T) {
	ctx := context.Background()
	inventory := newMemoryInventoryRepository()
	saveModelQueueScope(t, ctx, inventory, "acme", "site", "prod-a", "main-web")
	saveModelQueueScope(t, ctx, inventory, "acme", "site", "prod-b", "main-web")
	var backgroundErrors []error
	hub := New(Dependencies{
		Meta:         domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		Inventory:    inventory,
		Findings:     newMemoryHubFindingRepository(),
		ModelReports: newMemoryModelAnalysisReportRepository(),
		Model:        modeltest.NewGateway(),
		BackgroundError: func(err error) {
			backgroundErrors = append(backgroundErrors, err)
		},
	})

	result, err := hub.AnalyzeModelAnalysisQueue(ctx, AnalyzeModelAnalysisQueueInput{Limit: 1})
	if err != nil {
		t.Fatalf("AnalyzeModelAnalysisQueue returned error: %v", err)
	}
	if result.Scopes != 1 || result.Generated != 0 || result.Findings != 0 {
		t.Fatalf("result=%#v, want one bounded fallback scope and no generated reports", result)
	}
	if len(backgroundErrors) != 1 {
		t.Fatalf("backgroundErrors=%d, want one fallback warning", len(backgroundErrors))
	}
	if _, err := hub.AnalyzeModelAnalysisQueue(ctx, AnalyzeModelAnalysisQueueInput{Limit: 1}); err != nil {
		t.Fatalf("second AnalyzeModelAnalysisQueue returned error: %v", err)
	}
	if len(backgroundErrors) != 1 {
		t.Fatalf("backgroundErrors=%d after second run, want warning emitted only once", len(backgroundErrors))
	}
}

type scopedModelQueueFindingRepository struct {
	*memoryHubFindingRepository
	scopes     []ports.ModelAnalysisQueueScope
	scopeCalls int
	lastLimit  int
}

func (r *scopedModelQueueFindingRepository) ListModelAnalysisQueueScopes(_ context.Context, limit int) ([]ports.ModelAnalysisQueueScope, error) {
	r.scopeCalls++
	r.lastLimit = limit
	if limit > 0 && len(r.scopes) > limit {
		return append([]ports.ModelAnalysisQueueScope(nil), r.scopes[:limit]...), nil
	}
	return append([]ports.ModelAnalysisQueueScope(nil), r.scopes...), nil
}

func saveModelQueueScope(t *testing.T, ctx context.Context, inventory *memoryInventoryRepository, orgSlug string, projectSlug string, environmentSlug string, appSlug string) (domain.Organization, domain.Project, domain.Environment, domain.MonitoredApp) {
	t.Helper()
	hub := New(Dependencies{Inventory: inventory})
	org, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: orgSlug, Name: orgSlug})
	if err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	project, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: orgSlug, Slug: projectSlug, Name: projectSlug})
	if err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: orgSlug, ProjectSlug: projectSlug, Slug: environmentSlug, Name: environmentSlug})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: orgSlug, ProjectSlug: projectSlug, EnvironmentSlug: environmentSlug, Slug: appSlug, Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	return org, project, environment, app
}

func modelQueueFinding(org domain.Organization, project domain.Project, environment domain.Environment, app domain.MonitoredApp, dedupeKey string, at time.Time) domain.HubFinding {
	return domain.HubFinding{
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  environment.ID,
		AppID:          app.ID,
		RuleID:         "wordpress-admin-user-added",
		RuleVersion:    "2026-05-12.1",
		DedupeKey:      dedupeKey,
		Severity:       domain.SeverityHigh,
		Confidence:     domain.ConfidenceHigh,
		Title:          "WordPress administrator added",
		Summary:        "User roman@example.test became an administrator.",
		EventIDs:       []domain.ID{"event-1"},
		FirstEventAt:   at.Add(-time.Minute),
		LastEventAt:    at,
	}
}
