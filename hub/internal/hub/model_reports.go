package hub

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
	"github.com/rcooler/aegrail/hub/internal/reports"
)

type SaveModelAnalysisReportInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Report           domain.ModelAnalysisReport
}

type ListModelAnalysisReportsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Limit            int
}

type ListModelAnalysisReportsForFindingInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	FindingID        string
	Limit            int
}

type GetModelAnalysisReportInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	ReportID         string
}

type GenerateModelAnalysisReportInput struct {
	OrganizationSlug     string
	ProjectSlug          string
	EnvironmentSlug      string
	AppSlug              string
	FindingID            string
	Model                string
	MaxEventsPerFinding  int
	MaxMetadataDepth     int
	MaxStringLength      int
	MaxCollectionEntries int
	GeneratedAt          time.Time
	StableEvidenceTime   bool
}

type EnsureModelAnalysisReportInput GenerateModelAnalysisReportInput

type EnsureModelAnalysisReportResult struct {
	Report    domain.ModelAnalysisReport
	Generated bool
	Skipped   bool
}

const modelAnalysisRetryAfter = 15 * time.Minute

type findingModelAnalysisContext struct {
	Organization domain.Organization
	Project      domain.Project
	Environment  domain.Environment
	AppSlug      string
	AppID        domain.ID
	AppKind      string
	Finding      domain.HubFinding
	Bundle       reports.EvidenceBundle
	GeneratedAt  time.Time
}

func (h *Hub) SaveModelAnalysisReport(ctx context.Context, input SaveModelAnalysisReportInput) (domain.ModelAnalysisReport, error) {
	if h.modelReports == nil {
		return domain.ModelAnalysisReport{}, errors.New("model analysis report repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return domain.ModelAnalysisReport{}, err
	}
	org, project, environment, err := h.resolveEnvironmentContext(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.ModelAnalysisReport{}, err
	}
	report := input.Report
	report.OrganizationID = org.ID
	report.ProjectID = project.ID
	report.EnvironmentID = environment.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return domain.ModelAnalysisReport{}, err
		}
		report.AppID = app.ID
	}
	if strings.TrimSpace(report.ReportSchema) == "" {
		return domain.ModelAnalysisReport{}, errors.New("model report schema is required")
	}
	if strings.TrimSpace(report.Status) == "" {
		return domain.ModelAnalysisReport{}, errors.New("model report status is required")
	}
	if strings.TrimSpace(report.PromptTemplateID) == "" || strings.TrimSpace(report.PromptTemplateVersion) == "" {
		return domain.ModelAnalysisReport{}, errors.New("model report prompt template id and version are required")
	}
	if strings.TrimSpace(report.PromptSHA256) == "" || strings.TrimSpace(report.EvidenceBundleSHA256) == "" {
		return domain.ModelAnalysisReport{}, errors.New("model report prompt and evidence bundle hashes are required")
	}
	return h.modelReports.SaveModelAnalysisReport(ctx, report)
}

func (h *Hub) ListModelAnalysisReports(ctx context.Context, input ListModelAnalysisReportsInput) ([]domain.ModelAnalysisReport, error) {
	if h.modelReports == nil {
		return nil, errors.New("model analysis report repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return nil, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return nil, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return nil, err
		}
		appID = app.ID
	}
	return h.modelReports.ListModelAnalysisReports(ctx, environment.ID, appID, input.Limit)
}

func (h *Hub) ListModelAnalysisReportsForFinding(ctx context.Context, input ListModelAnalysisReportsForFindingInput) ([]domain.ModelAnalysisReport, error) {
	if h.modelReports == nil {
		return nil, errors.New("model analysis report repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return nil, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return nil, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return nil, err
		}
		appID = app.ID
	}
	findingID := domain.ID(strings.TrimSpace(input.FindingID))
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	return h.modelReports.ListModelAnalysisReportsForFinding(ctx, environment.ID, appID, findingID, input.Limit)
}

func (h *Hub) GetModelAnalysisReport(ctx context.Context, input GetModelAnalysisReportInput) (domain.ModelAnalysisReport, error) {
	if h.modelReports == nil {
		return domain.ModelAnalysisReport{}, errors.New("model analysis report repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return domain.ModelAnalysisReport{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.ModelAnalysisReport{}, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return domain.ModelAnalysisReport{}, err
		}
		appID = app.ID
	}
	reportID := domain.ID(strings.TrimSpace(input.ReportID))
	if reportID == "" {
		return domain.ModelAnalysisReport{}, errors.New("model analysis report id is required")
	}
	return h.modelReports.GetModelAnalysisReport(ctx, reportID, environment.ID, appID)
}

func (h *Hub) GenerateModelAnalysisReport(ctx context.Context, input GenerateModelAnalysisReportInput) (domain.ModelAnalysisReport, error) {
	analysisContext, err := h.buildFindingModelAnalysisContext(ctx, input)
	if err != nil {
		return domain.ModelAnalysisReport{}, err
	}
	return h.generateAndSaveModelAnalysisReport(ctx, analysisContext, input.Model)
}

func (h *Hub) EnsureModelAnalysisReport(ctx context.Context, input EnsureModelAnalysisReportInput) (EnsureModelAnalysisReportResult, error) {
	generateInput := GenerateModelAnalysisReportInput(input)
	generateInput.StableEvidenceTime = true
	analysisContext, err := h.buildFindingModelAnalysisContext(ctx, generateInput)
	if err != nil {
		return EnsureModelAnalysisReportResult{}, err
	}
	template := reports.CurrentModelAnalysisPromptTemplate()
	existing, ok, err := h.modelReports.FindLatestModelAnalysisReportByFinding(
		ctx,
		analysisContext.Environment.ID,
		analysisContext.AppID,
		analysisContext.Finding.ID,
		template.ID,
		template.Version,
		strings.TrimSpace(input.Model),
	)
	if err != nil {
		return EnsureModelAnalysisReportResult{}, err
	}
	if ok && shouldSkipExistingModelAnalysis(existing, time.Now().UTC()) {
		return EnsureModelAnalysisReportResult{
			Report:  existing,
			Skipped: true,
		}, nil
	}
	existing, ok, err = h.modelReports.FindModelAnalysisReportByEvidence(
		ctx,
		analysisContext.Environment.ID,
		analysisContext.AppID,
		analysisContext.Finding.ID,
		analysisContext.Bundle.BundleSHA256,
	)
	if err != nil {
		return EnsureModelAnalysisReportResult{}, err
	}
	if ok && shouldSkipExistingModelAnalysis(existing, time.Now().UTC()) {
		return EnsureModelAnalysisReportResult{
			Report:  existing,
			Skipped: true,
		}, nil
	}
	report, err := h.generateAndSaveModelAnalysisReport(ctx, analysisContext, input.Model)
	if err != nil {
		return EnsureModelAnalysisReportResult{}, err
	}
	return EnsureModelAnalysisReportResult{
		Report:    report,
		Generated: true,
	}, nil
}

func shouldSkipExistingModelAnalysis(report domain.ModelAnalysisReport, now time.Time) bool {
	if strings.EqualFold(report.Status, reports.ModelAnalysisStatusCompleted) {
		return true
	}
	if report.GeneratedAt.IsZero() {
		return true
	}
	return now.UTC().Sub(report.GeneratedAt.UTC()) < modelAnalysisRetryAfter
}

func (h *Hub) buildFindingModelAnalysisContext(ctx context.Context, input GenerateModelAnalysisReportInput) (findingModelAnalysisContext, error) {
	if h.modelReports == nil {
		return findingModelAnalysisContext{}, errors.New("model analysis report repository is not configured")
	}
	if h.findings == nil {
		return findingModelAnalysisContext{}, errors.New("finding repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return findingModelAnalysisContext{}, err
	}
	org, project, environment, err := h.resolveEnvironmentContext(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return findingModelAnalysisContext{}, err
	}

	var appID domain.ID
	var app domain.MonitoredApp
	appSlug := strings.TrimSpace(input.AppSlug)
	if appSlug != "" {
		var resolveErr error
		app, resolveErr = h.resolveAppPath(ctx, org.Slug, project.Slug, environment.Slug, appSlug)
		if resolveErr != nil {
			return findingModelAnalysisContext{}, resolveErr
		}
		appID = app.ID
		appSlug = app.Slug
	}

	findingID := domain.ID(strings.TrimSpace(input.FindingID))
	if findingID == "" {
		return findingModelAnalysisContext{}, errors.New("finding id is required")
	}
	finding, err := h.findings.GetHubFinding(ctx, findingID, environment.ID, appID)
	if err != nil {
		return findingModelAnalysisContext{}, err
	}
	if appID == "" {
		appID = finding.AppID
	}
	appKind := ""
	if appID != "" && app.ID != "" && appKind == "" {
		appKind = app.Kind
	}

	if appKind == "" {
		appKind = resolveMonitoredAppKindForID(ctx, h.inventory, environment.ID, appID)
	}

	evidenceGeneratedAt, reportGeneratedAt := modelAnalysisTimestamps(input, finding)

	findingsReport := reports.BuildHubFindingsJSONReport(h.appMeta(), reports.HubFindingsScope{
		Organization: org.Slug,
		Project:      project.Slug,
		Environment:  environment.Slug,
		App:          appSlug,
	}, []domain.HubFinding{finding}, evidenceGeneratedAt)
	bundleOptions := reports.DefaultEvidenceBundleOptions()
	bundleOptions.MaxFindings = 1
	if input.MaxEventsPerFinding > 0 {
		bundleOptions.MaxEventsPerFinding = input.MaxEventsPerFinding
	}
	if input.MaxMetadataDepth > 0 {
		bundleOptions.MaxMetadataDepth = input.MaxMetadataDepth
	}
	if input.MaxStringLength > 0 {
		bundleOptions.MaxStringLength = input.MaxStringLength
	}
	if input.MaxCollectionEntries > 0 {
		bundleOptions.MaxCollectionEntries = input.MaxCollectionEntries
	}

	bundle, err := reports.BuildEvidenceBundle(findingsReport, bundleOptions)
	if err != nil {
		return findingModelAnalysisContext{}, err
	}
	return findingModelAnalysisContext{
		Organization: org,
		Project:      project,
		Environment:  environment,
		AppSlug:      appSlug,
		AppID:        appID,
		AppKind:      appKind,
		Finding:      finding,
		Bundle:       bundle,
		GeneratedAt:  reportGeneratedAt,
	}, nil
}

func modelAnalysisTimestamps(input GenerateModelAnalysisReportInput, finding domain.HubFinding) (time.Time, time.Time) {
	reportGeneratedAt := input.GeneratedAt
	if reportGeneratedAt.IsZero() {
		reportGeneratedAt = time.Now().UTC()
	} else {
		reportGeneratedAt = reportGeneratedAt.UTC()
	}
	evidenceGeneratedAt := reportGeneratedAt
	if input.StableEvidenceTime {
		evidenceGeneratedAt = stableFindingEvidenceTime(finding)
	}
	return evidenceGeneratedAt, reportGeneratedAt
}

func stableFindingEvidenceTime(finding domain.HubFinding) time.Time {
	for _, value := range []time.Time{
		finding.UpdatedAt,
		finding.LastEventAt,
		finding.CreatedAt,
		finding.FirstEventAt,
	} {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

func (h *Hub) generateAndSaveModelAnalysisReport(ctx context.Context, analysisContext findingModelAnalysisContext, model string) (domain.ModelAnalysisReport, error) {
	generated, err := reports.GenerateModelAnalysisReport(ctx, h.model, analysisContext.Bundle, reports.ModelAnalysisOptions{
		Model:             model,
		AppKind:           analysisContext.AppKind,
		FindingRuleID:     string(analysisContext.Finding.RuleID),
		FindingID:         string(analysisContext.Finding.ID),
		FindingTitle:      analysisContext.Finding.Title,
		FindingSummary:    analysisContext.Finding.Summary,
		FindingSeverity:   string(analysisContext.Finding.Severity),
		FindingConfidence: string(analysisContext.Finding.Confidence),
	}, analysisContext.GeneratedAt)
	if err != nil {
		return domain.ModelAnalysisReport{}, err
	}

	report := reports.DomainModelAnalysisReport(generated)
	if analysisContext.AppID != "" {
		report.AppID = analysisContext.AppID
	}
	return h.SaveModelAnalysisReport(ctx, SaveModelAnalysisReportInput{
		OrganizationSlug: analysisContext.Organization.Slug,
		ProjectSlug:      analysisContext.Project.Slug,
		EnvironmentSlug:  analysisContext.Environment.Slug,
		AppSlug:          analysisContext.AppSlug,
		Report:           report,
	})
}

func resolveMonitoredAppKindForID(ctx context.Context, inventory ports.InventoryRepository, environmentID domain.ID, appID domain.ID) string {
	if inventory == nil || appID == "" {
		return ""
	}
	managedApps, err := inventory.ListMonitoredApps(ctx, environmentID)
	if err != nil || len(managedApps) == 0 {
		return ""
	}
	for _, item := range managedApps {
		if item.ID == appID {
			return strings.TrimSpace(item.Kind)
		}
	}
	return ""
}
