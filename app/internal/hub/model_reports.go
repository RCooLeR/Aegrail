package hub

import (
	"context"
	"errors"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
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

type GetModelAnalysisReportInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	ReportID         string
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
