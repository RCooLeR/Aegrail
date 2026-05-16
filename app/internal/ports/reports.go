package ports

import (
	"context"

	"github.com/rcooler/aegrail/internal/domain"
)

type ModelAnalysisReportRepository interface {
	SaveModelAnalysisReport(ctx context.Context, report domain.ModelAnalysisReport) (domain.ModelAnalysisReport, error)
	ListModelAnalysisReports(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.ModelAnalysisReport, error)
	GetModelAnalysisReport(ctx context.Context, reportID domain.ID, environmentID domain.ID, appID domain.ID) (domain.ModelAnalysisReport, error)
	FindModelAnalysisReportByEvidence(ctx context.Context, environmentID domain.ID, appID domain.ID, findingID domain.ID, evidenceBundleSHA256 string) (domain.ModelAnalysisReport, bool, error)
}
