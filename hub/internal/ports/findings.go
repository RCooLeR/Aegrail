package ports

import (
	"context"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type HubFindingRepository interface {
	SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error)
	GetHubFinding(ctx context.Context, findingID domain.ID, environmentID domain.ID, appID domain.ID) (domain.HubFinding, error)
	ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error)
	UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error)
	UpdateOpenHubFindingStatuses(ctx context.Context, environmentID domain.ID, appID domain.ID, update domain.HubFindingStatusUpdate) (int, error)
}

type ModelAnalysisQueueScope struct {
	Organization domain.Organization
	Project      domain.Project
	Environment  domain.Environment
}

type ModelAnalysisQueueScopeRepository interface {
	ListModelAnalysisQueueScopes(ctx context.Context, limit int) ([]ModelAnalysisQueueScope, error)
}

type HubFileIgnoreRuleRepository interface {
	SaveHubFileIgnoreRule(ctx context.Context, rule domain.HubFileIgnoreRule) (domain.HubFileIgnoreRule, error)
	ListActiveHubFileIgnoreRules(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.HubFileIgnoreRule, error)
}
