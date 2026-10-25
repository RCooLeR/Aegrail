package ports

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type HubFindingRepository interface {
	SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error)
	GetHubFinding(ctx context.Context, findingID domain.ID, environmentID domain.ID, appID domain.ID) (domain.HubFinding, error)
	ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error)
	UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error)
	UpdateOpenHubFindingStatuses(ctx context.Context, environmentID domain.ID, appID domain.ID, update domain.HubFindingStatusUpdate) (int, error)
}

// HubFindingPageRepository is an optional extension implemented by finding
// repositories that support stable keyset pagination and scope-wide summaries.
// HubFindingRepository remains unchanged so non-HTTP callers and custom
// repositories keep their existing contract.
type HubFindingPageRepository interface {
	ListHubFindingsPage(ctx context.Context, environmentID domain.ID, appID domain.ID, options HubFindingPageOptions) (HubFindingPage, error)
}

type HubFindingPageOptions struct {
	Limit       int
	After       *HubFindingPageCursor
	SkipSummary bool
	Statuses    []string
	Severities  []string
	Query       string
}

type HubFindingPageCursor struct {
	CreatedAt time.Time
	ID        domain.ID
}

type HubFindingPage struct {
	Findings             []domain.HubFinding
	Summary              HubFindingSummary
	SummaryIncluded      bool
	MatchedTotal         int64
	MatchedTotalIncluded bool
	HasMore              bool
}

type HubFindingSummary struct {
	Total              int64            `json:"total"`
	StatusCounts       map[string]int64 `json:"status_counts"`
	SeverityCounts     map[string]int64 `json:"severity_counts"`
	OpenSeverityCounts map[string]int64 `json:"open_severity_counts"`
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
