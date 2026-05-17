package hub

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const (
	defaultModelAnalysisQueueInterval = time.Minute
	defaultModelAnalysisQueueLimit    = 5
)

type AnalyzeModelAnalysisQueueInput struct {
	Limit                int
	Model                string
	MaxEventsPerFinding  int
	MaxMetadataDepth     int
	MaxStringLength      int
	MaxCollectionEntries int
	GeneratedAt          time.Time
}

type AnalyzeModelAnalysisQueueResult struct {
	Scopes    int
	Findings  int
	Generated int
	Skipped   int
	Failed    int
	Errors    []string
}

type ModelAnalysisWorkerOptions struct {
	Interval             time.Duration
	Limit                int
	Model                string
	MaxEventsPerFinding  int
	MaxMetadataDepth     int
	MaxStringLength      int
	MaxCollectionEntries int
	LockTTL              time.Duration
	OnError              func(error)
}

func (h *Hub) StartModelAnalysisWorker(ctx context.Context, options ModelAnalysisWorkerOptions) {
	interval := options.Interval
	if interval <= 0 {
		interval = defaultModelAnalysisQueueInterval
	}
	h.workersWG.Add(1)
	go func() {
		defer h.workersWG.Done()
		h.runModelAnalysisQueueOnce(ctx, options)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runModelAnalysisQueueOnce(ctx, options)
			}
		}
	}()
}

func (h *Hub) runModelAnalysisQueueOnce(ctx context.Context, options ModelAnalysisWorkerOptions) {
	release, ok, err := h.acquireModelAnalysisWorkerLock(ctx, options)
	if err != nil {
		if options.OnError != nil {
			options.OnError(err)
		}
		return
	}
	if !ok {
		return
	}
	defer release()

	_, err = h.AnalyzeModelAnalysisQueue(ctx, AnalyzeModelAnalysisQueueInput{
		Limit:                options.Limit,
		Model:                options.Model,
		MaxEventsPerFinding:  options.MaxEventsPerFinding,
		MaxMetadataDepth:     options.MaxMetadataDepth,
		MaxStringLength:      options.MaxStringLength,
		MaxCollectionEntries: options.MaxCollectionEntries,
	})
	if err != nil && options.OnError != nil {
		options.OnError(err)
	}
}

func (h *Hub) acquireModelAnalysisWorkerLock(ctx context.Context, options ModelAnalysisWorkerOptions) (func(), bool, error) {
	if h.locks == nil {
		return func() {}, true, nil
	}
	ttl := options.LockTTL
	if ttl <= 0 {
		ttl = options.Interval * 2
	}
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	lock, ok, err := h.locks.TryLock(ctx, "model-analysis-worker", ttl)
	if err != nil || !ok {
		return func() {}, ok, err
	}
	return func() {
		_ = lock.Release(context.Background())
	}, true, nil
}

func (h *Hub) AnalyzeModelAnalysisQueue(ctx context.Context, input AnalyzeModelAnalysisQueueInput) (AnalyzeModelAnalysisQueueResult, error) {
	if h.findings == nil {
		return AnalyzeModelAnalysisQueueResult{}, fmt.Errorf("finding repository is not configured")
	}
	if h.modelReports == nil {
		return AnalyzeModelAnalysisQueueResult{}, fmt.Errorf("model analysis report repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return AnalyzeModelAnalysisQueueResult{}, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = defaultModelAnalysisQueueLimit
	}

	result := AnalyzeModelAnalysisQueueResult{}
	organizations, err := h.inventory.ListOrganizations(ctx)
	if err != nil {
		return AnalyzeModelAnalysisQueueResult{}, err
	}
	for _, org := range organizations {
		projects, err := h.inventory.ListProjects(ctx, org.ID)
		if err != nil {
			return result, err
		}
		for _, project := range projects {
			environments, err := h.inventory.ListEnvironments(ctx, project.ID)
			if err != nil {
				return result, err
			}
			for _, environment := range environments {
				if result.Findings >= limit {
					return result, nil
				}
				result.Scopes++
				remaining := limit - result.Findings
				h.analyzeModelAnalysisQueueScope(ctx, input, org, project, environment, remaining, &result)
			}
		}
	}
	return result, nil
}

func (h *Hub) analyzeModelAnalysisQueueScope(ctx context.Context, input AnalyzeModelAnalysisQueueInput, org domain.Organization, project domain.Project, environment domain.Environment, limit int, result *AnalyzeModelAnalysisQueueResult) {
	if limit <= 0 {
		return
	}
	findings, err := h.findings.ListHubFindings(ctx, environment.ID, "", modelAnalysisQueueFetchLimit(limit))
	if err != nil {
		result.Failed++
		result.Errors = append(result.Errors, err.Error())
		return
	}
	for _, finding := range findings {
		if result.Findings >= inputLimit(input.Limit) {
			return
		}
		if !isModelAnalysisQueueFinding(finding) {
			continue
		}
		result.Findings++
		analysis, err := h.EnsureModelAnalysisReport(ctx, EnsureModelAnalysisReportInput{
			OrganizationSlug:     org.Slug,
			ProjectSlug:          project.Slug,
			EnvironmentSlug:      environment.Slug,
			FindingID:            string(finding.ID),
			Model:                input.Model,
			MaxEventsPerFinding:  input.MaxEventsPerFinding,
			MaxMetadataDepth:     input.MaxMetadataDepth,
			MaxStringLength:      input.MaxStringLength,
			MaxCollectionEntries: input.MaxCollectionEntries,
			GeneratedAt:          input.GeneratedAt,
		})
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, err.Error())
			continue
		}
		if analysis.Generated {
			result.Generated++
			continue
		}
		result.Skipped++
	}
}

func inputLimit(limit int) int {
	if limit <= 0 {
		return defaultModelAnalysisQueueLimit
	}
	return limit
}

func modelAnalysisQueueFetchLimit(limit int) int {
	if limit <= 0 {
		limit = defaultModelAnalysisQueueLimit
	}
	fetchLimit := limit * 5
	if fetchLimit < 50 {
		fetchLimit = 50
	}
	if fetchLimit > 500 {
		fetchLimit = 500
	}
	return fetchLimit
}

func isModelAnalysisQueueFinding(finding domain.HubFinding) bool {
	status := strings.TrimSpace(finding.Status)
	return status == "" || status == "open"
}
