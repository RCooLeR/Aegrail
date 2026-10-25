package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

var hubFindingCursorIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type ListHubFindingsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Limit            int
}

type ListHubFindingsPageInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Limit            int
	Cursor           string
	Statuses         []string
	Severities       []string
	Query            string
}

type ListHubFindingsPageResult struct {
	Findings             []domain.HubFinding
	Total                int64
	NextCursor           string
	Summary              ports.HubFindingSummary
	SummaryIncluded      bool
	MatchedTotal         int64
	MatchedTotalIncluded bool
}

type hubFindingCursorV2 struct {
	Version   int       `json:"v"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

type GetHubFindingInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	FindingID        string
}

type UpdateHubFindingStatusInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	FindingID        string
	Status           string
	Reason           string
	Note             string
	Actor            string
}

type AcceptHubFindingsBaselineInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Reason           string
	Note             string
	Actor            string
}

type AcceptHubFindingsBaselineResult struct {
	Updated int
	Status  string
	Reason  string
	Note    string
	Actor   string
}

func (h *Hub) ListHubFindings(ctx context.Context, input ListHubFindingsInput) ([]domain.HubFinding, error) {
	if h.findings == nil {
		return nil, errors.New("finding repository is not configured")
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
	return h.findings.ListHubFindings(ctx, environment.ID, appID, input.Limit)
}

func (h *Hub) ListHubFindingsPage(ctx context.Context, input ListHubFindingsPageInput) (ListHubFindingsPageResult, error) {
	if h.findings == nil {
		return ListHubFindingsPageResult{}, errors.New("finding repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return ListHubFindingsPageResult{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return ListHubFindingsPageResult{}, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return ListHubFindingsPageResult{}, err
		}
		appID = app.ID
	}
	cursor, err := decodeHubFindingCursor(input.Cursor)
	if err != nil {
		return ListHubFindingsPageResult{}, err
	}
	statuses, err := normalizeHubFindingFilterValues(input.Statuses, "status", []string{"open", "acknowledged", "false_positive", "resolved"})
	if err != nil {
		return ListHubFindingsPageResult{}, err
	}
	severities, err := normalizeHubFindingFilterValues(input.Severities, "severity", []string{"info", "low", "medium", "high", "critical"})
	if err != nil {
		return ListHubFindingsPageResult{}, err
	}
	query := strings.TrimSpace(input.Query)
	pageRepository, ok := h.findings.(ports.HubFindingPageRepository)
	if !ok {
		if len(statuses) > 0 || len(severities) > 0 || query != "" || cursor != nil {
			return ListHubFindingsPageResult{}, errors.New("finding repository does not support filtered pagination")
		}
		// Compatibility fallback for custom repositories. The production
		// PostgreSQL repository implements HubFindingPageRepository.
		findings, err := h.findings.ListHubFindings(ctx, environment.ID, appID, input.Limit)
		if err != nil {
			return ListHubFindingsPageResult{}, err
		}
		// A legacy limited list cannot prove a scope-wide total or summary.
		// Return only the records so callers do not mistake the page length
		// for an exact count.
		return ListHubFindingsPageResult{Findings: findings}, nil
	}
	page, err := pageRepository.ListHubFindingsPage(ctx, environment.ID, appID, ports.HubFindingPageOptions{
		Limit:       input.Limit,
		After:       cursor,
		SkipSummary: cursor != nil,
		Statuses:    statuses,
		Severities:  severities,
		Query:       query,
	})
	if err != nil {
		return ListHubFindingsPageResult{}, err
	}
	var nextCursor string
	if page.HasMore && len(page.Findings) > 0 {
		nextCursor, err = encodeHubFindingCursor(page.Findings[len(page.Findings)-1])
		if err != nil {
			return ListHubFindingsPageResult{}, err
		}
	}
	return ListHubFindingsPageResult{
		Findings:             page.Findings,
		Total:                page.Summary.Total,
		NextCursor:           nextCursor,
		Summary:              page.Summary,
		SummaryIncluded:      page.SummaryIncluded,
		MatchedTotal:         page.MatchedTotal,
		MatchedTotalIncluded: page.MatchedTotalIncluded,
	}, nil
}

func normalizeHubFindingFilterValues(values []string, name string, allowed []string) ([]string, error) {
	allowedValues := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedValues[value] = struct{}{}
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := allowedValues[value]; !ok {
			return nil, fmt.Errorf("finding %s %q is not supported", name, value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

func encodeHubFindingCursor(finding domain.HubFinding) (string, error) {
	payload, err := json.Marshal(hubFindingCursorV2{
		Version:   2,
		CreatedAt: finding.CreatedAt.UTC(),
		ID:        string(finding.ID),
	})
	if err != nil {
		return "", fmt.Errorf("encode finding cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeHubFindingCursor(value string) (*ports.HubFindingPageCursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("finding cursor is invalid")
	}
	var cursor hubFindingCursorV2
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return nil, errors.New("finding cursor is invalid")
	}
	cursorID := strings.TrimSpace(cursor.ID)
	if cursor.Version != 2 || cursor.CreatedAt.IsZero() || !hubFindingCursorIDPattern.MatchString(cursorID) {
		return nil, errors.New("finding cursor is invalid")
	}
	return &ports.HubFindingPageCursor{
		CreatedAt: cursor.CreatedAt.UTC(),
		ID:        domain.ID(cursorID),
	}, nil
}

func (h *Hub) GetHubFinding(ctx context.Context, input GetHubFindingInput) (domain.HubFinding, error) {
	if h.findings == nil {
		return domain.HubFinding{}, errors.New("finding repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return domain.HubFinding{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.HubFinding{}, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return domain.HubFinding{}, err
		}
		appID = app.ID
	}
	findingID := domain.ID(strings.TrimSpace(input.FindingID))
	if findingID == "" {
		return domain.HubFinding{}, errors.New("finding id is required")
	}
	return h.findings.GetHubFinding(ctx, findingID, environment.ID, appID)
}

func (h *Hub) UpdateHubFindingStatus(ctx context.Context, input UpdateHubFindingStatusInput) (domain.HubFinding, error) {
	if h.findings == nil {
		return domain.HubFinding{}, errors.New("finding repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return domain.HubFinding{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.HubFinding{}, err
	}
	findingID := domain.ID(strings.TrimSpace(input.FindingID))
	if findingID == "" {
		return domain.HubFinding{}, errors.New("finding id is required")
	}
	status, err := normalizeHubFindingStatus(input.Status)
	if err != nil {
		return domain.HubFinding{}, err
	}
	previous, err := h.findings.GetHubFinding(ctx, findingID, environment.ID, "")
	if err != nil {
		return domain.HubFinding{}, err
	}
	updated, err := h.findings.UpdateHubFindingStatus(ctx, findingID, environment.ID, domain.HubFindingStatusUpdate{
		Status: status,
		Reason: strings.TrimSpace(input.Reason),
		Note:   strings.TrimSpace(input.Note),
		Actor:  strings.TrimSpace(input.Actor),
	})
	if err != nil {
		return domain.HubFinding{}, err
	}
	if err := h.notifyHubFindingStatus(ctx, updated, findingStatusValue(previous.Status), map[string]any{"source": "finding_status"}); err != nil {
		return domain.HubFinding{}, err
	}
	return updated, nil
}

func (h *Hub) AcceptHubFindingsBaseline(ctx context.Context, input AcceptHubFindingsBaselineInput) (AcceptHubFindingsBaselineResult, error) {
	if h.findings == nil {
		return AcceptHubFindingsBaselineResult{}, errors.New("finding repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return AcceptHubFindingsBaselineResult{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return AcceptHubFindingsBaselineResult{}, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return AcceptHubFindingsBaselineResult{}, err
		}
		appID = app.ID
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		reason = "baseline_accepted"
	}
	note := strings.TrimSpace(input.Note)
	if note == "" {
		note = "Accepted current open findings as the safe baseline. Matching findings stay triaged; new future findings still open."
	}
	actor := strings.TrimSpace(input.Actor)
	if actor == "" {
		actor = "dashboard"
	}
	update := domain.HubFindingStatusUpdate{
		Status: "acknowledged",
		Reason: reason,
		Note:   note,
		Actor:  actor,
	}
	updated, err := h.findings.UpdateOpenHubFindingStatuses(ctx, environment.ID, appID, update)
	if err != nil {
		return AcceptHubFindingsBaselineResult{}, err
	}
	return AcceptHubFindingsBaselineResult{
		Updated: updated,
		Status:  update.Status,
		Reason:  update.Reason,
		Note:    update.Note,
		Actor:   update.Actor,
	}, nil
}

func normalizeHubFindingStatus(value string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(value))
	switch status {
	case "open", "acknowledged", "false_positive", "resolved":
		return status, nil
	case "ack", "acknowledge":
		return "acknowledged", nil
	case "false-positive", "false positive", "fp":
		return "false_positive", nil
	case "resolve":
		return "resolved", nil
	default:
		return "", fmt.Errorf("finding status %q is not supported", value)
	}
}
