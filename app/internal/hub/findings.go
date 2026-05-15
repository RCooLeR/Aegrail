package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type ListHubFindingsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Limit            int
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
	return h.findings.UpdateHubFindingStatus(ctx, findingID, environment.ID, domain.HubFindingStatusUpdate{
		Status: status,
		Reason: strings.TrimSpace(input.Reason),
		Note:   strings.TrimSpace(input.Note),
		Actor:  strings.TrimSpace(input.Actor),
	})
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
