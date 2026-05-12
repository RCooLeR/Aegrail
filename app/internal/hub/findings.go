package hub

import (
	"context"
	"errors"
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
