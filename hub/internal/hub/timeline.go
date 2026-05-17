package hub

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type ListTimelineEventsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Since            time.Time
	Limit            int
}

func (h *Hub) ListTimelineEvents(ctx context.Context, input ListTimelineEventsInput) ([]domain.TimelineEvent, error) {
	if h.ingest == nil {
		return nil, errors.New("ingest repository is not configured")
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
	return h.ingest.ListTimelineEvents(ctx, environment.ID, appID, input.Since, input.Limit)
}
