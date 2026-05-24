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

type ListTimelineEventsByIDInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	EventIDs         []string
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

func (h *Hub) ListTimelineEventsByID(ctx context.Context, input ListTimelineEventsByIDInput) ([]domain.TimelineEvent, error) {
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
	eventIDs := normalizeTimelineEventIDs(input.EventIDs, 200)
	if len(eventIDs) == 0 {
		return []domain.TimelineEvent{}, nil
	}
	return h.ingest.ListTimelineEventsByID(ctx, environment.ID, appID, eventIDs)
}

func normalizeTimelineEventIDs(values []string, limit int) []domain.ID {
	if limit <= 0 {
		limit = 200
	}
	seen := map[string]struct{}{}
	ids := make([]domain.ID, 0, len(values))
	for _, value := range values {
		id := strings.TrimSpace(value)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, domain.ID(id))
		if len(ids) >= limit {
			break
		}
	}
	return ids
}
