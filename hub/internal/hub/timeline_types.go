package hub

import (
	"context"
	"errors"
	"strings"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func (h *Hub) listTimelineEventsByTypes(ctx context.Context, input ListTimelineEventsInput, eventTypes []string, limit int) ([]domain.TimelineEvent, error) {
	normalizedTypes := make([]string, 0, len(eventTypes))
	seen := map[string]struct{}{}
	for _, eventType := range eventTypes {
		eventType = strings.TrimSpace(eventType)
		if eventType == "" {
			continue
		}
		if _, ok := seen[eventType]; ok {
			continue
		}
		seen[eventType] = struct{}{}
		normalizedTypes = append(normalizedTypes, eventType)
	}
	if len(normalizedTypes) == 0 {
		return []domain.TimelineEvent{}, nil
	}
	input.Limit = limit
	typeRepository, ok := h.ingest.(ports.IngestTimelineEventTypeRepository)
	if !ok {
		return h.ListTimelineEvents(ctx, input)
	}
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
	return typeRepository.ListTimelineEventsByTypes(ctx, environment.ID, appID, input.Since, normalizedTypes, limit)
}
