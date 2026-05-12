package hub

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

type ListConfigCoverageInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Since            time.Time
	Limit            int
}

type ConfigCoverageRecord struct {
	EventID         domain.ID
	AppID           domain.ID
	AppSlug         string
	HostID          domain.ID
	HostSlug        string
	Hostname        string
	AgentID         domain.ID
	AgentExternalID string
	ReportedAt      time.Time
	ReceivedAt      time.Time
	SiteSlug        string
	SiteKind        string
	CoverageLevel   string
	Labels          map[string]string
	Payload         map[string]any
}

func (h *Hub) ListConfigCoverage(ctx context.Context, input ListConfigCoverageInput) ([]ConfigCoverageRecord, error) {
	if h.ingest == nil {
		return nil, errors.New("ingest repository is not configured")
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 5000
	}
	events, err := h.ListTimelineEvents(ctx, ListTimelineEventsInput{
		OrganizationSlug: input.OrganizationSlug,
		ProjectSlug:      input.ProjectSlug,
		EnvironmentSlug:  input.EnvironmentSlug,
		AppSlug:          input.AppSlug,
		Since:            input.Since,
		Limit:            limit,
	})
	if err != nil {
		return nil, err
	}

	latest := map[string]ConfigCoverageRecord{}
	for _, event := range events {
		if event.EventType != "agent.config.coverage" {
			continue
		}
		record := configCoverageRecord(event)
		key := record.AgentExternalID + "\x00" + record.SiteSlug
		if record.SiteSlug == "" {
			key = record.AgentExternalID + "\x00" + event.Target
		}
		existing, ok := latest[key]
		if !ok || record.ReportedAt.After(existing.ReportedAt) || (record.ReportedAt.Equal(existing.ReportedAt) && record.ReceivedAt.After(existing.ReceivedAt)) {
			latest[key] = record
		}
	}

	records := make([]ConfigCoverageRecord, 0, len(latest))
	for _, record := range latest {
		records = append(records, record)
	}
	slices.SortFunc(records, func(a ConfigCoverageRecord, b ConfigCoverageRecord) int {
		if a.HostSlug != b.HostSlug {
			return strings.Compare(a.HostSlug, b.HostSlug)
		}
		if a.AgentExternalID != b.AgentExternalID {
			return strings.Compare(a.AgentExternalID, b.AgentExternalID)
		}
		return strings.Compare(a.SiteSlug, b.SiteSlug)
	})
	return records, nil
}

func configCoverageRecord(event domain.TimelineEvent) ConfigCoverageRecord {
	site := payloadMap(event.Payload, "site")
	coverage := payloadMap(event.Payload, "coverage")
	siteSlug := firstNonEmpty(
		payloadStringAny(site, "slug", ""),
		event.Labels["site_slug"],
		event.Target,
	)
	return ConfigCoverageRecord{
		EventID:         event.ID,
		AppID:           event.AppID,
		AppSlug:         event.AppSlug,
		HostID:          event.HostID,
		HostSlug:        event.HostSlug,
		Hostname:        event.Hostname,
		AgentID:         event.AgentID,
		AgentExternalID: event.AgentExternalID,
		ReportedAt:      event.EventTime,
		ReceivedAt:      event.ReceivedAt,
		SiteSlug:        siteSlug,
		SiteKind: firstNonEmpty(
			payloadStringAny(site, "kind", ""),
			event.Labels["site_kind"],
		),
		CoverageLevel: firstNonEmpty(
			payloadStringAny(coverage, "level", ""),
			event.Labels["coverage_level"],
		),
		Labels:  cloneStringMap(event.Labels),
		Payload: cloneAnyMap(event.Payload),
	}
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return map[string]any{}
	}
	clone := make(map[string]any, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
