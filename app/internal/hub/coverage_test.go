package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestListConfigCoverageReturnsLatestSiteCoverage(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 16, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		coverageTimelineEvent("evt-old-coverage", environment, app, host, agent, now.Add(-10*time.Minute), "example-com", "partial"),
		coverageTimelineEvent("evt-new-coverage", environment, app, host, agent, now, "example-com", "complete"),
		{
			ID:            "evt-file",
			EnvironmentID: environment.ID,
			AppID:         app.ID,
			HostID:        host.ID,
			AgentID:       agent.ID,
			EventTime:     now.Add(time.Minute),
			EventType:     "file.modified",
		},
	}

	records, err := hub.ListConfigCoverage(ctx, ListConfigCoverageInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("ListConfigCoverage returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %#v, want one latest coverage record", records)
	}
	record := records[0]
	if record.EventID != "evt-new-coverage" || record.SiteSlug != "example-com" || record.CoverageLevel != "complete" {
		t.Fatalf("record = %#v, want latest complete coverage", record)
	}
}

func coverageTimelineEvent(id domain.ID, environment domain.Environment, app domain.MonitoredApp, host domain.Host, agent domain.Agent, eventTime time.Time, site string, level string) domain.TimelineEvent {
	return domain.TimelineEvent{
		ID:              id,
		EnvironmentID:   environment.ID,
		AppID:           app.ID,
		AppSlug:         app.Slug,
		HostID:          host.ID,
		HostSlug:        host.Slug,
		Hostname:        host.Hostname,
		AgentID:         agent.ID,
		AgentExternalID: agent.AgentID,
		EventTime:       eventTime,
		ReceivedAt:      eventTime.Add(time.Second),
		EventType:       "agent.config.coverage",
		Target:          site,
		Severity:        domain.SeverityInfo,
		Labels: map[string]string{
			"site_slug":      site,
			"site_kind":      "wordpress",
			"coverage_level": level,
		},
		Payload: map[string]any{
			"site": map[string]any{
				"slug": site,
				"kind": "wordpress",
			},
			"coverage": map[string]any{
				"level": level,
			},
		},
	}
}
