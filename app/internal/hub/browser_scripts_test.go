package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestListBrowserScriptObservationsFiltersBrowserEvents(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 18, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		browserScriptObservationTimelineEvent("evt-script", environment, app, host, agent, now.Add(-2*time.Minute), "browser.script.observed", map[string]any{
			"page_url":     "https://example.com/",
			"final_url":    "https://example.com/",
			"mode":         "rendered",
			"source_type":  "external",
			"url":          "https://cdn.example.net/app.js",
			"url_redacted": "https://cdn.example.net/app.js",
			"domain":       "cdn.example.net",
			"path":         "/app.js",
			"sha256":       "script-hash",
		}),
		browserScriptObservationTimelineEvent("evt-tag-manager", environment, app, host, agent, now.Add(-time.Minute), "browser.tag_manager.detected", map[string]any{
			"page_url":         "https://example.com/pricing",
			"final_url":        "https://example.com/pricing",
			"mode":             "rendered",
			"source_type":      "external",
			"tag_manager":      true,
			"tag_manager_ids":  []any{"GTM-TEST"},
			"tag_manager_kind": "google_tag_manager",
		}),
		{
			ID:            "evt-file",
			EnvironmentID: environment.ID,
			AppID:         app.ID,
			HostID:        host.ID,
			AgentID:       agent.ID,
			EventTime:     now,
			EventType:     "file.modified",
		},
	}

	records, err := hub.ListBrowserScriptObservations(ctx, ListBrowserScriptObservationsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("ListBrowserScriptObservations returned error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %#v, want two browser observations", records)
	}
	if records[0].EventID != "evt-script" || records[0].Domain != "cdn.example.net" || records[0].SHA256 != "script-hash" {
		t.Fatalf("first record = %#v, want external script observation", records[0])
	}
	if records[1].EventID != "evt-tag-manager" || !records[1].TagManager || len(records[1].TagManagerIDs) != 1 || records[1].TagManagerIDs[0] != "GTM-TEST" {
		t.Fatalf("second record = %#v, want tag manager observation", records[1])
	}

	filtered, err := hub.ListBrowserScriptObservations(ctx, ListBrowserScriptObservationsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		PageURL:          "https://example.com",
		Kind:             "external",
		Since:            now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("ListBrowserScriptObservations with filters returned error: %v", err)
	}
	if len(filtered) != 1 || filtered[0].EventID != "evt-script" {
		t.Fatalf("filtered records = %#v, want only evt-script", filtered)
	}

	limited, err := hub.ListBrowserScriptObservations(ctx, ListBrowserScriptObservationsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		Limit:            1,
	})
	if err != nil {
		t.Fatalf("ListBrowserScriptObservations with limit returned error: %v", err)
	}
	if len(limited) != 1 || limited[0].EventID != "evt-script" {
		t.Fatalf("limited records = %#v, want first browser observation", limited)
	}
}

func browserScriptObservationTimelineEvent(id domain.ID, environment domain.Environment, app domain.MonitoredApp, host domain.Host, agent domain.Agent, eventTime time.Time, eventType string, payload map[string]any) domain.TimelineEvent {
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
		EventType:       eventType,
		Target:          "https://example.com/",
		Severity:        domain.SeverityInfo,
		Labels: map[string]string{
			"collector": "browser",
		},
		Payload: payload,
	}
}
