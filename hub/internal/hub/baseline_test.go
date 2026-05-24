package hub

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestCompareFileBaselinesFindsCrossHostDifferences(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

	if _, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme", Name: "Acme"}); err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	if _, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site", Name: "Customer Site"}); err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production", Name: "Production"})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	web01, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-01"})
	if err != nil {
		t.Fatalf("SaveHost web-01 returned error: %v", err)
	}
	web02, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-02"})
	if err != nil {
		t.Fatalf("SaveHost web-02 returned error: %v", err)
	}
	agent01, err := hub.SaveAgent(ctx, SaveAgentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", HostSlug: "web-01", AgentID: "agt_web_01", Fingerprint: "SHA256:1"})
	if err != nil {
		t.Fatalf("SaveAgent web-01 returned error: %v", err)
	}
	agent02, err := hub.SaveAgent(ctx, SaveAgentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", HostSlug: "web-02", AgentID: "agt_web_02", Fingerprint: "SHA256:2"})
	if err != nil {
		t.Fatalf("SaveAgent web-02 returned error: %v", err)
	}

	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	ingest.fileObservations = []domain.FileStateObservation{
		{
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          web01.ID,
			AgentID:         agent01.ID,
			HostSlug:        "web-01",
			AgentExternalID: "agt_web_01",
			EventTime:       now.Add(-2 * time.Minute),
			EventType:       "file.modified",
			Severity:        domain.SeverityInfo,
			RelativePath:    "index.php",
			Path:            "/srv/www/index.php",
			SHA256:          "aaa111",
			SizeBytes:       128,
		},
		{
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          web02.ID,
			AgentID:         agent02.ID,
			HostSlug:        "web-02",
			AgentExternalID: "agt_web_02",
			EventTime:       now.Add(-1 * time.Minute),
			EventType:       "file.modified",
			Severity:        domain.SeverityInfo,
			RelativePath:    "index.php",
			Path:            "/var/www/index.php",
			SHA256:          "bbb222",
			SizeBytes:       128,
		},
		{
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          web02.ID,
			AgentID:         agent02.ID,
			HostSlug:        "web-02",
			AgentExternalID: "agt_web_02",
			EventTime:       now,
			EventType:       "file.created",
			Severity:        domain.SeverityHigh,
			RelativePath:    "wp-content/uploads/avatar.php",
			Path:            "/var/www/wp-content/uploads/avatar.php",
			SHA256:          "shell",
			SizeBytes:       42,
		},
	}

	result, err := hub.CompareFileBaselines(ctx, CompareFileBaselinesInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("CompareFileBaselines returned error: %v", err)
	}
	if got, want := result.ObservedHosts, []string{"web-01", "web-02"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("observed hosts = %#v, want %#v", got, want)
	}
	if len(result.Differences) != 2 {
		t.Fatalf("differences = %#v, want 2", result.Differences)
	}

	byPath := map[string]FileBaselineDifference{}
	for _, difference := range result.Differences {
		byPath[difference.RelativePath] = difference
	}
	index := byPath["index.php"]
	if index.Reason != "file state differs across reporting hosts" || index.Severity != domain.SeverityMedium || len(index.Hosts) != 2 {
		t.Fatalf("index.php difference = %#v", index)
	}
	avatar := byPath["wp-content/uploads/avatar.php"]
	if avatar.Reason != "file change observed on one reporting host only" || avatar.Severity != domain.SeverityHigh || len(avatar.Hosts) != 1 {
		t.Fatalf("avatar.php difference = %#v", avatar)
	}
}

type memoryIngestRepository struct {
	fileObservations []domain.FileStateObservation
	timelineEvents   []domain.TimelineEvent
}

func (r *memoryIngestRepository) SaveIngestBatch(ctx context.Context, batch domain.IngestBatch, events []domain.IngestEvent) (domain.IngestBatch, []domain.IngestEvent, bool, error) {
	now := time.Now().UTC()
	if batch.ID == "" {
		batch.ID = domain.ID(fmt.Sprintf("batch-%d", len(r.timelineEvents)+1))
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = now
	}
	savedEvents := make([]domain.IngestEvent, 0, len(events))
	for _, event := range events {
		if event.ID == "" {
			event.ID = domain.ID(fmt.Sprintf("event-%d", len(r.timelineEvents)+1))
		}
		if event.BatchID == "" {
			event.BatchID = batch.ID
		}
		if event.CreatedAt.IsZero() {
			event.CreatedAt = now
		}
		savedEvents = append(savedEvents, event)
		r.timelineEvents = append(r.timelineEvents, domain.TimelineEvent{
			ID:             event.ID,
			BatchID:        event.BatchID,
			OrganizationID: event.OrganizationID,
			ProjectID:      event.ProjectID,
			EnvironmentID:  event.EnvironmentID,
			AppID:          event.AppID,
			ServiceID:      event.ServiceID,
			HostID:         event.HostID,
			AgentID:        event.AgentID,
			EventTime:      event.EventTime,
			ReceivedAt:     event.ReceivedAt,
			EventType:      event.EventType,
			Target:         event.Target,
			Severity:       event.Severity,
			Message:        event.Message,
			Region:         event.Region,
			Labels:         event.Labels,
			Payload:        event.Payload,
			CreatedAt:      event.CreatedAt,
		})
	}
	return batch, savedEvents, true, nil
}

func (r *memoryIngestRepository) ListIngestBatches(ctx context.Context, environmentID domain.ID, limit int) ([]domain.IngestBatch, error) {
	return nil, nil
}

func (r *memoryIngestRepository) ListFileStateObservations(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.FileStateObservation, error) {
	var observations []domain.FileStateObservation
	for _, observation := range r.fileObservations {
		if observation.EnvironmentID != environmentID || observation.AppID != appID || observation.EventTime.Before(since) {
			continue
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

func (r *memoryIngestRepository) ListTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error) {
	var events []domain.TimelineEvent
	for _, event := range r.timelineEvents {
		if event.EnvironmentID != environmentID || event.EventTime.Before(since) {
			continue
		}
		if appID != "" && event.AppID != appID {
			continue
		}
		events = append(events, event)
	}
	return events, nil
}

func (r *memoryIngestRepository) ListTimelineEventsByID(ctx context.Context, environmentID domain.ID, appID domain.ID, eventIDs []domain.ID) ([]domain.TimelineEvent, error) {
	byID := map[domain.ID]domain.TimelineEvent{}
	for _, event := range r.timelineEvents {
		if event.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && event.AppID != appID {
			continue
		}
		byID[event.ID] = event
	}
	events := make([]domain.TimelineEvent, 0, len(eventIDs))
	for _, eventID := range eventIDs {
		if event, ok := byID[eventID]; ok {
			events = append(events, event)
		}
	}
	return events, nil
}
