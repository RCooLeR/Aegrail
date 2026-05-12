package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestCorrelateEventsBuildsProbableIncidentChain(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

	if _, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme"}); err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	if _, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site"}); err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production"})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	host, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-02"})
	if err != nil {
		t.Fatalf("SaveHost returned error: %v", err)
	}
	agent, err := hub.SaveAgent(ctx, SaveAgentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", HostSlug: "web-02", AgentID: "agt_web_02", Fingerprint: "SHA256:test"})
	if err != nil {
		t.Fatalf("SaveAgent returned error: %v", err)
	}

	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-login",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "web-02",
			AgentID:         agent.ID,
			AgentExternalID: "agt_web_02",
			EventTime:       now,
			EventType:       "log.access",
			Target:          "/wp-login.php",
			Severity:        domain.SeverityInfo,
			Payload: map[string]any{
				"path":        "/wp-login.php",
				"status_code": 200,
			},
		},
		{
			ID:              "evt-file",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "web-02",
			AgentID:         agent.ID,
			AgentExternalID: "agt_web_02",
			EventTime:       now.Add(4 * time.Minute),
			EventType:       "file.created",
			Target:          "/var/www/wp-content/uploads/avatar.php",
			Severity:        domain.SeverityHigh,
			Payload: map[string]any{
				"relative_path": "wp-content/uploads/avatar.php",
				"sha256":        "shell",
			},
		},
		{
			ID:              "evt-db",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "db-01",
			AgentID:         agent.ID,
			AgentExternalID: "agt_db_01",
			EventTime:       now.Add(8 * time.Minute),
			EventType:       "db.role_changed",
			Target:          "users:42",
			Severity:        domain.SeverityHigh,
			Message:         "role changed from editor to admin",
			Payload:         map[string]any{},
		},
	}

	result, err := hub.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		Window:           30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CorrelateEvents returned error: %v", err)
	}
	if result.Events != 3 {
		t.Fatalf("events = %d, want 3", result.Events)
	}
	if len(result.Chains) == 0 {
		t.Fatal("expected at least one correlation chain")
	}
	if len(result.Chains) != 1 {
		t.Fatalf("chains = %#v, want only the highest-signal chain", result.Chains)
	}
	chain := result.Chains[0]
	if chain.RuleID != "probable-incident-chain" || chain.Severity != domain.SeverityHigh || chain.Confidence != domain.ConfidenceHigh {
		t.Fatalf("chain = %#v", chain)
	}
	if len(chain.Events) != 3 {
		t.Fatalf("chain events = %#v, want 3", chain.Events)
	}
}
