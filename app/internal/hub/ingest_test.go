package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestIngestEventsAutoSavesWordPressAdminFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings})
	ctx := context.Background()

	bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 14, 2, 2, 51, 0, time.UTC)
	result, err := hub.IngestEvents(ctx, IngestEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		ExternalBatchID:  "batch-admin-user-added",
		Source:           "agent",
		Events: []IngestEventInput{
			{
				EventTime: now,
				Type:      "db.entity.added",
				Target:    "wordpress:wordpress_user:wordpress_user:abc",
				Severity:  string(domain.SeverityHigh),
				Message:   "Privileged database entity wordpress_user added for wordpress",
				Labels: map[string]string{
					"db_profile":     "wordpress",
					"db_entity_type": "wordpress_user",
				},
				Payload: map[string]any{
					"database":    "wordpress",
					"profile":     "wordpress",
					"entity_type": "wordpress_user",
					"entity_key":  "wordpress_user:abc",
					"current": map[string]any{
						"type":       "wordpress_user",
						"key":        "wordpress_user:abc",
						"privileged": true,
						"signature":  "sig-admin",
						"attributes": map[string]any{
							"administrator":     true,
							"account_display":   "r***n@gmail.com",
							"email_masked":      "r***n@gmail.com",
							"email_hmac_sha256": "fingerprint",
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("IngestEvents returned error: %v", err)
	}
	if result.Reused || len(result.Events) != 1 {
		t.Fatalf("ingest result = %#v, want one newly stored event", result)
	}

	stored, err := hub.ListHubFindings(ctx, ListHubFindingsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
	})
	if err != nil {
		t.Fatalf("ListHubFindings returned error: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored findings = %#v, want one auto-correlated finding", stored)
	}
	finding := stored[0]
	if finding.RuleID != "wordpress-admin-user-added" || finding.Severity != domain.SeverityHigh || finding.Status != "open" {
		t.Fatalf("finding = %#v, want open high WordPress admin-user finding", finding)
	}
	if len(finding.EventIDs) != 1 || finding.EventIDs[0] != result.Events[0].ID {
		t.Fatalf("finding event ids = %#v, want saved ingest event id %q", finding.EventIDs, result.Events[0].ID)
	}
}
