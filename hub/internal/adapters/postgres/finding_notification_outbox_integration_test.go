package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestFindingNotificationOutboxIsTransactionalDeduplicatedAndLeasedIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubFindingPaginationIntegrationPool(t, ctx)
	defer cleanup()
	if _, err := pool.Exec(ctx, `
		ALTER TABLE hub_findings
			ALTER COLUMN status_updated_at SET DEFAULT now();
		CREATE TABLE hub_finding_notification_outbox (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id uuid NOT NULL REFERENCES hub_findings(id) ON DELETE CASCADE,
			event_type text NOT NULL,
			transport text NOT NULL,
			payload jsonb NOT NULL,
			attempt_count integer NOT NULL DEFAULT 0,
			next_attempt_at timestamptz NOT NULL DEFAULT now(),
			leased_until timestamptz,
			lease_token uuid,
			last_error text NOT NULL DEFAULT '',
			delivered_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (event_type, finding_id, transport)
		);
	`); err != nil {
		t.Fatalf("create notification outbox schema: %v", err)
	}

	repository := NewHubFindingRepositoryWithNotificationTransports(pool, []string{"webpush", "email", "email"})
	observedAt := time.Date(2026, 7, 29, 13, 0, 0, 0, time.UTC)
	finding := domain.HubFinding{
		OrganizationID: "dddddddd-dddd-dddd-dddd-dddddddddddd",
		ProjectID:      "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
		EnvironmentID:  "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		AppID:          "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		RuleID:         "wordpress-admin-user-added",
		RuleVersion:    "v1",
		DedupeKey:      "administrator:42",
		Severity:       domain.SeverityHigh,
		Confidence:     domain.ConfidenceHigh,
		Title:          "WordPress administrator added",
		EventIDs:       []domain.ID{"event-1"},
		FirstEventAt:   observedAt,
		LastEventAt:    observedAt,
	}
	first, err := repository.SaveHubFindingsObserved(ctx, []domain.HubFinding{finding}, "integration")
	if err != nil {
		t.Fatalf("first SaveHubFindingsObserved: %v", err)
	}
	if len(first) != 1 || !postgresHubFindingSaveCreated(first[0]) {
		t.Fatalf("first save = %#v, want newly created finding", first)
	}
	second, err := repository.SaveHubFindingsObserved(ctx, []domain.HubFinding{finding}, "integration")
	if err != nil {
		t.Fatalf("duplicate SaveHubFindingsObserved: %v", err)
	}
	if len(second) != 1 || postgresHubFindingSaveCreated(second[0]) {
		t.Fatalf("duplicate save = %#v, want existing finding", second)
	}
	var intentCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_finding_notification_outbox`).Scan(&intentCount); err != nil {
		t.Fatalf("count notification intents: %v", err)
	}
	if intentCount != 2 {
		t.Fatalf("notification intent count = %d, want one per configured transport", intentCount)
	}

	now := time.Now().UTC().Add(time.Second)
	claimed, err := repository.ClaimHubFindingNotifications(ctx, ports.HubFindingNotificationClaimOptions{
		Limit:         1,
		Now:           now,
		LeaseDuration: time.Minute,
		FindingIDs:    []domain.ID{first[0].ID},
	})
	if err != nil {
		t.Fatalf("first ClaimHubFindingNotifications: %v", err)
	}
	if len(claimed) != 1 || claimed[0].AttemptCount != 1 || claimed[0].LeaseToken == "" {
		t.Fatalf("first claim = %#v, want one leased first attempt", claimed)
	}
	secondClaim, err := repository.ClaimHubFindingNotifications(ctx, ports.HubFindingNotificationClaimOptions{
		Limit:         2,
		Now:           now,
		LeaseDuration: time.Minute,
		FindingIDs:    []domain.ID{first[0].ID},
	})
	if err != nil {
		t.Fatalf("second ClaimHubFindingNotifications: %v", err)
	}
	if len(secondClaim) != 1 {
		t.Fatalf("second claim count = %d, want only the other transport while first is leased", len(secondClaim))
	}
	if secondClaim[0].Transport == claimed[0].Transport {
		t.Fatalf("both claims returned transport %q despite active lease", claimed[0].Transport)
	}

	retryAt := now.Add(5 * time.Second)
	if err := repository.RetryHubFindingNotification(ctx, claimed[0].ID, claimed[0].LeaseToken, retryAt, "smtp temporarily unavailable"); err != nil {
		t.Fatalf("RetryHubFindingNotification: %v", err)
	}
	if err := repository.CompleteHubFindingNotification(ctx, secondClaim[0].ID, secondClaim[0].LeaseToken, now); err != nil {
		t.Fatalf("CompleteHubFindingNotification: %v", err)
	}
	tooEarly, err := repository.ClaimHubFindingNotifications(ctx, ports.HubFindingNotificationClaimOptions{
		Limit:         2,
		Now:           retryAt.Add(-time.Millisecond),
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("early ClaimHubFindingNotifications: %v", err)
	}
	if len(tooEarly) != 0 {
		t.Fatalf("early claim = %#v, want no due retries", tooEarly)
	}
	retried, err := repository.ClaimHubFindingNotifications(ctx, ports.HubFindingNotificationClaimOptions{
		Limit:         2,
		Now:           retryAt,
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatalf("retry ClaimHubFindingNotifications: %v", err)
	}
	if len(retried) != 1 || retried[0].ID != claimed[0].ID || retried[0].AttemptCount != 2 {
		t.Fatalf("retry claim = %#v, want failed intent at attempt two", retried)
	}

	if _, err := pool.Exec(ctx, `DROP TABLE hub_finding_notification_outbox`); err != nil {
		t.Fatalf("drop notification outbox for rollback check: %v", err)
	}
	withoutIntent := finding
	withoutIntent.DedupeKey = "administrator:99"
	if _, err := repository.SaveHubFindingsObserved(ctx, []domain.HubFinding{withoutIntent}, "integration"); err == nil {
		t.Fatal("SaveHubFindingsObserved succeeded without durable outbox table")
	}
	var findingCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_findings`).Scan(&findingCount); err != nil {
		t.Fatalf("count findings after failed notification enqueue: %v", err)
	}
	if findingCount != 1 {
		t.Fatalf("finding count after failed notification enqueue = %d, want original one only", findingCount)
	}
}
