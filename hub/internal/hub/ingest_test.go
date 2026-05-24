package hub

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
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

func TestIngestEventsQueuesCorrelationWhenJobQueueConfigured(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	queue := &memoryJobQueue{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings, Jobs: queue})
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
							"administrator":   true,
							"account_display": "roman@example.test",
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
	if len(queue.enqueued[ingestCorrelationQueueName]) != 1 {
		t.Fatalf("queued jobs = %#v, want one correlation job", queue.enqueued)
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
	if len(stored) != 0 {
		t.Fatalf("stored findings = %#v, want no inline correlation when queue is configured", stored)
	}

	var job ingestCorrelationJob
	if err := json.Unmarshal(queue.enqueued[ingestCorrelationQueueName][0], &job); err != nil {
		t.Fatalf("correlation job is not valid JSON: %v", err)
	}
	if job.Schema != ingestCorrelationJobSchema || job.OrganizationSlug != "acme" || job.AppSlug != "main-web" {
		t.Fatalf("job = %#v, want scoped ingest correlation job", job)
	}
	if err := hub.HandleCorrelationJob(ctx, queue.enqueued[ingestCorrelationQueueName][0]); err != nil {
		t.Fatalf("HandleCorrelationJob returned error: %v", err)
	}
	stored, err = hub.ListHubFindings(ctx, ListHubFindingsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
	})
	if err != nil {
		t.Fatalf("ListHubFindings after job returned error: %v", err)
	}
	if len(stored) != 1 || stored[0].RuleID != "wordpress-admin-user-added" {
		t.Fatalf("stored findings = %#v, want queued correlation finding", stored)
	}
}

func TestShouldAutoCorrelateIgnoresFileScanHeartbeat(t *testing.T) {
	if shouldAutoCorrelateIngestEvents([]domain.IngestEvent{{
		EventType: "file.scan.completed",
		Severity:  domain.SeverityInfo,
	}}) {
		t.Fatalf("file.scan.completed should not trigger correlation")
	}
	if !shouldAutoCorrelateIngestEvents([]domain.IngestEvent{{
		EventType: "file.modified",
		Severity:  domain.SeverityMedium,
	}}) {
		t.Fatalf("file.modified should trigger correlation")
	}
	if shouldAutoCorrelateIngestEvents([]domain.IngestEvent{{
		EventType: "log.access",
		Severity:  domain.SeverityInfo,
		Target:    "/2-accueil",
		Payload: map[string]any{
			"method":      "GET",
			"path":        "/2-accueil",
			"status_code": 200,
		},
	}}) {
		t.Fatalf("low-signal successful access log should not trigger correlation")
	}
	if !shouldAutoCorrelateIngestEvents([]domain.IngestEvent{{
		EventType: "log.access",
		Severity:  domain.SeverityInfo,
		Target:    "/wp-login.php",
		Payload: map[string]any{
			"method":      "POST",
			"path":        "/wp-login.php",
			"status_code": 302,
		},
	}}) {
		t.Fatalf("admin/login access log should trigger correlation")
	}
	if !shouldAutoCorrelateIngestEvents([]domain.IngestEvent{{
		EventType: "log.access",
		Severity:  domain.SeverityInfo,
		Target:    "/",
		Payload: map[string]any{
			"method":         "GET",
			"path":           "/",
			"status_code":    200,
			"remote_network": "tor_exit",
		},
	}}) {
		t.Fatalf("tor access log should trigger correlation")
	}
}

func TestAutoCorrelationEnqueueCoalescesHotScope(t *testing.T) {
	queue := &memoryJobQueue{}
	hub := New(Dependencies{
		Findings: newMemoryHubFindingRepository(),
		Jobs:     queue,
	})
	now := time.Date(2026, 5, 23, 21, 36, 0, 0, time.UTC)
	events := []domain.IngestEvent{{
		EventTime: now,
		EventType: "db.entity.added",
		Severity:  domain.SeverityHigh,
	}}
	if !hub.enqueueAutoCorrelation(context.Background(), "acme", "site", "production", "main-web", events) {
		t.Fatalf("first enqueue should be accepted")
	}
	if !hub.enqueueAutoCorrelation(context.Background(), "acme", "site", "production", "main-web", events) {
		t.Fatalf("coalesced enqueue should still be treated as handled")
	}
	if got := len(queue.enqueued[ingestCorrelationQueueName]); got != 1 {
		t.Fatalf("queued jobs = %d, want one coalesced job", got)
	}
}

func TestHandleCorrelationJobSkipsStaleBacklog(t *testing.T) {
	hub := New(Dependencies{})
	payload, err := json.Marshal(ingestCorrelationJob{
		Schema:           ingestCorrelationJobSchema,
		OrganizationSlug: "acme",
		ProjectSlug:      "site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		QueuedAt:         time.Now().Add(-defaultCorrelationJobMaxAge - time.Minute),
	})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if err := hub.HandleCorrelationJob(context.Background(), payload); err != nil {
		t.Fatalf("HandleCorrelationJob returned error for stale job: %v", err)
	}
}

func TestHandleCorrelationJobCoalescesHotBacklog(t *testing.T) {
	hub := New(Dependencies{})
	key := autoCorrelationScopeKey("acme", "site", "production", "main-web")
	hub.correlationRunLast[key] = time.Now()
	payload, err := json.Marshal(ingestCorrelationJob{
		Schema:           ingestCorrelationJobSchema,
		OrganizationSlug: "acme",
		ProjectSlug:      "site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		QueuedAt:         time.Now(),
	})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if err := hub.HandleCorrelationJob(context.Background(), payload); err != nil {
		t.Fatalf("HandleCorrelationJob returned error for coalesced job: %v", err)
	}
}

type memoryJobQueue struct {
	enqueued map[string][][]byte
}

func (q *memoryJobQueue) Enqueue(ctx context.Context, queue string, payload []byte) error {
	if q.enqueued == nil {
		q.enqueued = map[string][][]byte{}
	}
	copyPayload := append([]byte(nil), payload...)
	q.enqueued[queue] = append(q.enqueued[queue], copyPayload)
	return nil
}

func (q *memoryJobQueue) Dequeue(ctx context.Context, queue string, timeout time.Duration) ([]byte, error) {
	items := q.enqueued[queue]
	if len(items) == 0 {
		return nil, context.DeadlineExceeded
	}
	item := items[0]
	q.enqueued[queue] = items[1:]
	return item, nil
}
