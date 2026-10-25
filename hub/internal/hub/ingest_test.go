package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
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

func TestIngestEventsRunsImmediateCorrelationWhenJobQueueConfigured(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	queue := &memoryJobQueue{}
	notifications := &memoryNotificationSink{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings, Jobs: queue, Notifications: notifications})
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
	if got := len(queue.enqueued[ingestCorrelationQueueName]); got != 0 {
		t.Fatalf("queued jobs = %d, want immediate correlation without queue backlog", got)
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
	if len(stored) != 1 || stored[0].RuleID != "wordpress-admin-user-added" {
		t.Fatalf("stored findings = %#v, want immediate queued-scope correlation finding", stored)
	}
	if len(notifications.items) != 1 || notifications.items[0].Type != "finding.observed" {
		t.Fatalf("notifications = %#v, want immediate observed notification", notifications.items)
	}
}

func TestIngestEventsCorrelatesEveryCandidateBatchWithoutLosingThresholdCrossing(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	notifications := &memoryNotificationSink{}
	hub := New(Dependencies{
		Inventory:     inventory,
		Ingest:        ingest,
		Findings:      findings,
		Notifications: notifications,
	})
	ctx := context.Background()

	bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	start := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	webError := func(at time.Time) IngestEventInput {
		return IngestEventInput{
			EventTime: at,
			Type:      "log.access",
			Target:    "/checkout",
			Severity:  string(domain.SeverityMedium),
			Message:   "GET /checkout returned 500",
			Payload: map[string]any{
				"method":      "GET",
				"path":        "/checkout",
				"status_code": 500,
				"remote_addr": "198.51.100.42",
			},
		}
	}

	firstBatch := make([]IngestEventInput, 0, webErrorRateThreshold-1)
	for index := range webErrorRateThreshold - 1 {
		firstBatch = append(firstBatch, webError(start.Add(time.Duration(index)*time.Second)))
	}
	if _, err := hub.IngestEvents(ctx, IngestEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		ExternalBatchID:  "batch-web-errors-before-threshold",
		Source:           "agent",
		Events:           firstBatch,
	}); err != nil {
		t.Fatalf("first IngestEvents returned error: %v", err)
	}

	if _, err := hub.IngestEvents(ctx, IngestEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		ExternalBatchID:  "batch-web-errors-crossing-threshold",
		Source:           "agent",
		Events: []IngestEventInput{
			webError(start.Add(time.Duration(webErrorRateThreshold) * time.Second)),
		},
	}); err != nil {
		t.Fatalf("second IngestEvents returned error: %v", err)
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
	if len(stored) != 1 || stored[0].RuleID != "web-error-rate-spike" {
		t.Fatalf("stored findings = %#v, want one immediate web-error-rate-spike finding", stored)
	}
	if len(notifications.items) != 1 || notifications.items[0].Finding.RuleID != "web-error-rate-spike" {
		t.Fatalf("notifications = %#v, want one immediate observed notification", notifications.items)
	}
}

func TestIngestEventsCorrelatesClientErrorThresholdAcrossTwoBatches(t *testing.T) {
	for _, status := range []int{404, 429} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			inventory := newMemoryInventoryRepository()
			ingest := &memoryIngestRepository{}
			findings := newMemoryHubFindingRepository()
			notifications := &memoryNotificationSink{}
			hub := New(Dependencies{
				Inventory:     inventory,
				Ingest:        ingest,
				Findings:      findings,
				Notifications: notifications,
			})
			ctx := context.Background()

			bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
			start := time.Date(2026, 7, 29, 12, 10, 0, 0, time.UTC)
			clientError := func(at time.Time) IngestEventInput {
				return IngestEventInput{
					EventTime: at,
					Type:      "log.access",
					Target:    "/unknown-probe",
					Severity:  string(domain.SeverityInfo),
					Message:   fmt.Sprintf("GET /unknown-probe returned %d", status),
					Payload: map[string]any{
						"method":      "GET",
						"path":        "/unknown-probe",
						"status_code": status,
						"remote_addr": "198.51.100.42",
					},
				}
			}

			firstBatch := make([]IngestEventInput, 0, webRequestVolumeThreshold-1)
			for index := range webRequestVolumeThreshold - 1 {
				firstBatch = append(firstBatch, clientError(start.Add(time.Duration(index)*time.Second)))
			}
			if _, err := hub.IngestEvents(ctx, IngestEventsInput{
				OrganizationSlug: "acme",
				ProjectSlug:      "customer-site",
				EnvironmentSlug:  "production",
				AppSlug:          "main-web",
				HostSlug:         "web-01",
				AgentID:          "agt_web_01",
				ExternalBatchID:  fmt.Sprintf("batch-%d-before-threshold", status),
				Source:           "agent",
				Events:           firstBatch,
			}); err != nil {
				t.Fatalf("first IngestEvents returned error: %v", err)
			}

			if _, err := hub.IngestEvents(ctx, IngestEventsInput{
				OrganizationSlug: "acme",
				ProjectSlug:      "customer-site",
				EnvironmentSlug:  "production",
				AppSlug:          "main-web",
				HostSlug:         "web-01",
				AgentID:          "agt_web_01",
				ExternalBatchID:  fmt.Sprintf("batch-%d-crossing-threshold", status),
				Source:           "agent",
				Events: []IngestEventInput{
					clientError(start.Add(time.Duration(webRequestVolumeThreshold) * time.Second)),
				},
			}); err != nil {
				t.Fatalf("second IngestEvents returned error: %v", err)
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
			if len(stored) != 1 || stored[0].RuleID != "web-request-volume-spike" {
				t.Fatalf("stored findings = %#v, want one immediate web-request-volume-spike finding", stored)
			}
			if len(notifications.items) != 1 || notifications.items[0].Finding.RuleID != "web-request-volume-spike" {
				t.Fatalf("notifications = %#v, want one immediate observed notification", notifications.items)
			}
		})
	}
}

func TestConcurrentCandidateIngestForcesFollowupCorrelation(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := newBlockingCorrelationIngestRepository()
	findings := newMemoryHubFindingRepository()
	notifications := &memoryNotificationSink{}
	hub := New(Dependencies{
		Inventory:     inventory,
		Ingest:        ingest,
		Findings:      findings,
		Notifications: notifications,
	})
	ctx := context.Background()

	bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	start := time.Date(2026, 7, 29, 12, 20, 0, 0, time.UTC)
	webError := func(at time.Time) IngestEventInput {
		return IngestEventInput{
			EventTime: at,
			Type:      "log.access",
			Target:    "/checkout",
			Severity:  string(domain.SeverityMedium),
			Message:   "GET /checkout returned 500",
			Payload: map[string]any{
				"method":      "GET",
				"path":        "/checkout",
				"status_code": 500,
				"remote_addr": "198.51.100.42",
			},
		}
	}
	firstEvents := make([]IngestEventInput, 0, webErrorRateThreshold-1)
	for index := range webErrorRateThreshold - 1 {
		firstEvents = append(firstEvents, webError(start.Add(time.Duration(index)*time.Second)))
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := hub.IngestEvents(ctx, IngestEventsInput{
			OrganizationSlug: "acme",
			ProjectSlug:      "customer-site",
			EnvironmentSlug:  "production",
			AppSlug:          "main-web",
			HostSlug:         "web-01",
			AgentID:          "agt_web_01",
			ExternalBatchID:  "batch-concurrent-before-threshold",
			Source:           "agent",
			Events:           firstEvents,
		})
		firstDone <- err
	}()

	select {
	case <-ingest.firstListStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first correlation scan did not start")
	}

	if _, err := hub.IngestEvents(ctx, IngestEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		ExternalBatchID:  "batch-concurrent-crossing-threshold",
		Source:           "agent",
		Events: []IngestEventInput{
			webError(start.Add(time.Duration(webErrorRateThreshold) * time.Second)),
		},
	}); err != nil {
		t.Fatalf("concurrent IngestEvents returned error: %v", err)
	}
	close(ingest.releaseFirstList)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first IngestEvents returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("correlation leader did not finish")
	}

	if got := ingest.timelineListCallCount(); got != 2 {
		t.Fatalf("timeline list calls = %d, want initial scan plus one dirty follow-up", got)
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
	if len(stored) != 1 || stored[0].RuleID != "web-error-rate-spike" {
		t.Fatalf("stored findings = %#v, want threshold finding from dirty follow-up", stored)
	}
	if len(notifications.items) != 1 || notifications.items[0].Finding.RuleID != "web-error-rate-spike" {
		t.Fatalf("notifications = %#v, want immediate observed notification", notifications.items)
	}
	if len(hub.correlationRuns) != 0 {
		t.Fatalf("correlation runs = %#v, want completed scope state removed", hub.correlationRuns)
	}
}

func TestHandleOldV2CorrelationJobSavesQueuedCorrelationFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	queue := &memoryJobQueue{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings, Jobs: queue})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 14, 2, 2, 51, 0, time.UTC)
	_, _, _, err := ingest.SaveIngestBatch(ctx, domain.IngestBatch{
		ExternalID:     "manual-batch",
		OrganizationID: "org-001",
		ProjectID:      environment.ProjectID,
		EnvironmentID:  environment.ID,
		AppID:          app.ID,
		ServiceID:      "service-001",
		HostID:         host.ID,
		AgentID:        agent.ID,
	}, []domain.IngestEvent{
		{
			ID:             "evt-manual-admin-added",
			OrganizationID: "org-001",
			ProjectID:      "project-001",
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			ServiceID:      "service-001",
			HostID:         host.ID,
			AgentID:        agent.ID,
			EventTime:      now,
			EventType:      "db.entity.added",
			Target:         "wordpress:wordpress_user:wordpress_user:abc",
			Severity:       domain.SeverityHigh,
			Message:        "Privileged database entity wordpress_user added for wordpress",
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
	})
	if err != nil {
		t.Fatalf("SaveIngestBatch returned error: %v", err)
	}
	if !hub.enqueueAutoCorrelation(ctx, "acme", "customer-site", "production", "main-web", []domain.IngestEvent{{
		ID:        "evt-manual-admin-added",
		EventTime: now,
		EventType: "db.entity.added",
		Severity:  domain.SeverityHigh,
	}}) {
		t.Fatalf("enqueueAutoCorrelation returned false")
	}
	var job ingestCorrelationJob
	if err := json.Unmarshal(queue.enqueued[ingestCorrelationQueueName][0], &job); err != nil {
		t.Fatalf("correlation job is not valid JSON: %v", err)
	}
	if job.Schema != ingestCorrelationJobSchema || job.OrganizationSlug != "acme" || job.AppSlug != "main-web" ||
		len(job.TriggerEventIDs) != 1 || job.TriggerEventIDs[0] != "evt-manual-admin-added" {
		t.Fatalf("job = %#v, want scoped ingest correlation job", job)
	}
	job.QueuedAt = time.Now().Add(-48 * time.Hour)
	oldPayload, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("Marshal old v2 job returned error: %v", err)
	}
	if err := hub.HandleCorrelationJob(ctx, oldPayload); err != nil {
		t.Fatalf("HandleCorrelationJob returned error: %v", err)
	}
	stored, err := hub.ListHubFindings(ctx, ListHubFindingsInput{
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
	for _, status := range []int{404, 429} {
		if !shouldAutoCorrelateIngestEvents([]domain.IngestEvent{{
			EventType: "log.access",
			Severity:  domain.SeverityInfo,
			Target:    "/unknown-probe",
			Payload: map[string]any{
				"method":      "GET",
				"path":        "/unknown-probe",
				"status_code": status,
			},
		}}) {
			t.Fatalf("ordinary HTTP %d access log should trigger correlation", status)
		}
	}
}

func TestAutoCorrelationFallbackEnqueuesEveryTriggerBatch(t *testing.T) {
	queue := &memoryJobQueue{}
	hub := New(Dependencies{
		Findings: newMemoryHubFindingRepository(),
		Jobs:     queue,
	})
	now := time.Date(2026, 5, 23, 21, 36, 0, 0, time.UTC)
	firstEvents := []domain.IngestEvent{{
		ID:        "event-first",
		EventTime: now,
		EventType: "db.entity.added",
		Severity:  domain.SeverityHigh,
	}}
	secondEvents := []domain.IngestEvent{{
		ID:        "event-second",
		EventTime: now.Add(time.Second),
		EventType: "db.entity.added",
		Severity:  domain.SeverityHigh,
	}}
	if !hub.enqueueAutoCorrelation(context.Background(), "acme", "site", "production", "main-web", firstEvents) {
		t.Fatalf("first enqueue should be accepted")
	}
	if !hub.enqueueAutoCorrelation(context.Background(), "acme", "site", "production", "main-web", secondEvents) {
		t.Fatalf("second enqueue should be accepted")
	}
	jobs := queue.enqueued[ingestCorrelationQueueName]
	if got := len(jobs); got != 2 {
		t.Fatalf("queued jobs = %d, want one fallback job per trigger batch", got)
	}
	for index, expectedID := range []domain.ID{"event-first", "event-second"} {
		var job ingestCorrelationJob
		if err := json.Unmarshal(jobs[index], &job); err != nil {
			t.Fatalf("job %d is invalid JSON: %v", index, err)
		}
		if len(job.TriggerEventIDs) != 1 || job.TriggerEventIDs[0] != expectedID {
			t.Fatalf("job %d trigger ids = %#v, want %q", index, job.TriggerEventIDs, expectedID)
		}
	}
}

func TestHandleCorrelationJobIgnoresLegacySchema(t *testing.T) {
	hub := New(Dependencies{})
	payload, err := json.Marshal(ingestCorrelationJob{
		Schema:           "aegrail.hub.job.ingest-correlation.v1",
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
		t.Fatalf("legacy correlation job should be ignored safely: %v", err)
	}
}

func TestAutoCorrelationSingleFlightMarksHotScopePending(t *testing.T) {
	hub := New(Dependencies{})
	key := autoCorrelationScopeKey("acme", "site", "production", "main-web")
	first := CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		Window:           autoCorrelationWindow,
		Limit:            100,
		SaveFindings:     true,
		TriggerEventIDs:  []domain.ID{"event-first"},
	}
	if !hub.beginAutoCorrelationRun(key, first) {
		t.Fatal("first scope run should become the leader")
	}
	second := first
	second.Since = first.Since.Add(-time.Minute)
	second.Limit = 500
	second.TriggerEventIDs = []domain.ID{"event-second"}
	if hub.beginAutoCorrelationRun(key, second) {
		t.Fatal("concurrent scope run should be coalesced as pending")
	}
	third := second
	third.TriggerEventIDs = []domain.ID{"event-third", "event-second"}
	if hub.beginAutoCorrelationRun(key, third) {
		t.Fatal("third concurrent scope run should also be coalesced as pending")
	}
	next, rerun := hub.completeAutoCorrelationRun(key)
	if !rerun {
		t.Fatal("leader completion should require a dirty follow-up")
	}
	if !next.Since.Equal(second.Since) || next.Limit != second.Limit {
		t.Fatalf("next input = %#v, want merged pending scope input", next)
	}
	if got, want := next.TriggerEventIDs, []domain.ID{"event-second", "event-third"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("next trigger ids = %#v, want %#v", got, want)
	}
	if _, rerun := hub.completeAutoCorrelationRun(key); rerun {
		t.Fatal("clean follow-up completion should release the scope")
	}
	if len(hub.correlationRuns) != 0 {
		t.Fatalf("correlation runs = %#v, want released scope", hub.correlationRuns)
	}
}

type blockingCorrelationIngestRepository struct {
	*memoryIngestRepository
	mu                sync.Mutex
	firstListStarted  chan struct{}
	releaseFirstList  chan struct{}
	timelineListCalls int
}

func newBlockingCorrelationIngestRepository() *blockingCorrelationIngestRepository {
	return &blockingCorrelationIngestRepository{
		memoryIngestRepository: &memoryIngestRepository{},
		firstListStarted:       make(chan struct{}),
		releaseFirstList:       make(chan struct{}),
	}
}

func (r *blockingCorrelationIngestRepository) SaveIngestBatch(
	ctx context.Context,
	batch domain.IngestBatch,
	events []domain.IngestEvent,
) (domain.IngestBatch, []domain.IngestEvent, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.memoryIngestRepository.SaveIngestBatch(ctx, batch, events)
}

func (r *blockingCorrelationIngestRepository) ListTimelineEvents(
	ctx context.Context,
	environmentID domain.ID,
	appID domain.ID,
	since time.Time,
	limit int,
) ([]domain.TimelineEvent, error) {
	r.mu.Lock()
	r.timelineListCalls++
	call := r.timelineListCalls
	events, err := r.memoryIngestRepository.ListTimelineEvents(ctx, environmentID, appID, since, limit)
	r.mu.Unlock()
	if call == 1 {
		close(r.firstListStarted)
		select {
		case <-r.releaseFirstList:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return events, err
}

func (r *blockingCorrelationIngestRepository) timelineListCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.timelineListCalls
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
