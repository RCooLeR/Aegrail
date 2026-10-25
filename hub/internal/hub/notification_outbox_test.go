package hub

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type memoryNotificationOutboxRecord struct {
	item          ports.HubFindingNotificationOutboxItem
	nextAttemptAt time.Time
	delivered     bool
	leased        bool
	lastError     string
}

type memoryFindingNotificationOutbox struct {
	*memoryHubFindingRepository
	mu         sync.Mutex
	records    map[string]*memoryNotificationOutboxRecord
	keys       map[string]string
	transports []string
	nextID     int
}

func newMemoryFindingNotificationOutbox(transports ...string) *memoryFindingNotificationOutbox {
	if len(transports) == 0 {
		transports = []string{"email"}
	}
	return &memoryFindingNotificationOutbox{
		memoryHubFindingRepository: newMemoryHubFindingRepository(),
		records:                    map[string]*memoryNotificationOutboxRecord{},
		keys:                       map[string]string{},
		transports:                 transports,
	}
}

func (r *memoryFindingNotificationOutbox) SaveHubFindingsObserved(ctx context.Context, findings []domain.HubFinding, source string) ([]domain.HubFinding, error) {
	saved, err := r.memoryHubFindingRepository.SaveHubFindings(ctx, findings)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, finding := range saved {
		if !hubFindingSaveCreated(finding) || findingStatusValue(finding.Status) != "open" {
			continue
		}
		for _, transport := range r.transports {
			key := "finding.observed:" + string(finding.ID) + ":" + transport
			if _, exists := r.keys[key]; exists {
				continue
			}
			r.nextID++
			id := fmt.Sprintf("outbox-%d", r.nextID)
			notificationFinding := finding
			notificationFinding.Metadata = cloneAnyMap(finding.Metadata)
			delete(notificationFinding.Metadata, domain.HubFindingMetadataSaveCreated)
			r.records[id] = &memoryNotificationOutboxRecord{
				item: ports.HubFindingNotificationOutboxItem{
					ID:        domain.ID(id),
					Transport: transport,
					Notification: ports.HubFindingNotification{
						Type:     "finding.observed",
						SentAt:   time.Now().UTC(),
						Finding:  notificationFinding,
						Metadata: map[string]any{"source": source},
					},
					CreatedAt: time.Now().UTC(),
				},
				nextAttemptAt: time.Now().UTC(),
			}
			r.keys[key] = id
		}
	}
	return saved, nil
}

func (r *memoryFindingNotificationOutbox) ClaimHubFindingNotifications(_ context.Context, options ports.HubFindingNotificationClaimOptions) ([]ports.HubFindingNotificationOutboxItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 50
	}
	findingIDs := map[domain.ID]struct{}{}
	for _, id := range options.FindingIDs {
		findingIDs[id] = struct{}{}
	}
	ids := make([]string, 0, len(r.records))
	for id := range r.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	items := make([]ports.HubFindingNotificationOutboxItem, 0)
	for _, id := range ids {
		record := r.records[id]
		if record.delivered || record.leased || record.nextAttemptAt.After(now) {
			continue
		}
		if len(findingIDs) > 0 {
			if _, ok := findingIDs[record.item.Notification.Finding.ID]; !ok {
				continue
			}
		}
		record.leased = true
		record.item.AttemptCount++
		record.item.LeaseToken = domain.ID(fmt.Sprintf("lease-%s-%d", id, record.item.AttemptCount))
		items = append(items, record.item)
		if len(items) >= limit {
			break
		}
	}
	return items, nil
}

func (r *memoryFindingNotificationOutbox) CompleteHubFindingNotification(_ context.Context, itemID domain.ID, leaseToken domain.ID, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.records[string(itemID)]
	if record == nil || !record.leased || record.item.LeaseToken != leaseToken {
		return ports.ErrHubFindingNotificationLeaseLost
	}
	record.delivered = true
	record.leased = false
	record.item.LeaseToken = ""
	return nil
}

func (r *memoryFindingNotificationOutbox) RetryHubFindingNotification(_ context.Context, itemID domain.ID, leaseToken domain.ID, nextAttemptAt time.Time, lastError string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.records[string(itemID)]
	if record == nil || !record.leased || record.item.LeaseToken != leaseToken {
		return ports.ErrHubFindingNotificationLeaseLost
	}
	record.leased = false
	record.item.LeaseToken = ""
	record.nextAttemptAt = nextAttemptAt
	record.lastError = lastError
	return nil
}

func (r *memoryFindingNotificationOutbox) forceDue() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.records {
		if !record.delivered {
			record.nextAttemptAt = time.Time{}
		}
	}
}

func (r *memoryFindingNotificationOutbox) stats() (count int, delivered int, attempts int, lastError string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.records {
		count++
		attempts += record.item.AttemptCount
		if record.delivered {
			delivered++
		}
		if record.lastError != "" {
			lastError = record.lastError
		}
	}
	return
}

type retryOnceNamedNotificationSink struct {
	mu              sync.Mutex
	attempts        int
	failuresPending int
	notifications   []ports.HubFindingNotification
}

func (s *retryOnceNamedNotificationSink) NotificationTransports() []string {
	return []string{"email"}
}

func (s *retryOnceNamedNotificationSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	return s.NotifyHubFindingTransport(ctx, "email", notification)
}

func (s *retryOnceNamedNotificationSink) NotifyHubFindingTransport(_ context.Context, transport string, notification ports.HubFindingNotification) error {
	if transport != "email" {
		return fmt.Errorf("unexpected transport %q", transport)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	s.notifications = append(s.notifications, notification)
	if s.failuresPending > 0 {
		s.failuresPending--
		return errors.New("smtp temporarily unavailable")
	}
	return nil
}

func TestFindingNotificationOutboxRetriesFailedImmediateEmailAndDeduplicatesIntent(t *testing.T) {
	repository := newMemoryFindingNotificationOutbox()
	sink := &retryOnceNamedNotificationSink{failuresPending: 1}
	hub := New(Dependencies{
		Findings:           repository,
		Notifications:      sink,
		NotificationOutbox: repository,
	})
	input := []domain.HubFinding{{
		EnvironmentID: "environment-1",
		RuleID:        "wordpress-admin-user-added",
		RuleVersion:   "2026-07-29.1",
		DedupeKey:     "administrator:42",
		Severity:      domain.SeverityHigh,
		Confidence:    domain.ConfidenceHigh,
		Title:         "WordPress administrator added",
	}}

	saved, err := hub.saveHubFindingsObserved(context.Background(), input, "correlation")
	if err != nil {
		t.Fatalf("saveHubFindingsObserved returned error: %v", err)
	}
	if len(saved) != 1 {
		t.Fatalf("saved findings = %d, want one", len(saved))
	}
	if count, delivered, attempts, lastError := repository.stats(); count != 1 || delivered != 0 || attempts != 1 || lastError == "" {
		t.Fatalf("after immediate failure count=%d delivered=%d attempts=%d last_error=%q", count, delivered, attempts, lastError)
	}

	repository.forceDue()
	result, err := hub.DeliverPendingHubFindingNotifications(context.Background(), NotificationOutboxDeliveryOptions{MaxBatches: 1})
	if err != nil {
		t.Fatalf("DeliverPendingHubFindingNotifications returned error: %v", err)
	}
	if result.Delivered != 1 || result.Retried != 0 {
		t.Fatalf("retry result = %#v, want one delivered", result)
	}
	if count, delivered, attempts, _ := repository.stats(); count != 1 || delivered != 1 || attempts != 2 {
		t.Fatalf("after retry count=%d delivered=%d attempts=%d, want 1/1/2", count, delivered, attempts)
	}
	if sink.attempts != 2 {
		t.Fatalf("email attempts = %d, want two", sink.attempts)
	}
	if got := sink.notifications[0].Metadata["source"]; got != "correlation" {
		t.Fatalf("notification source = %#v, want correlation", got)
	}
	if _, leaked := sink.notifications[0].Finding.Metadata[domain.HubFindingMetadataSaveCreated]; leaked {
		t.Fatalf("notification leaked internal save marker: %#v", sink.notifications[0].Finding.Metadata)
	}

	if _, err := hub.saveHubFindingsObserved(context.Background(), input, "correlation"); err != nil {
		t.Fatalf("duplicate saveHubFindingsObserved returned error: %v", err)
	}
	if count, delivered, attempts, _ := repository.stats(); count != 1 || delivered != 1 || attempts != 2 {
		t.Fatalf("duplicate upsert changed outbox: count=%d delivered=%d attempts=%d", count, delivered, attempts)
	}
}

type independentlyFailingTransportSink struct {
	mu              sync.Mutex
	attempts        map[string]int
	failuresPending map[string]int
}

func (s *independentlyFailingTransportSink) NotificationTransports() []string {
	return []string{"email", "webpush"}
}

func (s *independentlyFailingTransportSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	for _, transport := range s.NotificationTransports() {
		if err := s.NotifyHubFindingTransport(ctx, transport, notification); err != nil {
			return err
		}
	}
	return nil
}

func (s *independentlyFailingTransportSink) NotifyHubFindingTransport(_ context.Context, transport string, _ ports.HubFindingNotification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[transport]++
	if s.failuresPending[transport] > 0 {
		s.failuresPending[transport]--
		return fmt.Errorf("%s temporarily unavailable", transport)
	}
	return nil
}

func TestFindingNotificationOutboxDoesNotRedeliverSuccessfulEmailWhenWebPushRetries(t *testing.T) {
	repository := newMemoryFindingNotificationOutbox("email", "webpush")
	sink := &independentlyFailingTransportSink{
		attempts:        map[string]int{},
		failuresPending: map[string]int{"webpush": 1},
	}
	hub := New(Dependencies{
		Findings:           repository,
		Notifications:      sink,
		NotificationOutbox: repository,
	})
	input := []domain.HubFinding{{
		EnvironmentID: "environment-1",
		RuleID:        "web-error-rate-spike",
		RuleVersion:   "v1",
		DedupeKey:     "window:1",
		Severity:      domain.SeverityHigh,
		Confidence:    domain.ConfidenceHigh,
		Title:         "Web error rate spike",
	}}
	if _, err := hub.saveHubFindingsObserved(context.Background(), input, "correlation"); err != nil {
		t.Fatalf("saveHubFindingsObserved returned error: %v", err)
	}
	repository.forceDue()
	if _, err := hub.DeliverPendingHubFindingNotifications(context.Background(), NotificationOutboxDeliveryOptions{MaxBatches: 1}); err != nil {
		t.Fatalf("DeliverPendingHubFindingNotifications returned error: %v", err)
	}

	sink.mu.Lock()
	emailAttempts := sink.attempts["email"]
	webPushAttempts := sink.attempts["webpush"]
	sink.mu.Unlock()
	if emailAttempts != 1 || webPushAttempts != 2 {
		t.Fatalf("transport attempts email=%d webpush=%d, want 1/2", emailAttempts, webPushAttempts)
	}
}

func TestNotificationOutboxRetryDelayIsExponentiallyBounded(t *testing.T) {
	if got := notificationOutboxRetryDelay(1, 5*time.Second, time.Minute); got != 5*time.Second {
		t.Fatalf("first retry delay = %s, want 5s", got)
	}
	if got := notificationOutboxRetryDelay(4, 5*time.Second, time.Minute); got != 40*time.Second {
		t.Fatalf("fourth retry delay = %s, want 40s", got)
	}
	if got := notificationOutboxRetryDelay(20, 5*time.Second, time.Minute); got != time.Minute {
		t.Fatalf("bounded retry delay = %s, want 1m", got)
	}
}
