package webpushnotify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestNewNotificationSinkDisabledWhenUnconfigured(t *testing.T) {
	sink, err := NewNotificationSink(nil, Config{})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	if sink != nil {
		t.Fatalf("sink = %#v, want nil", sink)
	}
}

func TestNewNotificationSinkRequiresVAPIDPair(t *testing.T) {
	_, err := NewNotificationSink(memoryPushSubscriptions{}, Config{PublicKey: "public-only"})
	if err == nil {
		t.Fatalf("NewNotificationSink returned nil error")
	}
}

func TestNewNotificationSinkNormalizesMailtoSubject(t *testing.T) {
	sink, err := NewNotificationSink(memoryPushSubscriptions{}, Config{
		PublicKey:  "public",
		PrivateKey: "private",
		Subject:    "mailto:security@example.test",
	})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	if sink.subject != "security@example.test" {
		t.Fatalf("subject = %q, want security@example.test", sink.subject)
	}
}

func TestNotificationSinkPayloadIncludesFindingURL(t *testing.T) {
	sink, err := NewNotificationSink(memoryPushSubscriptions{}, Config{
		PublicKey:  "public",
		PrivateKey: "private",
		BaseURL:    "https://hub.example.test/",
	})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	payload := sink.payload(ports.HubFindingNotification{
		Type:   "finding.observed",
		SentAt: time.Date(2026, 5, 18, 1, 2, 3, 0, time.UTC),
		Finding: domain.HubFinding{
			ID:       "finding-1",
			RuleID:   "web-script",
			Severity: domain.SeverityHigh,
			Title:    "Script changed",
			Summary:  "A new browser script was observed.",
		},
	})
	if got := payload["url"]; got != "https://hub.example.test/dashboard/issue/finding-1" {
		t.Fatalf("url = %#v", got)
	}
	if got := payload["title"]; !strings.Contains(got.(string), "HIGH") {
		t.Fatalf("title = %#v", got)
	}
}

func TestNotificationSinkNotifyNoopWithNoSubscriptions(t *testing.T) {
	sink, err := NewNotificationSink(memoryPushSubscriptions{}, Config{
		PublicKey:  "public",
		PrivateKey: "private",
	})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	if err := sink.NotifyHubFinding(context.Background(), ports.HubFindingNotification{
		Type:    "finding.observed",
		Finding: domain.HubFinding{Severity: domain.SeverityHigh},
	}); err != nil {
		t.Fatalf("NotifyHubFinding returned error: %v", err)
	}
}

type memoryPushSubscriptions struct{}

func (memoryPushSubscriptions) SaveHubPushSubscription(context.Context, domain.HubPushSubscription) (domain.HubPushSubscription, error) {
	return domain.HubPushSubscription{}, nil
}

func (memoryPushSubscriptions) ListActiveHubPushSubscriptions(context.Context) ([]domain.HubPushSubscription, error) {
	return nil, nil
}

func (memoryPushSubscriptions) DisableHubPushSubscription(context.Context, string) error {
	return nil
}

func (memoryPushSubscriptions) DeleteHubPushSubscription(context.Context, domain.ID, string) (bool, error) {
	return false, nil
}
