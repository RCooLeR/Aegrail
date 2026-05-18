package smtpnotify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestNewNotificationSinkDisabledWhenUnconfigured(t *testing.T) {
	sink, err := NewNotificationSink(Config{Host: "in-v3.mailjet.com", Port: "587"})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	if sink != nil {
		t.Fatalf("sink = %#v, want nil", sink)
	}
}

func TestNewNotificationSinkRequiresCredentialsAndRecipients(t *testing.T) {
	_, err := NewNotificationSink(Config{From: "Aegrail <alerts@example.test>"})
	if err == nil {
		t.Fatalf("NewNotificationSink returned nil error")
	}
}

func TestNotificationSinkBuildsEscapedMailjetMessage(t *testing.T) {
	sink, err := NewNotificationSink(Config{
		Username: "mailjet-key",
		Password: "mailjet-secret",
		From:     "Aegrail <alerts@example.test>",
		To:       []string{"ops@example.test"},
		BaseURL:  "https://hub.example.test",
	})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	notification := ports.HubFindingNotification{
		Type:   "finding.observed",
		SentAt: time.Now().UTC(),
		Finding: domain.HubFinding{
			ID:           "finding-1",
			RuleID:       "web-script",
			Severity:     domain.SeverityHigh,
			Confidence:   domain.ConfidenceMedium,
			Title:        "Script <changed>",
			Summary:      "Found <script>alert(1)</script>",
			FirstEventAt: time.Date(2026, 5, 18, 1, 2, 3, 0, time.UTC),
			LastEventAt:  time.Date(2026, 5, 18, 1, 4, 3, 0, time.UTC),
		},
	}
	message := string(sink.emailMessage(notification, "[Aegrail] test"))
	if !strings.Contains(message, "https://hub.example.test/dashboard/issue/finding-1") {
		t.Fatalf("message missing dashboard URL:\n%s", message)
	}
	if !strings.Contains(message, "Script &lt;changed&gt;") || strings.Contains(message, "<script>alert") {
		t.Fatalf("message did not escape finding content:\n%s", message)
	}
}

func TestNotificationSinkSeverityAndEventFilters(t *testing.T) {
	sink, err := NewNotificationSink(Config{
		Username:    "mailjet-key",
		Password:    "mailjet-secret",
		From:        "alerts@example.test",
		To:          []string{"ops@example.test"},
		MinSeverity: "high",
		Events:      []string{"finding.status_updated"},
	})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	notification := ports.HubFindingNotification{
		Type:    "finding.observed",
		Finding: domain.HubFinding{Severity: domain.SeverityCritical},
	}
	if sink.shouldSend(notification) {
		t.Fatalf("shouldSend matched an event outside the allow list")
	}
	notification.Type = "finding.status_updated"
	notification.Finding.Severity = domain.SeverityMedium
	if sink.shouldSend(notification) {
		t.Fatalf("shouldSend matched severity below threshold")
	}
	notification.Finding.Severity = domain.SeverityHigh
	if !sink.shouldSend(notification) {
		t.Fatalf("shouldSend rejected configured event/severity")
	}
}

func TestSMTPEnvelopeAddressParsesDisplayNames(t *testing.T) {
	address, err := smtpEnvelopeAddress("Aegrail <alerts@example.test>")
	if err != nil {
		t.Fatalf("smtpEnvelopeAddress returned error: %v", err)
	}
	if address != "alerts@example.test" {
		t.Fatalf("address = %q, want alerts@example.test", address)
	}
}

func TestNotificationSinkNotifyNoopWhenFiltered(t *testing.T) {
	sink, err := NewNotificationSink(Config{
		Username:    "mailjet-key",
		Password:    "mailjet-secret",
		From:        "alerts@example.test",
		To:          []string{"ops@example.test"},
		MinSeverity: "critical",
	})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	if err := sink.NotifyHubFinding(context.Background(), ports.HubFindingNotification{
		Type:    "finding.observed",
		Finding: domain.HubFinding{Severity: domain.SeverityLow},
	}); err != nil {
		t.Fatalf("NotifyHubFinding returned error: %v", err)
	}
}
