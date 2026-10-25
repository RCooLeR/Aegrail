package hub

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestReportNotificationErrorThrottlesRepeatedPushTLSFailures(t *testing.T) {
	var reported []error
	hub := New(Dependencies{
		BackgroundError: func(err error) {
			reported = append(reported, err)
		},
	})

	err := errors.New(`web push notification failed: push provider fcm.googleapis.com request failed: Post "fcm.googleapis.com": tls: failed to verify certificate: x509: certificate signed by unknown authority`)
	hub.reportNotificationError(err)
	hub.reportNotificationError(err)

	if len(reported) != 1 {
		t.Fatalf("reported errors = %d, want one throttled report", len(reported))
	}
	if !strings.Contains(reported[0].Error(), "x509: certificate signed by unknown authority") {
		t.Fatalf("reported error = %q, want x509 context", reported[0].Error())
	}
}

func TestCompactNotificationErrorLimitsLogSize(t *testing.T) {
	message := compactNotificationError(strings.Repeat("push failed ", 200))
	if len(message) > notificationErrorMaxLength+3 {
		t.Fatalf("message length = %d, want capped", len(message))
	}
	if !strings.HasSuffix(message, "...") {
		t.Fatalf("message = %q, want ellipsis", message)
	}
}

func TestShouldNotifyHubFindingSkipsClosedObservedFindings(t *testing.T) {
	closedStatuses := []string{"acknowledged", "resolved", "false_positive"}
	for _, status := range closedStatuses {
		if shouldNotifyHubFinding("finding.observed", domain.HubFinding{Status: status}) {
			t.Fatalf("status %q should not send finding.observed notification", status)
		}
	}
	if !shouldNotifyHubFinding("finding.observed", notificationTestFinding("open", true)) {
		t.Fatal("open finding should send finding.observed notification")
	}
	if !shouldNotifyHubFinding("finding.observed", notificationTestFinding("", true)) {
		t.Fatal("empty status should be treated as open for new findings")
	}
	if !shouldNotifyHubFinding("finding.status_updated", domain.HubFinding{Status: "resolved"}) {
		t.Fatal("status update notifications should not be filtered by closed status")
	}
}

func TestShouldNotifyHubFindingSkipsRefreshedOldOpenFindings(t *testing.T) {
	if shouldNotifyHubFinding("finding.observed", notificationTestFinding("open", false)) {
		t.Fatal("refreshed open finding should not send another observed notification")
	}
	if shouldNotifyHubFinding("finding.observed", domain.HubFinding{Status: "open"}) {
		t.Fatal("observed notification should require save-created marker")
	}
}

func TestNotifyHubFindingsStripsSaveCreatedMetadata(t *testing.T) {
	notifications := &memoryNotificationSink{}
	hub := New(Dependencies{Notifications: notifications})
	findings := []domain.HubFinding{notificationTestFinding("open", true)}

	if err := hub.notifyHubFindings(context.Background(), "finding.observed", findings, nil); err != nil {
		t.Fatalf("notifyHubFindings returned error: %v", err)
	}
	if len(notifications.items) != 1 {
		t.Fatalf("notifications = %#v, want one notification", notifications.items)
	}
	if _, ok := notifications.items[0].Finding.Metadata[domain.HubFindingMetadataSaveCreated]; ok {
		t.Fatalf("notification metadata leaked internal save marker: %#v", notifications.items[0].Finding.Metadata)
	}
	if _, ok := findings[0].Metadata[domain.HubFindingMetadataSaveCreated]; ok {
		t.Fatalf("returned finding metadata leaked internal save marker: %#v", findings[0].Metadata)
	}
}

func TestSaveHubFindingsObservedNotifiesCreatedHighFinding(t *testing.T) {
	notifications := &memoryNotificationSink{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Findings: findings, Notifications: notifications})
	input := []domain.HubFinding{{
		EnvironmentID: "environment-1",
		RuleID:        "wordpress-admin-user-added",
		RuleVersion:   "2026-07-07.1",
		DedupeKey:     "admin-user",
		Severity:      domain.SeverityHigh,
		Confidence:    domain.ConfidenceHigh,
		Title:         "WordPress administrator added",
	}}

	saved, err := hub.saveHubFindingsObserved(context.Background(), input, "test")
	if err != nil {
		t.Fatalf("saveHubFindingsObserved returned error: %v", err)
	}
	if len(notifications.items) != 1 {
		t.Fatalf("notifications = %#v, want one observed notification", notifications.items)
	}
	if notifications.items[0].Type != "finding.observed" || notifications.items[0].Finding.Severity != domain.SeverityHigh {
		t.Fatalf("notification = %#v, want observed high finding", notifications.items[0])
	}
	if _, ok := saved[0].Metadata[domain.HubFindingMetadataSaveCreated]; ok {
		t.Fatalf("saved finding leaked internal save marker: %#v", saved[0].Metadata)
	}

	if _, err := hub.saveHubFindingsObserved(context.Background(), input, "test"); err != nil {
		t.Fatalf("second saveHubFindingsObserved returned error: %v", err)
	}
	if len(notifications.items) != 1 {
		t.Fatalf("notifications = %#v, want duplicate save not to resend observed notification", notifications.items)
	}
}

type blockingHubNotificationSink struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (s blockingHubNotificationSink) NotifyHubFinding(context.Context, ports.HubFindingNotification) error {
	s.started <- struct{}{}
	<-s.release
	return nil
}

func TestNotifyHubFindingsStartsIndependentFindingEmailsConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	hub := New(Dependencies{
		Notifications: blockingHubNotificationSink{started: started, release: release},
	})
	findings := []domain.HubFinding{
		notificationTestFinding("open", true),
		notificationTestFinding("open", true),
	}
	findings[0].ID = "finding-1"
	findings[1].ID = "finding-2"
	done := make(chan error, 1)
	go func() {
		done <- hub.notifyHubFindings(context.Background(), "finding.observed", findings, nil)
	}()

	for index := range findings {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("finding notification %d did not start promptly", index+1)
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("notifyHubFindings returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("notifyHubFindings did not finish after deliveries completed")
	}
}

func notificationTestFinding(status string, saveCreated bool) domain.HubFinding {
	return domain.HubFinding{
		Status: status,
		Metadata: map[string]any{
			domain.HubFindingMetadataSaveCreated: saveCreated,
		},
	}
}
