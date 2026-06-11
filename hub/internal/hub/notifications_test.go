package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/domain"
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

func notificationTestFinding(status string, saveCreated bool) domain.HubFinding {
	return domain.HubFinding{
		Status: status,
		Metadata: map[string]any{
			domain.HubFindingMetadataSaveCreated: saveCreated,
		},
	}
}
