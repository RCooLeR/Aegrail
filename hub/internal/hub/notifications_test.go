package hub

import (
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
	if !shouldNotifyHubFinding("finding.observed", domain.HubFinding{Status: "open"}) {
		t.Fatal("open finding should send finding.observed notification")
	}
	if !shouldNotifyHubFinding("finding.observed", domain.HubFinding{}) {
		t.Fatal("empty status should be treated as open")
	}
	if !shouldNotifyHubFinding("finding.status_updated", domain.HubFinding{Status: "resolved"}) {
		t.Fatal("status update notifications should not be filtered by closed status")
	}
}
