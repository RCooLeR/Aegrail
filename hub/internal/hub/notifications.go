package hub

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

const notificationErrorReportEvery = 5 * time.Minute
const notificationErrorMaxLength = 800

func (h *Hub) notifyHubFindings(ctx context.Context, eventType string, findings []domain.HubFinding, metadata map[string]any) error {
	if h.notifications == nil || len(findings) == 0 {
		return nil
	}
	failed := 0
	var firstErr error
	for _, finding := range findings {
		if !shouldNotifyHubFinding(eventType, finding) {
			continue
		}
		// Notification transports are best-effort. Findings are durable evidence;
		// webhook/email/push outages must not make correlation or ingest jobs fail.
		if err := h.notifyHubFinding(ctx, eventType, finding, metadata); err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if failed > 0 {
		h.reportNotificationError(fmt.Errorf("%d finding notification(s) failed; first error: %w", failed, firstErr))
	}
	return nil
}

func shouldNotifyHubFinding(eventType string, finding domain.HubFinding) bool {
	if strings.TrimSpace(eventType) != "finding.observed" {
		return true
	}
	status := findingStatusValue(strings.TrimSpace(finding.Status))
	return status == "open"
}

func (h *Hub) notifyHubFinding(ctx context.Context, eventType string, finding domain.HubFinding, metadata map[string]any) error {
	if h.notifications == nil {
		return nil
	}
	return h.notifications.NotifyHubFinding(ctx, ports.HubFindingNotification{
		Type:     eventType,
		SentAt:   time.Now().UTC(),
		Finding:  finding,
		Metadata: cloneAnyMap(metadata),
	})
}

func (h *Hub) notifyHubFindingStatus(ctx context.Context, finding domain.HubFinding, oldStatus string, metadata map[string]any) error {
	if h.notifications == nil {
		return nil
	}
	err := h.notifications.NotifyHubFinding(ctx, ports.HubFindingNotification{
		Type:      "finding.status_updated",
		SentAt:    time.Now().UTC(),
		Finding:   finding,
		Metadata:  cloneAnyMap(metadata),
		Actor:     finding.StatusActor,
		OldStatus: oldStatus,
		NewStatus: findingStatusValue(finding.Status),
	})
	if err != nil {
		h.reportNotificationError(err)
	}
	return nil
}

func (h *Hub) reportNotificationError(err error) {
	if err == nil || h == nil || h.backgroundError == nil {
		return
	}
	message := compactNotificationError(err.Error())
	if message == "" {
		return
	}
	key := notificationErrorKey(message)
	now := time.Now().UTC()
	h.notificationErrorMu.Lock()
	lastReportedAt := h.notificationErrorLast[key]
	if !lastReportedAt.IsZero() && now.Sub(lastReportedAt) < notificationErrorReportEvery {
		h.notificationErrorMu.Unlock()
		return
	}
	if h.notificationErrorLast == nil {
		h.notificationErrorLast = map[string]time.Time{}
	}
	h.notificationErrorLast[key] = now
	h.notificationErrorMu.Unlock()
	h.backgroundError(fmt.Errorf("notification delivery failed: %s", message))
}

func findingStatusValue(status string) string {
	if status == "" {
		return "open"
	}
	return status
}

func compactNotificationError(message string) string {
	message = strings.TrimSpace(message)
	message = strings.Join(strings.Fields(message), " ")
	if len(message) <= notificationErrorMaxLength {
		return message
	}
	return strings.TrimSpace(message[:notificationErrorMaxLength]) + "..."
}

func notificationErrorKey(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "fcm.googleapis.com") && strings.Contains(lower, "x509: certificate signed by unknown authority"):
		return "webpush:fcm:x509_unknown_authority"
	case strings.Contains(lower, "web push notification failed"):
		return "webpush:" + compactNotificationError(message)
	case strings.Contains(lower, "smtp"):
		return "email:" + compactNotificationError(message)
	case strings.Contains(lower, "webhook"):
		return "webhook:" + compactNotificationError(message)
	default:
		return compactNotificationError(message)
	}
}
