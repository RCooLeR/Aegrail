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
const notificationDeliveryConcurrency = 4

func (h *Hub) notifyHubFindings(ctx context.Context, eventType string, findings []domain.HubFinding, metadata map[string]any) error {
	if h.notifications == nil || len(findings) == 0 {
		return nil
	}
	failed := 0
	var firstErr error
	results := make(chan error, len(findings))
	slots := make(chan struct{}, notificationDeliveryConcurrency)
	pending := 0
	for index := range findings {
		finding := findings[index]
		if !shouldNotifyHubFinding(eventType, finding) {
			stripHubFindingSaveMetadata(&findings[index])
			continue
		}
		stripHubFindingSaveMetadata(&finding)
		stripHubFindingSaveMetadata(&findings[index])
		// Notification transports are best-effort. Findings are durable evidence;
		// webhook/email/push outages must not make correlation or ingest jobs fail.
		slots <- struct{}{}
		pending++
		go func() {
			defer func() { <-slots }()
			results <- h.notifyHubFinding(ctx, eventType, finding, metadata)
		}()
	}
	for range pending {
		if err := <-results; err != nil {
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

func (h *Hub) saveHubFindingsObserved(ctx context.Context, findings []domain.HubFinding, source string) ([]domain.HubFinding, error) {
	if h.findings == nil {
		return nil, fmt.Errorf("finding repository is not configured")
	}
	outboxWriter, durableOutbox := h.findings.(ports.HubFindingObservedOutboxWriter)
	durableOutbox = durableOutbox && h.notificationOutbox != nil && h.notifications != nil
	var (
		saved []domain.HubFinding
		err   error
	)
	if durableOutbox {
		saved, err = outboxWriter.SaveHubFindingsObserved(ctx, findings, source)
	} else {
		saved, err = h.findings.SaveHubFindings(ctx, findings)
	}
	if err != nil {
		return nil, err
	}
	if durableOutbox {
		createdFindingIDs := make([]domain.ID, 0, len(saved))
		for index := range saved {
			if shouldNotifyHubFinding("finding.observed", saved[index]) {
				createdFindingIDs = append(createdFindingIDs, saved[index].ID)
			}
			stripHubFindingSaveMetadata(&saved[index])
		}
		if len(createdFindingIDs) > 0 {
			if _, deliverErr := h.DeliverPendingHubFindingNotifications(ctx, NotificationOutboxDeliveryOptions{
				BatchSize:  500,
				MaxBatches: 10,
				FindingIDs: createdFindingIDs,
			}); deliverErr != nil {
				h.reportNotificationError(fmt.Errorf("immediate finding notification outbox delivery failed: %w", deliverErr))
			}
		}
		return saved, nil
	}
	if err := h.notifyHubFindings(ctx, "finding.observed", saved, map[string]any{"source": source}); err != nil {
		return nil, err
	}
	return saved, nil
}

func shouldNotifyHubFinding(eventType string, finding domain.HubFinding) bool {
	if strings.TrimSpace(eventType) != "finding.observed" {
		return true
	}
	status := findingStatusValue(strings.TrimSpace(finding.Status))
	return status == "open" && hubFindingSaveCreated(finding)
}

func hubFindingSaveCreated(finding domain.HubFinding) bool {
	value, ok := finding.Metadata[domain.HubFindingMetadataSaveCreated]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true") || strings.TrimSpace(typed) == "1"
	default:
		return false
	}
}

func stripHubFindingSaveMetadata(finding *domain.HubFinding) {
	if finding == nil || finding.Metadata == nil {
		return
	}
	delete(finding.Metadata, domain.HubFindingMetadataSaveCreated)
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
