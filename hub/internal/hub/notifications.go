package hub

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func (h *Hub) notifyHubFindings(ctx context.Context, eventType string, findings []domain.HubFinding, metadata map[string]any) error {
	if h.notifications == nil || len(findings) == 0 {
		return nil
	}
	for _, finding := range findings {
		if err := h.notifyHubFinding(ctx, eventType, finding, metadata); err != nil {
			return err
		}
	}
	return nil
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
	return h.notifications.NotifyHubFinding(ctx, ports.HubFindingNotification{
		Type:      "finding.status_updated",
		SentAt:    time.Now().UTC(),
		Finding:   finding,
		Metadata:  cloneAnyMap(metadata),
		Actor:     finding.StatusActor,
		OldStatus: oldStatus,
		NewStatus: findingStatusValue(finding.Status),
	})
}

func findingStatusValue(status string) string {
	if status == "" {
		return "open"
	}
	return status
}
