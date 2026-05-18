package ports

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type HubFindingNotification struct {
	Type      string            `json:"type"`
	SentAt    time.Time         `json:"sent_at"`
	Finding   domain.HubFinding `json:"finding"`
	Metadata  map[string]any    `json:"metadata,omitempty"`
	Actor     string            `json:"actor,omitempty"`
	OldStatus string            `json:"old_status,omitempty"`
	NewStatus string            `json:"new_status,omitempty"`
}

type NotificationSink interface {
	NotifyHubFinding(ctx context.Context, notification HubFindingNotification) error
}

type PushSubscriptionRepository interface {
	SaveHubPushSubscription(ctx context.Context, subscription domain.HubPushSubscription) (domain.HubPushSubscription, error)
	ListActiveHubPushSubscriptions(ctx context.Context) ([]domain.HubPushSubscription, error)
	DisableHubPushSubscription(ctx context.Context, endpoint string) error
	DeleteHubPushSubscription(ctx context.Context, userID domain.ID, endpoint string) (bool, error)
}
