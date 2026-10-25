package ports

import (
	"context"
	"errors"
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

// NotificationTransportSink exposes independently deliverable notification
// transports. The outbox uses this extension so a failed transport can be
// retried without redelivering transports that already succeeded.
type NotificationTransportSink interface {
	NotificationSink
	NotificationTransports() []string
	NotifyHubFindingTransport(ctx context.Context, transport string, notification HubFindingNotification) error
}

type HubFindingObservedOutboxWriter interface {
	SaveHubFindingsObserved(ctx context.Context, findings []domain.HubFinding, source string) ([]domain.HubFinding, error)
}

type HubFindingNotificationOutboxItem struct {
	ID           domain.ID
	LeaseToken   domain.ID
	Transport    string
	Notification HubFindingNotification
	AttemptCount int
	CreatedAt    time.Time
}

type HubFindingNotificationClaimOptions struct {
	Limit         int
	Now           time.Time
	LeaseDuration time.Duration
	FindingIDs    []domain.ID
}

type HubFindingNotificationOutboxRepository interface {
	ClaimHubFindingNotifications(ctx context.Context, options HubFindingNotificationClaimOptions) ([]HubFindingNotificationOutboxItem, error)
	CompleteHubFindingNotification(ctx context.Context, itemID domain.ID, leaseToken domain.ID, deliveredAt time.Time) error
	RetryHubFindingNotification(ctx context.Context, itemID domain.ID, leaseToken domain.ID, nextAttemptAt time.Time, lastError string) error
}

var ErrHubFindingNotificationLeaseLost = errors.New("hub finding notification outbox lease was lost")

type PushSubscriptionRepository interface {
	SaveHubPushSubscription(ctx context.Context, subscription domain.HubPushSubscription) (domain.HubPushSubscription, error)
	ListActiveHubPushSubscriptions(ctx context.Context) ([]domain.HubPushSubscription, error)
	DisableHubPushSubscription(ctx context.Context, endpoint string) error
	DeleteHubPushSubscription(ctx context.Context, userID domain.ID, endpoint string) (bool, error)
}
