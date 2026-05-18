package hub

import (
	"context"
	"errors"
	"strings"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type SaveHubPushSubscriptionInput struct {
	UserID    string
	Endpoint  string
	P256DH    string
	Auth      string
	UserAgent string
}

type DeleteHubPushSubscriptionInput struct {
	UserID   string
	Endpoint string
}

func (h *Hub) SaveHubPushSubscription(ctx context.Context, input SaveHubPushSubscriptionInput) (domain.HubPushSubscription, error) {
	if h.pushSubscriptions == nil {
		return domain.HubPushSubscription{}, errors.New("push subscription repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	if userID == "" {
		return domain.HubPushSubscription{}, errors.New("user id is required")
	}
	endpoint := strings.TrimSpace(input.Endpoint)
	p256dh := strings.TrimSpace(input.P256DH)
	auth := strings.TrimSpace(input.Auth)
	if endpoint == "" || p256dh == "" || auth == "" {
		return domain.HubPushSubscription{}, errors.New("push endpoint and keys are required")
	}
	return h.pushSubscriptions.SaveHubPushSubscription(ctx, domain.HubPushSubscription{
		UserID:    userID,
		Endpoint:  endpoint,
		P256DH:    p256dh,
		Auth:      auth,
		UserAgent: strings.TrimSpace(input.UserAgent),
		Status:    "active",
	})
}

func (h *Hub) DeleteHubPushSubscription(ctx context.Context, input DeleteHubPushSubscriptionInput) (bool, error) {
	if h.pushSubscriptions == nil {
		return false, errors.New("push subscription repository is not configured")
	}
	userID := domain.ID(strings.TrimSpace(input.UserID))
	endpoint := strings.TrimSpace(input.Endpoint)
	if userID == "" || endpoint == "" {
		return false, errors.New("user id and push endpoint are required")
	}
	return h.pushSubscriptions.DeleteHubPushSubscription(ctx, userID, endpoint)
}
