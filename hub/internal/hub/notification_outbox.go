package hub

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

const (
	defaultNotificationOutboxInterval       = time.Second
	defaultNotificationOutboxBatchSize      = 100
	defaultNotificationOutboxMaxBatches     = 10
	defaultNotificationOutboxLeaseDuration  = time.Minute
	defaultNotificationOutboxAttemptTimeout = 30 * time.Second
	defaultNotificationOutboxRetryMin       = 5 * time.Second
	defaultNotificationOutboxRetryMax       = 15 * time.Minute
	notificationOutboxFinalizeTimeout       = 5 * time.Second
)

type NotificationOutboxWorkerOptions struct {
	Interval       time.Duration
	BatchSize      int
	MaxBatches     int
	LeaseDuration  time.Duration
	AttemptTimeout time.Duration
	RetryMin       time.Duration
	RetryMax       time.Duration
	OnError        func(error)
}

type NotificationOutboxDeliveryOptions struct {
	BatchSize      int
	MaxBatches     int
	LeaseDuration  time.Duration
	AttemptTimeout time.Duration
	RetryMin       time.Duration
	RetryMax       time.Duration
	FindingIDs     []domain.ID
	Now            time.Time
}

type NotificationOutboxDeliveryResult struct {
	Claimed   int
	Delivered int
	Retried   int
}

func (h *Hub) StartNotificationOutboxWorker(ctx context.Context, options NotificationOutboxWorkerOptions) bool {
	if h == nil || h.notificationOutbox == nil || h.notifications == nil {
		return false
	}
	interval := options.Interval
	if interval <= 0 {
		interval = defaultNotificationOutboxInterval
	}
	h.workersWG.Add(1)
	go runHubWorker(ctx, "notification-outbox", func(ctx context.Context) {
		defer h.workersWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		run := func() {
			_, err := h.DeliverPendingHubFindingNotifications(ctx, NotificationOutboxDeliveryOptions{
				BatchSize:      options.BatchSize,
				MaxBatches:     options.MaxBatches,
				LeaseDuration:  options.LeaseDuration,
				AttemptTimeout: options.AttemptTimeout,
				RetryMin:       options.RetryMin,
				RetryMax:       options.RetryMax,
			})
			if err == nil {
				return
			}
			if options.OnError != nil {
				options.OnError(err)
			} else if h.backgroundError != nil {
				h.backgroundError(err)
			}
		}
		run()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	})
	return true
}

func (h *Hub) DeliverPendingHubFindingNotifications(ctx context.Context, options NotificationOutboxDeliveryOptions) (NotificationOutboxDeliveryResult, error) {
	if h == nil || h.notificationOutbox == nil {
		return NotificationOutboxDeliveryResult{}, errors.New("hub finding notification outbox is not configured")
	}
	if h.notifications == nil {
		return NotificationOutboxDeliveryResult{}, errors.New("hub notification sink is not configured")
	}
	options = normalizeNotificationOutboxDeliveryOptions(options)
	result := NotificationOutboxDeliveryResult{}
	for batchIndex := 0; batchIndex < options.MaxBatches; batchIndex++ {
		now := options.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		items, err := h.notificationOutbox.ClaimHubFindingNotifications(ctx, ports.HubFindingNotificationClaimOptions{
			Limit:         options.BatchSize,
			Now:           now,
			LeaseDuration: options.LeaseDuration,
			FindingIDs:    options.FindingIDs,
		})
		if err != nil {
			return result, fmt.Errorf("claim finding notification outbox: %w", err)
		}
		if len(items) == 0 {
			break
		}
		result.Claimed += len(items)
		batchResult := h.deliverHubFindingNotificationBatch(ctx, items, options)
		result.Delivered += batchResult.Delivered
		result.Retried += batchResult.Retried
		if len(items) < options.BatchSize {
			break
		}
	}
	return result, nil
}

func normalizeNotificationOutboxDeliveryOptions(options NotificationOutboxDeliveryOptions) NotificationOutboxDeliveryOptions {
	if options.BatchSize <= 0 {
		options.BatchSize = defaultNotificationOutboxBatchSize
	}
	if options.BatchSize > 500 {
		options.BatchSize = 500
	}
	if options.MaxBatches <= 0 {
		options.MaxBatches = defaultNotificationOutboxMaxBatches
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = defaultNotificationOutboxLeaseDuration
	}
	if options.AttemptTimeout <= 0 {
		options.AttemptTimeout = defaultNotificationOutboxAttemptTimeout
	}
	if minimumLease := options.AttemptTimeout + notificationOutboxFinalizeTimeout; options.LeaseDuration < minimumLease {
		options.LeaseDuration = minimumLease
	}
	if options.RetryMin <= 0 {
		options.RetryMin = defaultNotificationOutboxRetryMin
	}
	if options.RetryMax <= 0 {
		options.RetryMax = defaultNotificationOutboxRetryMax
	}
	if options.RetryMax < options.RetryMin {
		options.RetryMax = options.RetryMin
	}
	return options
}

func (h *Hub) deliverHubFindingNotificationBatch(ctx context.Context, items []ports.HubFindingNotificationOutboxItem, options NotificationOutboxDeliveryOptions) NotificationOutboxDeliveryResult {
	type deliveryResult struct {
		delivered bool
		retried   bool
	}
	results := make(chan deliveryResult, len(items))
	slots := make(chan struct{}, notificationDeliveryConcurrency)
	var wait sync.WaitGroup
	for _, item := range items {
		slots <- struct{}{}
		wait.Go(func() {
			defer func() { <-slots }()
			delivered, retried := h.deliverHubFindingNotificationItem(ctx, item, options)
			results <- deliveryResult{delivered: delivered, retried: retried}
		})
	}
	wait.Wait()
	close(results)
	result := NotificationOutboxDeliveryResult{}
	for item := range results {
		if item.delivered {
			result.Delivered++
		}
		if item.retried {
			result.Retried++
		}
	}
	return result
}

func (h *Hub) deliverHubFindingNotificationItem(ctx context.Context, item ports.HubFindingNotificationOutboxItem, options NotificationOutboxDeliveryOptions) (bool, bool) {
	attemptCtx, cancel := context.WithTimeout(ctx, options.AttemptTimeout)
	err := h.notifyHubFindingTransport(attemptCtx, item.Transport, item.Notification)
	cancel()
	finishedAt := time.Now().UTC()

	finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx), notificationOutboxFinalizeTimeout)
	defer finalizeCancel()
	if err == nil {
		if completeErr := h.notificationOutbox.CompleteHubFindingNotification(finalizeCtx, item.ID, item.LeaseToken, finishedAt); completeErr != nil {
			h.reportNotificationError(fmt.Errorf("mark %s notification %s delivered: %w", item.Transport, item.ID, completeErr))
			return false, false
		}
		return true, false
	}

	nextAttemptAt := finishedAt.Add(notificationOutboxRetryDelay(item.AttemptCount, options.RetryMin, options.RetryMax))
	retryErr := h.notificationOutbox.RetryHubFindingNotification(
		finalizeCtx,
		item.ID,
		item.LeaseToken,
		nextAttemptAt,
		compactNotificationError(err.Error()),
	)
	if retryErr != nil {
		h.reportNotificationError(fmt.Errorf("%s notification %s failed: %v; persist retry: %w", item.Transport, item.ID, err, retryErr))
		return false, false
	}
	h.reportNotificationError(fmt.Errorf("%s notification %s failed; retry at %s: %w", item.Transport, item.ID, nextAttemptAt.Format(time.RFC3339), err))
	return false, true
}

func (h *Hub) notifyHubFindingTransport(ctx context.Context, transport string, notification ports.HubFindingNotification) error {
	if transportSink, ok := h.notifications.(ports.NotificationTransportSink); ok {
		return transportSink.NotifyHubFindingTransport(ctx, transport, notification)
	}
	return h.notifications.NotifyHubFinding(ctx, notification)
}

func notificationOutboxRetryDelay(attempt int, minimum time.Duration, maximum time.Duration) time.Duration {
	if minimum <= 0 {
		minimum = defaultNotificationOutboxRetryMin
	}
	if maximum < minimum {
		maximum = minimum
	}
	delay := minimum
	for current := 1; current < attempt && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
