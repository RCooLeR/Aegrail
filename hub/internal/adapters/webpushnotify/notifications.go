package webpushnotify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type Config struct {
	PublicKey   string
	PrivateKey  string
	Subject     string
	BaseURL     string
	MinSeverity string
	Events      []string
	TTL         int
	Timeout     time.Duration
}

type NotificationSink struct {
	repository  ports.PushSubscriptionRepository
	publicKey   string
	privateKey  string
	subject     string
	baseURL     string
	minSeverity string
	events      map[string]struct{}
	ttl         int
	client      *http.Client
	cacheMu     sync.Mutex
	cacheAt     time.Time
	cache       []domain.HubPushSubscription
}

const activeSubscriptionCacheTTL = 30 * time.Second

func NewNotificationSink(repository ports.PushSubscriptionRepository, config Config) (*NotificationSink, error) {
	publicKey := strings.TrimSpace(config.PublicKey)
	privateKey := strings.TrimSpace(config.PrivateKey)
	if repository == nil && publicKey == "" && privateKey == "" {
		return nil, nil
	}
	if repository == nil {
		return nil, fmt.Errorf("web push notifications require a push subscription repository")
	}
	if publicKey == "" && privateKey == "" {
		return nil, nil
	}
	if publicKey == "" || privateKey == "" {
		return nil, fmt.Errorf("web push notifications require both public and private VAPID keys")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	events := eventSet(config.Events)
	if len(events) == 0 {
		events["finding.observed"] = struct{}{}
	}
	minSeverity := strings.ToLower(strings.TrimSpace(config.MinSeverity))
	if minSeverity == "" {
		minSeverity = "medium"
	}
	subject := strings.TrimSpace(config.Subject)
	if strings.HasPrefix(strings.ToLower(subject), "mailto:") {
		subject = strings.TrimSpace(subject[len("mailto:"):])
	}
	if subject == "" {
		subject = "security@example.invalid"
	}
	ttl := config.TTL
	if ttl <= 0 {
		ttl = 3600
	}
	return &NotificationSink{
		repository:  repository,
		publicKey:   publicKey,
		privateKey:  privateKey,
		subject:     subject,
		baseURL:     strings.TrimRight(strings.TrimSpace(config.BaseURL), "/"),
		minSeverity: minSeverity,
		events:      events,
		ttl:         ttl,
		client:      &http.Client{Timeout: timeout},
	}, nil
}

func (s *NotificationSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	if s == nil || !s.shouldSend(notification) {
		return nil
	}
	subscriptions, err := s.activeSubscriptions(ctx)
	if err != nil {
		return err
	}
	if len(subscriptions) == 0 {
		return nil
	}
	payload, err := json.Marshal(s.payload(notification))
	if err != nil {
		return err
	}
	var errs []string
	for _, subscription := range subscriptions {
		err := s.send(ctx, subscription, payload)
		if err == nil {
			continue
		}
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("web push notification failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *NotificationSink) shouldSend(notification ports.HubFindingNotification) bool {
	if _, ok := s.events[strings.TrimSpace(notification.Type)]; !ok {
		return false
	}
	return severityRank(notification.Finding.Severity) >= severityRank(domain.Severity(s.minSeverity))
}

func (s *NotificationSink) send(ctx context.Context, subscription domain.HubPushSubscription, payload []byte) error {
	response, err := webpush.SendNotificationWithContext(ctx, payload, &webpush.Subscription{
		Endpoint: subscription.Endpoint,
		Keys: webpush.Keys{
			Auth:   subscription.Auth,
			P256dh: subscription.P256DH,
		},
	}, &webpush.Options{
		HTTPClient:      s.client,
		Subscriber:      s.subject,
		TTL:             s.ttl,
		Urgency:         webpush.UrgencyHigh,
		VAPIDPublicKey:  s.publicKey,
		VAPIDPrivateKey: s.privateKey,
	})
	if err != nil {
		return fmt.Errorf("push provider %s request failed: %s", pushEndpointLabel(subscription.Endpoint), sanitizePushError(err.Error(), subscription.Endpoint))
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		_ = s.repository.DisableHubPushSubscription(ctx, subscription.Endpoint)
		s.invalidateSubscriptionCache()
		return nil
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	content, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	return fmt.Errorf("push provider %s returned HTTP %d: %s", pushEndpointLabel(subscription.Endpoint), response.StatusCode, strings.TrimSpace(string(content)))
}

func (s *NotificationSink) activeSubscriptions(ctx context.Context) ([]domain.HubPushSubscription, error) {
	now := time.Now()
	s.cacheMu.Lock()
	if !s.cacheAt.IsZero() && now.Sub(s.cacheAt) < activeSubscriptionCacheTTL {
		items := append([]domain.HubPushSubscription(nil), s.cache...)
		s.cacheMu.Unlock()
		return items, nil
	}
	s.cacheMu.Unlock()

	subscriptions, err := s.repository.ListActiveHubPushSubscriptions(ctx)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	s.cacheAt = now
	s.cache = append(s.cache[:0], subscriptions...)
	items := append([]domain.HubPushSubscription(nil), s.cache...)
	s.cacheMu.Unlock()
	return items, nil
}

func (s *NotificationSink) invalidateSubscriptionCache() {
	s.cacheMu.Lock()
	s.cacheAt = time.Time{}
	s.cache = nil
	s.cacheMu.Unlock()
}

func sanitizePushError(message string, endpoint string) string {
	message = strings.TrimSpace(message)
	label := pushEndpointLabel(endpoint)
	if endpoint != "" {
		message = strings.ReplaceAll(message, endpoint, label)
	}
	return message
}

func pushEndpointLabel(endpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}

func (s *NotificationSink) payload(notification ports.HubFindingNotification) map[string]any {
	finding := notification.Finding
	return map[string]any{
		"type":       notification.Type,
		"title":      fmt.Sprintf("%s: %s", strings.ToUpper(string(finding.Severity)), finding.Title),
		"body":       finding.Summary,
		"finding_id": string(finding.ID),
		"rule_id":    finding.RuleID,
		"severity":   string(finding.Severity),
		"url":        s.findingURL(finding.ID),
		"sent_at":    notification.SentAt.UTC().Format(time.RFC3339),
	}
}

func (s *NotificationSink) findingURL(findingID domain.ID) string {
	if s.baseURL == "" || findingID == "" {
		return "/dashboard/"
	}
	return s.baseURL + "/dashboard/issue/" + string(findingID)
}

func eventSet(values []string) map[string]struct{} {
	events := map[string]struct{}{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				events[item] = struct{}{}
			}
		}
	}
	return events
}

func severityRank(severity domain.Severity) int {
	switch strings.ToLower(strings.TrimSpace(string(severity))) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
