package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type Config struct {
	URL     string
	Secret  string
	Timeout time.Duration
}

type NotificationSink struct {
	url    string
	secret string
	client *http.Client
}

func NewNotificationSink(config Config) (*NotificationSink, error) {
	url := strings.TrimSpace(config.URL)
	if url == "" {
		return nil, nil
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &NotificationSink{
		url:    url,
		secret: strings.TrimSpace(config.Secret),
		client: &http.Client{Timeout: timeout},
	}, nil
}

func (s *NotificationSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	if s == nil || s.url == "" {
		return nil
	}
	body, err := json.Marshal(webhookNotificationRecord(notification))
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "aegrail-hub-notifier")
	if s.secret != "" {
		request.Header.Set("X-Aegrail-Signature", "sha256="+hmacSHA256Hex(s.secret, body))
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	content, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("notification webhook returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(content)))
}

type webhookNotificationPayload struct {
	Type      string               `json:"type"`
	SentAt    time.Time            `json:"sent_at"`
	Finding   webhookFindingRecord `json:"finding"`
	Metadata  map[string]any       `json:"metadata,omitempty"`
	Actor     string               `json:"actor,omitempty"`
	OldStatus string               `json:"old_status,omitempty"`
	NewStatus string               `json:"new_status,omitempty"`
}

type webhookFindingRecord struct {
	ID              string         `json:"id"`
	OrganizationID  string         `json:"organization_id,omitempty"`
	ProjectID       string         `json:"project_id,omitempty"`
	EnvironmentID   string         `json:"environment_id,omitempty"`
	AppID           string         `json:"app_id,omitempty"`
	RuleID          string         `json:"rule_id"`
	RuleVersion     string         `json:"rule_version"`
	DedupeKey       string         `json:"dedupe_key"`
	Severity        string         `json:"severity"`
	Confidence      string         `json:"confidence"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	Status          string         `json:"status"`
	StatusReason    string         `json:"status_reason,omitempty"`
	StatusNote      string         `json:"status_note,omitempty"`
	StatusActor     string         `json:"status_actor,omitempty"`
	StatusUpdatedAt time.Time      `json:"status_updated_at,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	FirstEventAt    time.Time      `json:"first_event_at"`
	LastEventAt     time.Time      `json:"last_event_at"`
	CreatedAt       time.Time      `json:"created_at,omitempty"`
	UpdatedAt       time.Time      `json:"updated_at,omitempty"`
}

func webhookNotificationRecord(notification ports.HubFindingNotification) webhookNotificationPayload {
	return webhookNotificationPayload{
		Type:      notification.Type,
		SentAt:    notification.SentAt,
		Finding:   webhookFinding(notification.Finding),
		Metadata:  notification.Metadata,
		Actor:     notification.Actor,
		OldStatus: notification.OldStatus,
		NewStatus: notification.NewStatus,
	}
}

func webhookFinding(finding domain.HubFinding) webhookFindingRecord {
	status := finding.Status
	if status == "" {
		status = "open"
	}
	return webhookFindingRecord{
		ID:              string(finding.ID),
		OrganizationID:  string(finding.OrganizationID),
		ProjectID:       string(finding.ProjectID),
		EnvironmentID:   string(finding.EnvironmentID),
		AppID:           string(finding.AppID),
		RuleID:          finding.RuleID,
		RuleVersion:     finding.RuleVersion,
		DedupeKey:       finding.DedupeKey,
		Severity:        string(finding.Severity),
		Confidence:      string(finding.Confidence),
		Title:           finding.Title,
		Summary:         finding.Summary,
		Status:          status,
		StatusReason:    finding.StatusReason,
		StatusNote:      finding.StatusNote,
		StatusActor:     finding.StatusActor,
		StatusUpdatedAt: finding.StatusUpdatedAt,
		Metadata:        finding.Metadata,
		FirstEventAt:    finding.FirstEventAt,
		LastEventAt:     finding.LastEventAt,
		CreatedAt:       finding.CreatedAt,
		UpdatedAt:       finding.UpdatedAt,
	}
}

func hmacSHA256Hex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
