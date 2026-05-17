package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestNotificationSinkPostsFindingWebhook(t *testing.T) {
	var signature string
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-Aegrail-Signature")
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink, err := NewNotificationSink(Config{URL: server.URL, Secret: "secret", Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewNotificationSink returned error: %v", err)
	}
	err = sink.NotifyHubFinding(context.Background(), ports.HubFindingNotification{
		Type:   "finding.observed",
		SentAt: time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC),
		Finding: domain.HubFinding{
			ID:         "finding-1",
			RuleID:     "browser-script-domain-new",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
			Title:      "New browser script domain",
		},
	})
	if err != nil {
		t.Fatalf("NotifyHubFinding returned error: %v", err)
	}
	if !strings.HasPrefix(signature, "sha256=") {
		t.Fatalf("signature = %q, want sha256 HMAC header", signature)
	}
	finding, _ := payload["finding"].(map[string]any)
	if payload["type"] != "finding.observed" || finding["rule_id"] != "browser-script-domain-new" {
		t.Fatalf("payload = %#v, want webhook finding payload", payload)
	}
}
