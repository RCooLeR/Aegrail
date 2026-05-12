package httpadapter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
)

func TestVerifyIngestSignatureAcceptsValidSignature(t *testing.T) {
	body := []byte(`{"batch_id":"test"}`)
	timestamp := "2026-05-12T01:00:00Z"
	request := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	request.Header.Set(headerTimestamp, timestamp)
	request.Header.Set(headerSignature, "sha256="+signTestBody("secret", timestamp, body))

	err := verifyIngestSignature(request, body, HubOptions{
		IngestSecret:        "secret",
		IngestSignatureSkew: time.Minute,
		Now: func() time.Time {
			return time.Date(2026, 5, 12, 1, 0, 30, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("verifyIngestSignature returned error: %v", err)
	}
}

func TestVerifyIngestSignatureRejectsInvalidSignature(t *testing.T) {
	body := []byte(`{"batch_id":"test"}`)
	request := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	request.Header.Set(headerTimestamp, "2026-05-12T01:00:00Z")
	request.Header.Set(headerSignature, "sha256=bad")

	err := verifyIngestSignature(request, body, HubOptions{
		IngestSecret:        "secret",
		IngestSignatureSkew: time.Minute,
		Now: func() time.Time {
			return time.Date(2026, 5, 12, 1, 0, 30, 0, time.UTC)
		},
	})
	if err == nil {
		t.Fatal("verifyIngestSignature returned nil error for invalid signature")
	}
}

func TestVerifyIngestSignatureRejectsStaleTimestamp(t *testing.T) {
	body := []byte(`{"batch_id":"test"}`)
	timestamp := "2026-05-12T01:00:00Z"
	request := httptest.NewRequest("POST", "/api/v1/ingest/events", nil)
	request.Header.Set(headerTimestamp, timestamp)
	request.Header.Set(headerSignature, "sha256="+signTestBody("secret", timestamp, body))

	err := verifyIngestSignature(request, body, HubOptions{
		IngestSecret:        "secret",
		IngestSignatureSkew: time.Minute,
		Now: func() time.Time {
			return time.Date(2026, 5, 12, 1, 2, 1, 0, time.UTC)
		},
	})
	if err == nil {
		t.Fatal("verifyIngestSignature returned nil error for stale timestamp")
	}
}

func signTestBody(secret string, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestHubRouterListsRuleDefinitions(t *testing.T) {
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/rules?platform=wordpress", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Count int `json:"count"`
		Rules []struct {
			ID          string   `json:"id"`
			Version     string   `json:"version"`
			Category    string   `json:"category"`
			Platforms   []string `json:"platforms"`
			ActionHints []string `json:"action_hints"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Count == 0 {
		t.Fatalf("body = %#v, want WordPress rules", body)
	}
	if body.Rules[0].Version == "" || body.Rules[0].Category != "database_snapshot" {
		t.Fatalf("first rule = %#v, want versioned database rule", body.Rules[0])
	}
}
