package httpadapter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"
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
