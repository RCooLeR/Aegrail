package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/wire"
)

func TestDecodeIngestBodyDecryptsWireEnvelope(t *testing.T) {
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	hubPrivate, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	nodePrivate, nodePublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	repo := newHTTPTestInventoryRepository()
	agent := repo.agents[repo.hosts[0].ID][0]
	agent.NodePublicKey = nodePublic
	agent.WireProtocol = wire.EnvelopeSchema
	repo.agents[repo.hosts[0].ID][0] = agent

	plaintext := []byte(`{"org":"acme","project":"customer-site","environment":"production","host":"web-01","agent_id":"agt_web_01","batch_id":"b1","events":[{"time":"2026-05-17T01:02:03Z","type":"test.event"}]}`)
	envelope, err := wire.Encrypt(plaintext, agent.AgentID, nodePrivate, hubPublic, now)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	decoded, signature, err := decodeIngestBody(request, body, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{
		WirePrivateKey:    hubPrivate,
		WireTimestampSkew: time.Minute,
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("decodeIngestBody returned error: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("decoded = %s, want %s", decoded, plaintext)
	}
	if signature == "" || signature[:8] != "wire:v1:" {
		t.Fatalf("signature = %q, want wire signature", signature)
	}
}

func TestDecodeIngestBodyRejectsRawJSON(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	_, _, err := decodeIngestBody(request, []byte(`{"batch_id":"raw"}`), hubapp.New(hubapp.Dependencies{}), HubOptions{
		WirePrivateKey: "local-test-key",
		Now:            time.Now,
	})
	if err == nil {
		t.Fatal("decodeIngestBody returned nil error for raw JSON")
	}
}

func TestIsLoopbackRequestDoesNotTrustHostFallback(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/nodes", nil)
	request.RemoteAddr = "not-a-valid-remote-address"
	request.Host = "127.0.0.1"

	if isLoopbackRequest(request) {
		t.Fatal("isLoopbackRequest trusted Host when RemoteAddr could not be parsed")
	}
}

func TestIsLoopbackRequestTrustsSocketRemoteAddress(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/nodes", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Host = "example.com"

	if !isLoopbackRequest(request) {
		t.Fatal("isLoopbackRequest did not trust loopback RemoteAddr")
	}
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

func TestHubAuthRateLimiterSweepsStaleKeys(t *testing.T) {
	limiter := newHubAuthRateLimiter(1, time.Minute)
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	if !limiter.allow("one", now) || !limiter.allow("two", now) {
		t.Fatalf("initial attempts should be allowed")
	}
	if got := len(limiter.attempts); got != 2 {
		t.Fatalf("attempt keys = %d, want 2 before sweep", got)
	}
	if !limiter.allow("three", now.Add(2*time.Minute)) {
		t.Fatalf("attempt after window should be allowed")
	}
	if got := len(limiter.attempts); got != 1 {
		t.Fatalf("attempt keys = %d, want stale keys swept", got)
	}
}
