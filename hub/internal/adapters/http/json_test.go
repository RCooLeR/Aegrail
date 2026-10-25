package httpadapter

import (
	"bytes"
	"compress/gzip"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestDecodeJSONBodyUsesStrictJSONV2Contract(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{name: "valid", body: []byte(`{"name":"dashboard"}`)},
		{name: "unknown member", body: []byte(`{"name":"dashboard","nae":"typo"}`), wantErr: true},
		{name: "duplicate member", body: []byte(`{"name":"first","name":"second"}`), wantErr: true},
		{name: "trailing value", body: []byte(`{"name":"dashboard"} {}`), wantErr: true},
		{name: "invalid utf8", body: append([]byte(`{"name":"`), 0xff, '"', '}'), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(test.body))
			var payload struct {
				Name string `json:"name"`
			}
			err := decodeJSONBody(recorder, request, &payload)
			if (err != nil) != test.wantErr {
				t.Fatalf("decodeJSONBody error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestDecodeJSONBodyLimitsRequestSize(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := `{"name":"` + strings.Repeat("x", int(maxJSONRequestBodyBytes)) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	var payload struct {
		Name string `json:"name"`
	}

	if err := decodeJSONBody(recorder, request, &payload); err == nil {
		t.Fatal("decodeJSONBody returned nil error for an oversized request")
	}
}

func TestDecodeJSONBodyAcceptsStandardPushSubscriptionShape(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/",
		strings.NewReader(`{"endpoint":"https://push.example/subscription","expirationTime":null,"keys":{"p256dh":"public-key","auth":"secret"}}`),
	)
	var payload pushSubscriptionRequest

	if err := decodeJSONBody(recorder, request, &payload); err != nil {
		t.Fatalf("decodeJSONBody returned error for PushSubscription.toJSON output: %v", err)
	}
	if payload.Endpoint != "https://push.example/subscription" || payload.Keys.P256DH != "public-key" || payload.Keys.Auth != "secret" {
		t.Fatalf("decoded push subscription = %#v", payload)
	}
}

func TestWriteJSONDoesNotCommitSuccessBeforeMarshal(t *testing.T) {
	recorder := httptest.NewRecorder()

	writeJSON(recorder, http.StatusAccepted, make(chan int))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

func TestHubRouterCompressesAPIJSONResponsesOnly(t *testing.T) {
	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail-hub", Version: "test"},
		nil,
		HubOptions{},
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", recorder.Header().Get("Content-Encoding"))
	}
	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader returned error: %v", err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if !bytes.Contains(body, []byte(`"error":"hub is not configured"`)) {
		t.Fatalf("decoded response = %s, want API error payload", body)
	}

	rootRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	rootRequest.Header.Set("Accept-Encoding", "gzip")
	rootRecorder := httptest.NewRecorder()
	router.ServeHTTP(rootRecorder, rootRequest)
	if got := rootRecorder.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("root Content-Encoding = %q, want uncompressed non-API response", got)
	}
}

func TestHubRouterHonorsAcceptEncodingQuality(t *testing.T) {
	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail-hub", Version: "test"},
		nil,
		HubOptions{},
	)
	tests := []struct {
		acceptEncoding string
		wantEncoding   string
	}{
		{acceptEncoding: "gzip;q=0"},
		{acceptEncoding: "xgzip"},
		{acceptEncoding: "gzip;q=bogus"},
		{acceptEncoding: "gzip;q=0.4, identity;q=0.8"},
		{acceptEncoding: "gzip;q=0.4, deflate;q=0.8, identity;q=0.2", wantEncoding: "deflate"},
		{acceptEncoding: "gzip;q=0, *;q=0"},
	}
	for _, test := range tests {
		t.Run(test.acceptEncoding, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/events", nil)
			request.Header.Set("Accept-Encoding", test.acceptEncoding)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if got := recorder.Header().Get("Content-Encoding"); got != test.wantEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, test.wantEncoding)
			}
		})
	}
}

func TestIngestEventsRequestAcceptsAgentQueueV1Contract(t *testing.T) {
	body := []byte(`{
		"schema":"aegrail.agent.queue.v1",
		"queued_at":"2026-08-28T09:10:11.123456789Z",
		"org":"acme","project":"shop","environment":"production",
		"app":"storefront","service":"web","host":"web-01",
		"agent_id":"agent-01","batch_id":"batch-01","source":"watch",
		"region":"eu-central","labels":{"tier":"edge"},
		"events":[{"time":"2026-08-28T09:10:10Z","type":"file.changed",
			"target":"/srv/app/index.php","severity":"medium","message":"changed",
			"region":"eu-central","labels":{"kind":"php"},"payload":{"size":42}}]
	}`)
	var request ingestEventsRequest
	if err := json.Unmarshal(body, &request, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("strictly decode Agent QueuedBatch JSON: %v", err)
	}
	input, err := request.toInput("wire-signature")
	if err != nil {
		t.Fatalf("toInput: %v", err)
	}
	if request.Schema != agentQueueSchema || request.QueuedAt.IsZero() ||
		input.AgentID != "agent-01" || input.ExternalBatchID != "batch-01" || len(input.Events) != 1 {
		t.Fatalf("decoded Agent queue contract incorrectly: request=%#v input=%#v", request, input)
	}
}

func TestIngestEventsRequestRejectsUnsupportedAgentQueueSchema(t *testing.T) {
	request := ingestEventsRequest{Schema: "aegrail.agent.queue.v2"}
	if _, err := request.toInput("wire-signature"); err == nil {
		t.Fatal("toInput accepted an unsupported Agent queue schema")
	}
}
