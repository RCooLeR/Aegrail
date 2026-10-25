package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/wire"
)

func TestAgentQueueSendDeletesBatchByDefault(t *testing.T) {
	root := t.TempDir()
	fixedNow := time.Date(2026, 5, 12, 2, 10, 0, 0, time.UTC)
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		var envelope wire.Envelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("Unmarshal envelope returned error: %v", err)
		}
		if envelope.Schema != wire.EnvelopeSchema || envelope.NodeID != "agt_web_01" || envelope.Ciphertext == "" {
			t.Fatalf("envelope = %#v, want encrypted wire envelope", envelope)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return fixedNow }

	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     filepath.Join(root, "queue"),
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		App:          "main-web",
		Service:      "frontend",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
		BatchID:  "batch-1",
		Type:     "file.created",
		Target:   "/var/www/app/uploads/avatar.php",
		Severity: "high",
	}); err != nil {
		t.Fatalf("EnqueueEvent returned error: %v", err)
	}

	status, err := runtime.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.Pending != 1 {
		t.Fatalf("pending = %d, want 1", status.Pending)
	}

	result, err := runtime.SendQueued(context.Background(), 0)
	if err != nil {
		t.Fatalf("SendQueued returned error: %v", err)
	}
	if result.Sent != 1 || result.Failed != 0 || result.PendingAfter != 0 {
		t.Fatalf("result = %+v, want one sent and zero pending", result)
	}

	status, err = runtime.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error after send: %v", err)
	}
	if status.Pending != 0 || status.Sent != 0 {
		t.Fatalf("status = %+v, want zero pending and zero sent archives", status)
	}
}

func TestNewRuntimeDefaultsHubTimeoutToSixtySeconds(t *testing.T) {
	runtime := NewRuntime(Config{})
	if runtime.client.Timeout != 60*time.Second {
		t.Fatalf("client timeout = %s, want 60s", runtime.client.Timeout)
	}
	if runtime.Config.HubTimeout != 60*time.Second {
		t.Fatalf("config timeout = %s, want 60s", runtime.Config.HubTimeout)
	}
}

func TestNewRuntimeHonorsConfiguredHubTimeout(t *testing.T) {
	runtime := NewRuntime(Config{HubTimeout: 15 * time.Second})
	if runtime.client.Timeout != 15*time.Second {
		t.Fatalf("client timeout = %s, want 15s", runtime.client.Timeout)
	}
	if runtime.Config.HubTimeout != 15*time.Second {
		t.Fatalf("config timeout = %s, want 15s", runtime.Config.HubTimeout)
	}
}

func TestAgentQueueSendReportsTotalPendingBeforeLimit(t *testing.T) {
	root := t.TempDir()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     filepath.Join(root, "queue"),
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	for index := 0; index < 3; index++ {
		if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
			BatchID: "batch-limit-" + strconv.Itoa(index),
			Type:    "file.created",
			Target:  "/var/www/app/file.php",
		}); err != nil {
			t.Fatalf("EnqueueEvent %d returned error: %v", index, err)
		}
	}

	result, err := runtime.SendQueued(context.Background(), 1)
	if err != nil {
		t.Fatalf("SendQueued returned error: %v", err)
	}
	if result.PendingBefore != 3 || result.Sent != 1 || result.PendingAfter != 2 {
		t.Fatalf("result = %+v, want PendingBefore 3, Sent 1, PendingAfter 2", result)
	}
}

func TestSendQueuedAllDrainsPendingBeyondPerPassLimit(t *testing.T) {
	root := t.TempDir()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     filepath.Join(root, "queue"),
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	for index := 0; index < 3; index++ {
		if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
			BatchID: "batch-drain-" + strconv.Itoa(index),
			Type:    "file.created",
			Target:  "/var/www/app/file.php",
		}); err != nil {
			t.Fatalf("EnqueueEvent %d returned error: %v", index, err)
		}
	}

	result, err := runtime.SendQueuedAll(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("SendQueuedAll returned error: %v", err)
	}
	if result.PendingBefore != 3 || result.Sent != 3 || result.Failed != 0 || result.PendingAfter != 0 {
		t.Fatalf("result = %+v, want PendingBefore 3, Sent 3, PendingAfter 0", result)
	}
}

func TestSendQueuedAllStopsWhenNoProgress(t *testing.T) {
	root := t.TempDir()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     filepath.Join(root, "queue"),
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	for index := 0; index < 2; index++ {
		if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
			BatchID: "batch-stuck-" + strconv.Itoa(index),
			Type:    "file.created",
			Target:  "/var/www/app/file.php",
		}); err != nil {
			t.Fatalf("EnqueueEvent %d returned error: %v", index, err)
		}
	}

	result, err := runtime.SendQueuedAll(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("SendQueuedAll returned error: %v", err)
	}
	if result.Sent != 0 || result.Failed != 1 || result.PendingAfter != 2 {
		t.Fatalf("result = %+v, want one failed pass and both batches still pending", result)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want a single pass without retry loop", requests)
	}
}

func TestSendQueuedAllQuarantinesPermanentHubRejectAndContinues(t *testing.T) {
	root := t.TempDir()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			http.Error(w, `{"error":"resource not found"}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	queueDir := filepath.Join(root, "queue")
	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   queueDir,
	})
	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     queueDir,
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	for _, batchID := range []string{"a-permanent-reject", "b-good"} {
		if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
			BatchID: batchID,
			Type:    "file.created",
			Target:  "/var/www/app/file.php",
		}); err != nil {
			t.Fatalf("EnqueueEvent %q returned error: %v", batchID, err)
		}
	}

	result, err := runtime.SendQueuedAll(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("SendQueuedAll returned error: %v", err)
	}
	if result.PendingBefore != 2 || result.Sent != 1 || result.Failed != 1 || result.PendingAfter != 0 {
		t.Fatalf("result = %+v, want one quarantined reject, one sent, zero pending", result)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want rejected batch then newer batch", requests)
	}
	failedFiles, err := queueFiles(filepath.Join(queueDir, "failed"))
	if err != nil {
		t.Fatalf("queueFiles failed returned error: %v", err)
	}
	if len(failedFiles) != 1 || !strings.Contains(filepath.Base(failedFiles[0]), "a-permanent-reject") {
		t.Fatalf("failed files = %#v, want permanent reject quarantined", failedFiles)
	}
	if len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "moved to failed queue") {
		t.Fatalf("errors = %#v, want failed-queue message", result.Errors)
	}
}

func TestAgentQueueSendCanReadNodeSecretFromEnvironment(t *testing.T) {
	root := t.TempDir()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	t.Setenv("AEGRAIL_TEST_NODE_SECRET", nodeSecret)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope wire.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Fatalf("Decode envelope returned error: %v", err)
		}
		if envelope.Ciphertext == "" || envelope.NodeID != "agt_web_01" {
			t.Fatalf("envelope = %#v, want encrypted node batch", envelope)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	_, err = runtime.Install(context.Background(), Identity{
		HubURL:        server.URL,
		HubProtocol:   "aegrail-wire-v1",
		HubPublicKey:  hubPublic,
		NodeSecretEnv: "AEGRAIL_TEST_NODE_SECRET",
		QueueDir:      filepath.Join(root, "queue"),
		Org:           "acme",
		Project:       "customer-site",
		Environment:   "production",
		Host:          "web-01",
		AgentID:       "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{BatchID: "batch-env", Type: "file.created"}); err != nil {
		t.Fatalf("EnqueueEvent returned error: %v", err)
	}
	result, err := runtime.SendQueued(context.Background(), 0)
	if err != nil {
		t.Fatalf("SendQueued returned error: %v", err)
	}
	if result.Sent != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v, want env-secret send success", result)
	}
}

func TestAgentQueueSendQuarantinesWrongAgentIDBatch(t *testing.T) {
	root := t.TempDir()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	queueDir := filepath.Join(root, "queue")
	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   queueDir,
	})
	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     queueDir,
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		Host:         "web-01",
		AgentID:      "agt_current",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	pendingDir := filepath.Join(queueDir, "pending")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatalf("MkdirAll pending returned error: %v", err)
	}
	wrongBatch := QueuedBatch{
		Schema:      QueueSchema,
		QueuedAt:    time.Date(2026, 5, 21, 1, 0, 0, 0, time.UTC),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		Host:        "web-01",
		AgentID:     "agt_old",
		BatchID:     "wrong-agent",
		Source:      "logs",
		Events: []QueuedEvent{{
			Time: time.Date(2026, 5, 21, 1, 0, 0, 0, time.UTC),
			Type: "log.scan",
		}},
	}
	content, err := json.Marshal(wrongBatch)
	if err != nil {
		t.Fatalf("Marshal wrongBatch returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pendingDir, "wrong-agent.json"), content, 0o600); err != nil {
		t.Fatalf("WriteFile pending returned error: %v", err)
	}

	result, err := runtime.SendQueued(context.Background(), 0)
	if err != nil {
		t.Fatalf("SendQueued returned error: %v", err)
	}
	if result.Sent != 0 || result.Failed != 1 || result.PendingAfter != 0 {
		t.Fatalf("result = %+v, want one quarantined failed batch and zero pending", result)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want no hub requests for wrong-agent pending batch", requests)
	}
	failedFiles, err := queueFiles(filepath.Join(queueDir, "failed"))
	if err != nil {
		t.Fatalf("queueFiles failed returned error: %v", err)
	}
	if len(failedFiles) != 1 {
		t.Fatalf("failed files = %d, want 1", len(failedFiles))
	}
	if len(result.Errors) == 0 || !strings.Contains(result.Errors[0], "does not match configured agent_id") {
		t.Fatalf("errors = %#v, want configured-agent mismatch message", result.Errors)
	}
}

func TestAgentQueueSendCanRetainSentBatch(t *testing.T) {
	root := t.TempDir()
	fixedNow := time.Date(2026, 5, 12, 2, 10, 0, 0, time.UTC)
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath:    filepath.Join(root, "agent.json"),
		QueueDir:      filepath.Join(root, "queue"),
		SentRetention: time.Hour,
	})
	runtime.now = func() time.Time { return fixedNow }

	_, err = runtime.Install(context.Background(), Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     filepath.Join(root, "queue"),
		Org:          "acme",
		Project:      "customer-site",
		Environment:  "production",
		App:          "main-web",
		Service:      "frontend",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
		BatchID: "batch-1",
		Type:    "file.created",
	}); err != nil {
		t.Fatalf("EnqueueEvent returned error: %v", err)
	}

	result, err := runtime.SendQueued(context.Background(), 0)
	if err != nil {
		t.Fatalf("SendQueued returned error: %v", err)
	}
	if result.Sent != 1 || result.PendingAfter != 0 {
		t.Fatalf("result = %+v, want one sent and zero pending", result)
	}
	status, err := runtime.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error after send: %v", err)
	}
	if status.Pending != 0 || status.Sent != 1 {
		t.Fatalf("status = %+v, want retained sent archive", status)
	}
}

func TestAgentQueueSkipsDuplicatePendingBatch(t *testing.T) {
	root := t.TempDir()
	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	_, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	input := EnqueueEventInput{
		BatchID:  "batch-1",
		Type:     "file.created",
		Target:   "/var/www/app/uploads/avatar.php",
		Severity: "high",
	}
	if _, _, err := runtime.EnqueueEvent(context.Background(), input); err != nil {
		t.Fatalf("first EnqueueEvent returned error: %v", err)
	}
	if _, _, err := runtime.EnqueueEvent(context.Background(), input); err != nil {
		t.Fatalf("duplicate EnqueueEvent returned error: %v", err)
	}
	status, err := runtime.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.Pending != 1 {
		t.Fatalf("pending = %d, want 1", status.Pending)
	}
}

func TestAgentDiscardPendingMovesBatchToDiscarded(t *testing.T) {
	root := t.TempDir()
	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	_, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
		BatchID:  "batch-1",
		Type:     "file.created",
		Severity: "high",
	}); err != nil {
		t.Fatalf("EnqueueEvent returned error: %v", err)
	}

	result, err := runtime.DiscardPending(context.Background(), 0)
	if err != nil {
		t.Fatalf("DiscardPending returned error: %v", err)
	}
	if result.Discarded != 1 || result.PendingAfter != 0 {
		t.Fatalf("discard result = %+v, want one discarded and zero pending", result)
	}
	status, err := runtime.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.Pending != 0 || status.Discarded != 1 {
		t.Fatalf("status = %+v, want discarded queue count", status)
	}
}

func TestAgentQueueMaxPendingFilesDiscardsOldest(t *testing.T) {
	root := t.TempDir()
	runtime := NewRuntime(Config{
		ConfigPath:      filepath.Join(root, "agent.json"),
		QueueDir:        filepath.Join(root, "queue"),
		MaxPendingFiles: 2,
	})
	_, err := runtime.Install(context.Background(), Identity{
		HubURL:      "https://hub.example.test",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	})
	if err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	for index := 1; index <= 3; index++ {
		if _, _, err := runtime.EnqueueEvent(context.Background(), EnqueueEventInput{
			BatchID: fmt.Sprintf("batch-%d", index),
			Type:    "log.scan",
			Message: fmt.Sprintf("event %d", index),
		}); err != nil {
			t.Fatalf("EnqueueEvent %d returned error: %v", index, err)
		}
	}

	status, err := runtime.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.Pending != 2 || status.Discarded != 1 {
		t.Fatalf("status = %+v, want two pending and one discarded", status)
	}
	if _, err := os.Stat(filepath.Join(root, "queue", "pending", "batch-1.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest pending batch still exists or stat returned unexpected error: %v", err)
	}
	for _, name := range []string{"batch-2.json", "batch-3.json"} {
		if _, err := os.Stat(filepath.Join(root, "queue", "pending", name)); err != nil {
			t.Fatalf("expected pending %s: %v", name, err)
		}
	}
}

func TestScanWatchedPathsBaselinesThenQueuesFileCreate(t *testing.T) {
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	uploadsDir := filepath.Join(appRoot, "wp-content", "uploads")
	if err := os.MkdirAll(uploadsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC) }

	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	result, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("ScanWatchedPaths returned error: %v", err)
	}
	if !result.Baselined || result.Queued != 0 || result.WatchedFiles != 0 {
		t.Fatalf("first result = %+v, want empty baseline", result)
	}

	shellPath := filepath.Join(uploadsDir, "avatar.php")
	if err := os.WriteFile(shellPath, []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 1, 0, 0, time.UTC) }

	result, err = runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("ScanWatchedPaths returned error after create: %v", err)
	}
	if result.Baselined || result.Queued != 1 || result.WatchedFiles != 1 {
		t.Fatalf("second result = %+v, want one queued change", result)
	}

	files, err := queueFiles(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("queueFiles returned error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("pending files = %d, want 1", len(files))
	}
	content, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	var batch QueuedBatch
	if err := json.Unmarshal(content, &batch); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(batch.Events))
	}
	event := batch.Events[0]
	relativeUploadPath := filepath.ToSlash(filepath.Join("wp-content", "uploads", "avatar.php"))
	if event.Type != "file.created" || event.Severity != "high" || event.Target != relativeUploadPath {
		t.Fatalf("event = %+v, want high severity file.created for upload php", event)
	}
	if event.Payload["path"] != relativeUploadPath || event.Payload["relative_path"] != relativeUploadPath {
		t.Fatalf("relative_path = %#v", event.Payload["relative_path"])
	}

	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 2, 0, 0, time.UTC) }
	result, err = runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("ScanWatchedPaths returned error after clean scan: %v", err)
	}
	if result.Baselined || result.Queued != 1 || result.WatchedFiles != 1 {
		t.Fatalf("clean result = %+v, want one scan heartbeat", result)
	}
	files, err = queueFiles(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("queueFiles after clean scan returned error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("pending files after clean scan = %d, want 2", len(files))
	}
	var heartbeat QueuedBatch
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile heartbeat candidate returned error: %v", err)
		}
		var candidate QueuedBatch
		if err := json.Unmarshal(content, &candidate); err != nil {
			t.Fatalf("Unmarshal heartbeat candidate returned error: %v", err)
		}
		if len(candidate.Events) == 1 && candidate.Events[0].Type == "file.scan.completed" {
			heartbeat = candidate
			break
		}
	}
	if len(heartbeat.Events) != 1 {
		t.Fatalf("missing file.scan.completed heartbeat in queued batches")
	}
	if heartbeat.Events[0].Payload["watched_files"] != float64(1) {
		t.Fatalf("heartbeat payload = %#v, want watched_files 1", heartbeat.Events[0].Payload)
	}
}

func TestScanWatchedPathsBaselinesWithoutQueue(t *testing.T) {
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	uploadsDir := filepath.Join(appRoot, "wp-content", "uploads")
	if err := os.MkdirAll(uploadsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC) }

	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	result, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
		NoEvents: true,
	})
	if err != nil {
		t.Fatalf("ScanWatchedPaths baseline returned error: %v", err)
	}
	if !result.Baselined || result.Queued != 0 {
		t.Fatalf("baseline result = %+v, want baseline with zero queued events", result)
	}

	shellPath := filepath.Join(uploadsDir, "avatar.php")
	if err := os.WriteFile(shellPath, []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 1, 0, 0, time.UTC) }

	result, err = runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
		NoEvents: true,
	})
	if err != nil {
		t.Fatalf("ScanWatchedPaths second scan returned error: %v", err)
	}
	if result.Queued != 0 {
		t.Fatalf("second result = %+v, want no queued events in no-events mode", result)
	}
	files, err := queueFiles(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("queueFiles returned error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("pending files = %d, want 0 in no-events mode", len(files))
	}
}

func TestScanWatchedPathsReusesHashesForUnchangedFiles(t *testing.T) {
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	pluginDir := filepath.Join(appRoot, "wp-content", "plugins", "shop")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "shop.php"), []byte("<?php echo 'shop';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	result, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("baseline scan returned error: %v", err)
	}
	if !result.Baselined || result.HashedFiles != 1 || result.ReusedHashes != 0 {
		t.Fatalf("baseline result = %+v, want one hashed file and no reused hashes", result)
	}

	result, err = runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("unchanged scan returned error: %v", err)
	}
	if result.HashedFiles != 0 || result.ReusedHashes != 1 {
		t.Fatalf("unchanged result = %+v, want previous hash reused without hashing", result)
	}
}

func TestScanWatchedPathsRefreshesHashesAfterFullHashInterval(t *testing.T) {
	t.Setenv("AEGRAIL_WATCH_FULL_HASH_INTERVAL", "1s")
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	pluginDir := filepath.Join(appRoot, "wp-content", "plugins", "shop")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "shop.php"), []byte("<?php echo 'shop';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC) }
	if _, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	}); err != nil {
		t.Fatalf("baseline scan returned error: %v", err)
	}

	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 2, 0, time.UTC) }
	result, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("interval scan returned error: %v", err)
	}
	if result.HashedFiles != 1 || result.ReusedHashes != 0 {
		t.Fatalf("interval result = %+v, want full hash refresh", result)
	}
}

func TestScanWatchedPathsSkipsCacheAndSafeUploadMedia(t *testing.T) {
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	uploadsDir := filepath.Join(appRoot, "wp-content", "uploads")
	cacheDir := filepath.Join(appRoot, "wp-content", "cache")
	if err := os.MkdirAll(uploadsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll uploads returned error: %v", err)
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatalf("MkdirAll cache returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	if _, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	}); err != nil {
		t.Fatalf("baseline scan returned error: %v", err)
	}

	if err := os.WriteFile(filepath.Join(uploadsDir, "photo.jpg"), []byte("image"), 0o600); err != nil {
		t.Fatalf("WriteFile jpg returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "rendered.php"), []byte("<?php echo 'cache';"), 0o600); err != nil {
		t.Fatalf("WriteFile cache returned error: %v", err)
	}
	shellPath := filepath.Join(uploadsDir, "avatar.php")
	if err := os.WriteFile(shellPath, []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile php returned error: %v", err)
	}

	result, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{
		Root:     appRoot,
		Profiles: []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("second scan returned error: %v", err)
	}
	if result.Queued != 1 || result.WatchedFiles != 1 {
		t.Fatalf("result = %+v, want only uploaded php tracked", result)
	}
}

func TestShouldSkipNoisyPathSkipsCacheVariants(t *testing.T) {
	if !shouldSkipNoisyPath("/var/www/site/wp-content/cache_old/logo.png") {
		t.Fatalf("expected cache_old paths to be skipped as noisy")
	}
	if !shouldSkipNoisyPath("/var/www/site/.cache_old/logo.php") {
		t.Fatalf("expected .cache_old paths to be skipped as noisy")
	}
	if !shouldSkipNoisyPath("/var/www/site/cache-old/logo.php") {
		t.Fatalf("expected cache-old paths to be skipped as noisy")
	}
	if shouldSkipNoisyPath("/var/www/site/upload/avatar.php") {
		t.Fatalf("uploading php should be tracked")
	}
	if !shouldSkipNoisyPath("/var/www/site/wp-content/plugins/shop/assets/logo.png") {
		t.Fatalf("plugin binary assets should be skipped")
	}
	if shouldSkipNoisyPath("/var/www/site/wp-content/plugins/shop/assets/app.js") {
		t.Fatalf("plugin scripts should still be tracked")
	}
	if !shouldSkipNoisyPath("/var/www/site/assets/logo.png") {
		t.Fatalf("static binary assets should be skipped")
	}
	if shouldSkipNoisyPath("/var/www/site/assets/app.js") {
		t.Fatalf("static scripts should still be tracked")
	}
	if !shouldSkipNoisyPath("/var/www/site/modules/reviews/logs/logs.txt") {
		t.Fatalf("module log files should be skipped")
	}
	if !shouldSkipNoisyPath("/var/www/site/themes/at_petstore/profiles/id_gencode_5b02b134d274d_1526903092.tpl") {
		t.Fatalf("generated PrestaShop theme profile templates should be skipped")
	}
	if shouldSkipNoisyPath("/var/www/site/themes/at_petstore/profiles/layout.tpl") {
		t.Fatalf("normal theme profile templates should still be tracked")
	}
	if !shouldSkipNoisyPath("/var/www/site/public/build/assets/app.123.js") {
		t.Fatalf("generated Laravel build assets should be skipped")
	}
	if shouldSkipNoisyPath("/var/www/site/routes/web.php") {
		t.Fatalf("Laravel route source should be tracked")
	}
	if shouldSkipNoisyPath("/var/www/site/public/build/shell.php") {
		t.Fatalf("PHP in generated asset directories should still be tracked")
	}
}

func TestFileChangedIgnoresModTimeWhenHashesMatch(t *testing.T) {
	previous := fileState{
		Path:      "/site/wp-content/themes/theme/functions.php",
		SizeBytes: 12,
		ModTime:   time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC),
		SHA256:    "abc123",
	}
	current := previous
	current.ModTime = previous.ModTime.Add(5 * time.Minute)

	if fileChanged(previous, current) {
		t.Fatalf("fileChanged returned true for same hash and different mod time")
	}

	current.SHA256 = "def456"
	if !fileChanged(previous, current) {
		t.Fatalf("fileChanged returned false for different hash")
	}
}

func TestCanReuseFileHashRejectsStatusChangeTimeDrift(t *testing.T) {
	previous := fileState{
		Path:             "/site/wp-content/plugins/shop/plugin.php",
		SizeBytes:        12,
		ModTime:          time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC),
		StatusChangeTime: time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC),
		SHA256:           "abc123",
	}
	current := previous
	current.StatusChangeTime = previous.StatusChangeTime.Add(5 * time.Minute)

	if canReuseFileHash(previous, current) {
		t.Fatalf("canReuseFileHash returned true after status-change time drift")
	}
}

func TestFileEventUsesStatusChangeTimeForBackdatedCreate(t *testing.T) {
	observedAt := time.Date(2026, 5, 17, 2, 30, 0, 0, time.UTC)
	modTime := observedAt.AddDate(-1, 0, 0)
	statusChangeTime := observedAt.Add(-3 * time.Second)
	state := fileState{
		Path:             filepath.FromSlash("/site/wp-content/uploads/shell.php"),
		RelativePath:     "wp-content/uploads/shell.php",
		SizeBytes:        12,
		ModTime:          modTime,
		StatusChangeTime: statusChangeTime,
		ObservedAt:       observedAt,
		SHA256:           "abc123",
	}

	event := fileEvent("file.created", state, fileState{})
	if !event.EventTime.Equal(statusChangeTime) {
		t.Fatalf("event time = %s, want status change time %s", event.EventTime, statusChangeTime)
	}
	if event.Payload["event_time_source"] != "status_change_time" || event.Payload["timestamp_backdated"] != true {
		t.Fatalf("payload = %#v, want backdated timestamp evidence", event.Payload)
	}
	if event.Payload["mod_time"] != modTime.Format(time.RFC3339Nano) ||
		event.Payload["status_change_time"] != statusChangeTime.Format(time.RFC3339Nano) ||
		event.Payload["observed_at"] != observedAt.Format(time.RFC3339Nano) {
		t.Fatalf("payload = %#v, want filesystem timestamps", event.Payload)
	}
}

func TestFileEventUsesOldSourceTimeWhenNoMaskingEvidence(t *testing.T) {
	observedAt := time.Date(2026, 5, 17, 2, 30, 0, 0, time.UTC)
	modTime := observedAt.AddDate(-1, 0, 0)
	state := fileState{
		Path:         filepath.FromSlash("/site/wp-content/themes/theme/archive.php"),
		RelativePath: "wp-content/themes/theme/archive.php",
		SizeBytes:    12,
		ModTime:      modTime,
		ObservedAt:   observedAt,
		SHA256:       "abc123",
	}

	event := fileEvent("file.created", state, fileState{})
	if !event.EventTime.Equal(modTime) {
		t.Fatalf("event time = %s, want source mod time %s", event.EventTime, modTime)
	}
	if event.Payload["event_time_source"] != "mod_time" {
		t.Fatalf("payload = %#v, want mod_time source", event.Payload)
	}
	if _, ok := event.Payload["timestamp_backdated"]; ok {
		t.Fatalf("payload = %#v, did not expect masking flag", event.Payload)
	}
}

func TestFileModifiedEventFlagsHashChangeWithPreservedModTime(t *testing.T) {
	observedAt := time.Date(2026, 5, 17, 2, 45, 0, 0, time.UTC)
	modTime := observedAt.Add(-30 * time.Minute)
	previous := fileState{
		Path:      filepath.FromSlash("/site/wp-content/plugins/shop/plugin.php"),
		SizeBytes: 12,
		ModTime:   modTime,
		SHA256:    "old",
	}
	current := previous
	current.ObservedAt = observedAt
	current.SHA256 = "new"

	event := fileEvent("file.modified", current, previous)
	if !event.EventTime.Equal(observedAt) {
		t.Fatalf("event time = %s, want observed time %s", event.EventTime, observedAt)
	}
	if event.Payload["event_time_source"] != "observed_at" || event.Payload["timestamp_backdated"] != true {
		t.Fatalf("payload = %#v, want preserved-mtime masking evidence", event.Payload)
	}
}

func TestClassifyFileSeverityTreatsLocalWpConfigAsHigh(t *testing.T) {
	path := filepath.FromSlash("/var/www/site/wp-config-local.php")
	severity := classifyFileSeverity("file.modified", path)
	if severity != string(domain.SeverityHigh) {
		t.Fatalf("severity = %q, want high", severity)
	}
}

func TestFileEventRecognizesPrestaShopAssetRedirectGuard(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "themes", "at_petstore", "modules", "blockreviews", "views", "img", "btn", "index.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	content := `<?php
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Location: ../");
exit;
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	state := testFileState(t, root, path)
	event := fileEvent("file.created", state, fileState{})
	if event.Severity != string(domain.SeverityInfo) {
		t.Fatalf("severity = %q, want info for recognized guard", event.Severity)
	}
	if event.Payload["file_kind"] != "prestashop_asset_guard_index" ||
		event.Payload["file_role"] != "directory_guard" ||
		event.Payload["file_role_confidence"] != "high" {
		t.Fatalf("payload = %#v, want recognized directory guard metadata", event.Payload)
	}
}

func TestFileEventKeepsSuspiciousPHPInPrestaShopAssetPathHigh(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "themes", "at_petstore", "modules", "blockreviews", "views", "img", "btn", "index.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(path, []byte(`<?php eval($_POST["x"] ?? "");`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	state := testFileState(t, root, path)
	event := fileEvent("file.created", state, fileState{})
	if event.Severity != string(domain.SeverityHigh) {
		t.Fatalf("severity = %q, want high for unrecognized PHP in image path", event.Severity)
	}
	if _, ok := event.Payload["file_kind"]; ok {
		t.Fatalf("payload = %#v, did not expect benign file_kind", event.Payload)
	}
}

func TestFileEventRecognizesPostEvalPHPWebshellContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "modules", "gridhtml", "x.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(path, []byte(`<?php @eval(base64_decode($_POST[0]));`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	event := fileEvent("file.created", testFileState(t, root, path), fileState{})
	if event.Severity != string(domain.SeverityHigh) {
		t.Fatalf("severity = %q, want high for webshell-like PHP", event.Severity)
	}
	if event.Payload["file_role"] != "suspicious_php" ||
		event.Payload["security_context"] != "webshell_like_php" ||
		event.Payload["suspicious_php_reason"] != "post_base64_eval_webshell" {
		t.Fatalf("payload = %#v, want suspicious PHP metadata without file content", event.Payload)
	}
}

func TestFileEventRecognizesSelfDeletingCommandProbe(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "modules", "ps_facetedsearch", "ps_facetedsearch-3d2c8f50.php")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(path, []byte(`<?php echo "CMD_START\n"; passthru('id'); echo "\nCMD_END\n"; @unlink(__FILE__);`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	event := fileEvent("file.created", testFileState(t, root, path), fileState{})
	if event.Severity != string(domain.SeverityHigh) {
		t.Fatalf("severity = %q, want high for command probe PHP", event.Severity)
	}
	if event.Payload["suspicious_php_reason"] != "self_deleting_command_probe" {
		t.Fatalf("payload = %#v, want command probe reason", event.Payload)
	}
}

func TestFileEventAddsFrameworkDeployEvidence(t *testing.T) {
	observedAt := time.Date(2026, 5, 17, 2, 45, 0, 0, time.UTC)
	laravel := fileState{
		Path:         filepath.FromSlash("/site/routes/web.php"),
		RelativePath: "routes/web.php",
		SizeBytes:    12,
		ModTime:      observedAt,
		ObservedAt:   observedAt,
		SHA256:       "abc123",
	}
	event := fileEvent("file.modified", laravel, fileState{})
	if event.Payload["platform_hint"] != "laravel" ||
		event.Payload["file_area"] != "route" ||
		event.Payload["framework_component"] != "routes" ||
		event.Payload["deploy_evidence"] != true {
		t.Fatalf("laravel payload = %#v, want route deploy evidence", event.Payload)
	}

	presta := fileState{
		Path:         filepath.FromSlash("/site/modules/payments/config.xml"),
		RelativePath: "modules/payments/config.xml",
		SizeBytes:    12,
		ModTime:      observedAt,
		ObservedAt:   observedAt,
		SHA256:       "def456",
	}
	event = fileEvent("file.created", presta, fileState{})
	if event.Payload["platform_hint"] != "prestashop" ||
		event.Payload["file_area"] != "extension" ||
		event.Payload["framework_component"] != "module" ||
		event.Payload["deploy_evidence"] != true {
		t.Fatalf("prestashop payload = %#v, want module deploy evidence", event.Payload)
	}

	upload := fileState{
		Path:         filepath.FromSlash("/site/wp-content/uploads/avatar.php"),
		RelativePath: "wp-content/uploads/avatar.php",
		SizeBytes:    12,
		ModTime:      observedAt,
		ObservedAt:   observedAt,
		SHA256:       "ghi789",
	}
	event = fileEvent("file.created", upload, fileState{})
	if event.Payload["platform_hint"] != "wordpress" ||
		event.Payload["file_area"] != "writable_asset" ||
		event.Payload["security_context"] != "writable_php" {
		t.Fatalf("upload payload = %#v, want writable PHP evidence", event.Payload)
	}

	reactSource := fileState{
		Path:         filepath.FromSlash("/site/src/App.tsx"),
		RelativePath: "src/App.tsx",
		SizeBytes:    12,
		ModTime:      observedAt,
		ObservedAt:   observedAt,
		SHA256:       "jkl012",
	}
	event = fileEvent("file.modified", reactSource, fileState{})
	if event.Payload["platform_hint"] != "react" ||
		event.Payload["file_area"] != "frontend_source" ||
		event.Payload["framework_component"] != "entrypoint" ||
		event.Payload["deploy_evidence"] != true {
		t.Fatalf("react payload = %#v, want frontend deploy evidence", event.Payload)
	}

	nodeRoute := fileState{
		Path:         filepath.FromSlash("/site/routes/auth.js"),
		RelativePath: "routes/auth.js",
		SizeBytes:    12,
		ModTime:      observedAt,
		ObservedAt:   observedAt,
		SHA256:       "mno345",
	}
	event = fileEvent("file.modified", nodeRoute, fileState{})
	if event.Payload["platform_hint"] != "nodejs" ||
		event.Payload["file_area"] != "backend_source" ||
		event.Payload["framework_component"] != "route" ||
		event.Payload["deploy_evidence"] != true {
		t.Fatalf("node payload = %#v, want backend route deploy evidence", event.Payload)
	}

	staticEntry := fileState{
		Path:         filepath.FromSlash("/site/service-worker.js"),
		RelativePath: "service-worker.js",
		SizeBytes:    12,
		ModTime:      observedAt,
		ObservedAt:   observedAt,
		SHA256:       "pqr678",
	}
	event = fileEvent("file.modified", staticEntry, fileState{})
	if event.Payload["platform_hint"] != "static" ||
		event.Payload["file_area"] != "public_entrypoint" ||
		event.Payload["framework_component"] != "document" ||
		event.Payload["deploy_evidence"] != true {
		t.Fatalf("static payload = %#v, want static entrypoint deploy evidence", event.Payload)
	}
}

func testFileState(t *testing.T, root string, path string) fileState {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	scan := watchScanResult{}
	state, err := buildFileState(path, info, root, map[string]fileState{}, true, &scan)
	if err != nil {
		t.Fatalf("buildFileState returned error: %v", err)
	}
	return state
}

func TestScanWatchedPathsReturnsErrorWhenStateIsLocked(t *testing.T) {
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	if err := os.MkdirAll(appRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	lockPath := filepath.Join(root, "state", "file-watch.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatalf("MkdirAll lock dir returned error: %v", err)
	}
	if err := os.WriteFile(lockPath, []byte("locked"), 0o600); err != nil {
		t.Fatalf("WriteFile lock returned error: %v", err)
	}

	_, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{Paths: []string{appRoot}})
	if err == nil || !strings.Contains(err.Error(), "watch state is locked") {
		t.Fatalf("ScanWatchedPaths error = %v, want lock error", err)
	}
}

func TestScanWatchedPathsRecoversFromStaleWatchLock(t *testing.T) {
	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	if err := os.MkdirAll(appRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC) }
	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	lockPath := filepath.Join(root, "state", "file-watch.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatalf("MkdirAll lock dir returned error: %v", err)
	}
	oldTime := time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC).Add(-10 * time.Minute)
	if err := os.WriteFile(lockPath, []byte("stale-lock"), 0o600); err != nil {
		t.Fatalf("WriteFile lock returned error: %v", err)
	}
	if err := os.Chtimes(lockPath, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes stale lock returned error: %v", err)
	}
	t.Setenv("AEGRAIL_WATCH_LOCK_STALE_AFTER", "5m")

	_, err := runtime.ScanWatchedPaths(context.Background(), WatchOptions{Paths: []string{appRoot}})
	if err != nil {
		t.Fatalf("ScanWatchedPaths returned error for stale lock recovery: %v", err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock should be removed after recovery, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "state", "file-watch.json")); err != nil {
		t.Fatalf("baseline state expected to be created: %v", err)
	}
}

func TestScanLogPathsBaselinesThenQueuesAppendedLine(t *testing.T) {
	t.Setenv("AEGRAIL_TOR_CHECK", "0")
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	logPath := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logPath, []byte("127.0.0.1 - - [12/May/2026:08:00:00 +0000] \"GET / HTTP/1.1\" 200 12\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC) }

	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	result, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("ScanLogPaths returned error: %v", err)
	}
	if !result.Baselined || result.Queued != 1 || result.WatchedLogs != 1 {
		t.Fatalf("first result = %+v, want queued log baseline marker", result)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	if _, err := file.WriteString("127.0.0.1 - - [12/May/2026:08:01:00 +0000] \"GET /wp-login.php?token=super-secret HTTP/1.1\" 500 42\n"); err != nil {
		t.Fatalf("WriteString returned error: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 1, 0, 0, time.UTC) }

	result, err = runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("ScanLogPaths returned error after append: %v", err)
	}
	if result.Baselined || result.Queued != 1 || result.WatchedLogs != 1 {
		t.Fatalf("second result = %+v, want one queued log line", result)
	}

	files, err := queueFiles(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("queueFiles returned error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("pending files = %d, want 2", len(files))
	}
	var batch QueuedBatch
	var baseline QueuedBatch
	for _, queued := range files {
		content, err := os.ReadFile(queued)
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}
		var candidate QueuedBatch
		if err := json.Unmarshal(content, &candidate); err != nil {
			t.Fatalf("Unmarshal returned error: %v", err)
		}
		if len(candidate.Events) == 1 && candidate.Events[0].Type == "log.access" {
			batch = candidate
		}
		if len(candidate.Events) == 1 && candidate.Events[0].Type == "log.baseline.created" {
			baseline = candidate
		}
	}
	if len(baseline.Events) != 1 || baseline.Events[0].Payload["watched_logs"] != float64(1) {
		t.Fatalf("baseline batch = %#v, want log baseline marker", baseline)
	}
	if !strings.HasPrefix(batch.BatchID, "log-") {
		t.Fatalf("batch id = %q, want log prefix", batch.BatchID)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(batch.Events))
	}
	event := batch.Events[0]
	if event.Type != "log.access" || event.Severity != "medium" || event.Target != filepath.Clean(logPath) {
		t.Fatalf("event = %+v, want medium log.access for 500 access log", event)
	}
	if !event.Time.Equal(time.Date(2026, 5, 12, 8, 1, 0, 0, time.UTC)) {
		t.Fatalf("event time = %s, want parsed log timestamp", event.Time)
	}
	line, ok := event.Payload["line"].(string)
	if !ok {
		t.Fatalf("payload line = %#v, want string", event.Payload["line"])
	}
	if strings.Contains(line, "super-secret") || !strings.Contains(line, "[REDACTED]") {
		t.Fatalf("payload line was not redacted: %s", line)
	}
	if event.Payload["parser"] != "web_access" || event.Payload["path"] != "/wp-login.php" {
		t.Fatalf("structured payload = %#v", event.Payload)
	}
	query, _ := event.Payload["query_redacted"].(string)
	if strings.Contains(query, "super-secret") || !strings.Contains(query, "%5BREDACTED%5D") {
		t.Fatalf("structured query was not redacted: %q", query)
	}
	if event.Payload["status_code"] != float64(500) {
		t.Fatalf("status_code = %#v, want 500", event.Payload["status_code"])
	}
}

func TestScanLogPathsBatchesAppendedLinesIntoSingleBatch(t *testing.T) {
	t.Setenv("AEGRAIL_TOR_CHECK", "0")
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	logPath := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logPath, []byte("127.0.0.1 - - [12/May/2026:08:00:00 +0000] \"GET / HTTP/1.1\" 200 12\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC) }

	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	if _, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}}); err != nil {
		t.Fatalf("ScanLogPaths baseline returned error: %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	const appended = 5
	for index := 0; index < appended; index++ {
		line := fmt.Sprintf("203.0.113.7 - - [12/May/2026:08:01:0%d +0000] \"GET /wp-login.php HTTP/1.1\" 500 42\n", index)
		if _, err := file.WriteString(line); err != nil {
			t.Fatalf("WriteString %d returned error: %v", index, err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	runtime.now = func() time.Time { return time.Date(2026, 5, 12, 8, 2, 0, 0, time.UTC) }

	result, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("ScanLogPaths returned error after append: %v", err)
	}
	if result.Queued != appended {
		t.Fatalf("queued = %d, want %d events", result.Queued, appended)
	}

	files, err := queueFiles(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("queueFiles returned error: %v", err)
	}
	// One baseline-marker batch from the first scan plus a single multi-event
	// batch for all appended lines.
	if len(files) != 2 {
		t.Fatalf("pending files = %d, want 2 (baseline marker + one log batch)", len(files))
	}
	var batch QueuedBatch
	for _, queued := range files {
		content, err := os.ReadFile(queued)
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}
		var candidate QueuedBatch
		if err := json.Unmarshal(content, &candidate); err != nil {
			t.Fatalf("Unmarshal returned error: %v", err)
		}
		if len(candidate.Events) > 0 && candidate.Events[0].Type == "log.access" {
			batch = candidate
		}
	}
	if !strings.HasPrefix(batch.BatchID, "log-") {
		t.Fatalf("batch id = %q, want log prefix", batch.BatchID)
	}
	if len(batch.Events) != appended {
		t.Fatalf("events in batch = %d, want %d", len(batch.Events), appended)
	}
	if batch.App != "main-web" || batch.Service != "frontend" {
		t.Fatalf("batch scope = app %q service %q, want identity scope", batch.App, batch.Service)
	}
	for index, event := range batch.Events {
		if event.Type != "log.access" || event.Target != filepath.Clean(logPath) {
			t.Fatalf("event %d = %+v, want log.access for %s", index, event, logPath)
		}
		wantTime := time.Date(2026, 5, 12, 8, 1, index, 0, time.UTC)
		if !event.Time.Equal(wantTime) {
			t.Fatalf("event %d time = %s, want %s", index, event.Time, wantTime)
		}
	}
}

func TestResolveWatchPathsReturnsProfilePaths(t *testing.T) {
	root := filepath.Join("var", "www", "site")
	paths, err := ResolveWatchPaths(WatchOptions{
		Root:     root,
		Profiles: []string{"wordpress", "prestashop", "mautic"},
	})
	if err != nil {
		t.Fatalf("ResolveWatchPaths returned error: %v", err)
	}
	expected := map[string]bool{
		filepath.Clean(filepath.Join(root, "wp-config.php")):         false,
		filepath.Clean(filepath.Join(root, "wp-config-local.php")):   false,
		filepath.Clean(filepath.Join(root, "wp-content", "uploads")): false,
		filepath.Clean(filepath.Join(root, "config")):                false,
		filepath.Clean(filepath.Join(root, "modules")):               false,
		filepath.Clean(filepath.Join(root, "var", "logs")):           false,
		filepath.Clean(filepath.Join(root, "app", "config")):         false,
		filepath.Clean(filepath.Join(root, "wp-content", "plugins")): false,
		filepath.Clean(filepath.Join(root, "wp-content", "themes")):  false,
		filepath.Clean(filepath.Join(root, "themes")):                false,
		filepath.Clean(filepath.Join(root, "upload")):                false,
		filepath.Clean(filepath.Join(root, "img")):                   false,
		filepath.Clean(filepath.Join(root, ".env")):                  false,
		filepath.Clean(filepath.Join(root, "media")):                 false,
		filepath.Clean(filepath.Join(root, "plugins")):               false,
	}
	for _, path := range paths {
		if _, ok := expected[path]; ok {
			expected[path] = true
		}
	}
	for path, found := range expected {
		if !found {
			t.Fatalf("expected profile path %s in %v", path, paths)
		}
	}
}

func TestResolveWatchPathsReturnsFrontendProfilePaths(t *testing.T) {
	root := filepath.Join("var", "www", "frontend")
	paths, err := ResolveWatchPaths(WatchOptions{
		Root:     root,
		Profiles: []string{"static", "react", "nodejs"},
	})
	if err != nil {
		t.Fatalf("ResolveWatchPaths returned error: %v", err)
	}
	expected := map[string]bool{
		filepath.Clean(root): false,
		filepath.Clean(filepath.Join(root, "package.json")):   false,
		filepath.Clean(filepath.Join(root, "vite.config.ts")): false,
		filepath.Clean(filepath.Join(root, "src")):            false,
		filepath.Clean(filepath.Join(root, "public")):         false,
		filepath.Clean(filepath.Join(root, "server.js")):      false,
		filepath.Clean(filepath.Join(root, "routes")):         false,
		filepath.Clean(filepath.Join(root, "middleware")):     false,
	}
	for _, path := range paths {
		if _, ok := expected[path]; ok {
			expected[path] = true
		}
	}
	for path, found := range expected {
		if !found {
			t.Fatalf("expected frontend profile path %s in %v", path, paths)
		}
	}
}
