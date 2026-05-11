package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentQueueSendMovesBatchToSent(t *testing.T) {
	root := t.TempDir()
	fixedNow := time.Date(2026, 5, 12, 2, 10, 0, 0, time.UTC)
	secret := "secret"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		timestamp := r.Header.Get("X-Aegrail-Timestamp")
		signature := strings.TrimPrefix(r.Header.Get("X-Aegrail-Signature"), "sha256=")
		if signature != signBody(secret, timestamp, body) {
			t.Fatalf("signature mismatch")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	runtime.now = func() time.Time { return fixedNow }

	_, err := runtime.Install(context.Background(), Identity{
		HubURL:      server.URL,
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

	result, err := runtime.SendQueued(context.Background(), secret, 0)
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
	if status.Pending != 0 || status.Sent != 1 {
		t.Fatalf("status = %+v, want zero pending and one sent", status)
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
	if event.Type != "file.created" || event.Severity != "high" || event.Target != filepath.Clean(shellPath) {
		t.Fatalf("event = %+v, want high severity file.created for upload php", event)
	}
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

func TestResolveWatchPathsReturnsProfilePaths(t *testing.T) {
	root := filepath.Join("var", "www", "site")
	paths, err := ResolveWatchPaths(WatchOptions{
		Root:     root,
		Profiles: []string{"wordpress", "prestashop"},
	})
	if err != nil {
		t.Fatalf("ResolveWatchPaths returned error: %v", err)
	}
	expected := map[string]bool{
		filepath.Clean(filepath.Join(root, "wp-config.php")):         false,
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
