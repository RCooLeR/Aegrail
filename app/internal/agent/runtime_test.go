package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
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

func TestClassifyFileSeverityTreatsLocalWpConfigAsHigh(t *testing.T) {
	path := filepath.FromSlash("/var/www/site/wp-config-local.php")
	severity := classifyFileSeverity("file.modified", path)
	if severity != string(domain.SeverityHigh) {
		t.Fatalf("severity = %q, want high", severity)
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
	if !result.Baselined || result.Queued != 0 || result.WatchedLogs != 1 {
		t.Fatalf("first result = %+v, want one log baseline", result)
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
