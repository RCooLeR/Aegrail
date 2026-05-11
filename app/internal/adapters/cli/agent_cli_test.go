package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rcooler/aegrail/internal/agent"
	"github.com/rcooler/aegrail/internal/domain"
)

func TestAgentStartOnceSendsOneRequestForOneQueuedChange(t *testing.T) {
	var requests int32
	var mu sync.Mutex
	var batchIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		var body struct {
			BatchID string `json:"batch_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		mu.Lock()
		batchIDs = append(batchIDs, body.BatchID)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	uploadsDir := filepath.Join(appRoot, "wp-content", "uploads")
	if err := os.MkdirAll(uploadsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	configPath := filepath.Join(root, "agent.json")
	queueDir := filepath.Join(root, "queue")
	runtime := agent.NewRuntime(agent.Config{ConfigPath: configPath, QueueDir: queueDir})
	if _, err := runtime.Install(context.Background(), agent.Identity{
		HubURL:      server.URL,
		QueueDir:    queueDir,
		Org:         "smoke",
		Project:     "watcher",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	runCLI(t, "aegrail", "agent", "start", "--once", "--config", configPath, "--queue-dir", queueDir, "--root", appRoot, "--profile", "wordpress")
	if err := os.WriteFile(filepath.Join(uploadsDir, "avatar.php"), []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	runCLI(t, "aegrail", "agent", "start", "--once", "--config", configPath, "--queue-dir", queueDir, "--root", appRoot, "--profile", "wordpress", "--secret", "secret")

	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("requests = %d, want 1; batch ids: %v", got, batchIDs)
	}
}

func runCLI(t *testing.T, args ...string) {
	t.Helper()
	app := New(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr
	if err := app.RunContext(context.Background(), args); err != nil {
		t.Fatalf("RunContext(%v) returned error: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
}
