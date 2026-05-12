package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rcooler/aegrail/internal/agent"
	"github.com/rcooler/aegrail/internal/domain"
)

func TestAgentConfigValidateAcceptsMultiSiteConfig(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "agent.yaml")
	content := fmt.Sprintf(`schema: aegrail.agent.server_config.v1
hub:
  url: http://127.0.0.1:8787
identity:
  org: acme
  project: hosted-sites
  environment: production
  host: web-01
  agent_id: agt_web_01
runtime:
  queue_dir: %q
  state_dir: %q
  interval: 30s
sites:
  - slug: example-com
    domain: example.com
    kind: wordpress
    app: example-com
    service: frontend
    root: %q
    files:
      profiles: [wordpress]
`, filepath.Join(root, "queue"), filepath.Join(root, "state"), filepath.Join(root, "site"))
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	stdout := runCLICapture(t, "aegrail", "agent", "config", "validate", "--config", configPath)
	if !strings.Contains(stdout, "Config valid: 1 site(s)") {
		t.Fatalf("stdout = %q, want config valid message", stdout)
	}
}

func TestAgentRunConfigQueuesBrowserCrawlEvents(t *testing.T) {
	pageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Example</title><script src="/app.js"></script></head><body></body></html>`))
	}))
	defer pageServer.Close()

	root := t.TempDir()
	configPath := filepath.Join(root, "agent.yaml")
	content := fmt.Sprintf(`schema: aegrail.agent.server_config.v1
hub:
  url: http://127.0.0.1:8787
identity:
  org: acme
  project: hosted-sites
  environment: production
  host: web-01
  agent_id: agt_web_01
runtime:
  queue_dir: %q
  state_dir: %q
  interval: 30s
sites:
  - slug: example-com
    domain: example.com
    kind: wordpress
    app: example-com
    service: frontend
    root: %q
    browser_crawl:
      enabled: true
      rendered: false
      max_pages: 1
      timeout: 5s
      urls:
        - %q
`, filepath.Join(root, "queue"), filepath.Join(root, "state"), filepath.Join(root, "site"), pageServer.URL)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	stdout := runCLICapture(t, "aegrail", "agent", "run", "--once", "--config", configPath)
	if !strings.Contains(stdout, "Browser crawled 1 page(s)") {
		t.Fatalf("stdout = %q, want browser crawl summary", stdout)
	}

	entries, err := os.ReadDir(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("pending files = %d, want 1", len(entries))
	}
	contentBytes, err := os.ReadFile(filepath.Join(root, "queue", "pending", entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	var batch agent.QueuedBatch
	if err := json.Unmarshal(contentBytes, &batch); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if batch.Source != "agent.browser" || batch.App != "example-com" {
		t.Fatalf("batch source/app = %s/%s, want agent.browser/example-com", batch.Source, batch.App)
	}
	if batch.Labels["site_slug"] != "example-com" || batch.Labels["domain"] != "example.com" {
		t.Fatalf("batch labels = %#v, want site context", batch.Labels)
	}
	if len(batch.Events) < 2 {
		t.Fatalf("events = %d, want crawl and script events", len(batch.Events))
	}
}

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
	_ = runCLICapture(t, args...)
}

func runCLICapture(t *testing.T, args ...string) string {
	t.Helper()
	app := New(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr
	if err := app.Run(args); err != nil {
		t.Fatalf("Run(%v) returned error: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}
