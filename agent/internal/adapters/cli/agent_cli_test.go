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
	"time"

	"github.com/rcooler/aegrail/agent/internal/agent"
	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/wire"
)

func TestAgentConfigValidateAcceptsMultiSiteConfig(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "agent.yaml")
	content := fmt.Sprintf(`schema: aegrail.agent.server_config.v1
hub:
  url: http://127.0.0.1:8787
  protocol: aegrail-wire-v1
  hub_public_key: test-hub-public-key
  node_secret: test-node-secret
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
	stdout := runCLICapture(t, "agent", "config", "validate", "--config", configPath)
	if !strings.Contains(stdout, "Config valid: 1 site(s)") {
		t.Fatalf("stdout = %q, want config valid message", stdout)
	}
}

func TestAgentStatusAcceptsServerConfig(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "agent.yaml")
	content := fmt.Sprintf(`schema: aegrail.agent.server_config.v1
hub:
  url: http://127.0.0.1:8787
  protocol: aegrail-wire-v1
  hub_public_key: test-hub-public-key
  node_secret: test-node-secret
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
`, filepath.Join(root, "queue"), filepath.Join(root, "state"), filepath.Join(root, "site"))
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	stdout := runCLICapture(t, "agent", "status", "--config", configPath)
	if !strings.Contains(stdout, "DISCARDED") || !strings.Contains(stdout, filepath.Join(root, "queue")) {
		t.Fatalf("stdout = %q, want server-config queue status", stdout)
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
  protocol: aegrail-wire-v1
  hub_public_key: test-hub-public-key
  node_secret: test-node-secret
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

	stdout := runCLICapture(t, "agent", "run", "--once", "--config", configPath)
	if !strings.Contains(stdout, "Browser crawled 1 page(s)") {
		t.Fatalf("stdout = %q, want browser crawl summary", stdout)
	}
	if got := strings.Count(stdout, "example-com browser_pages=1"); got != 1 {
		t.Fatalf("stdout = %q, want one browser site summary, got %d", stdout, got)
	}

	entries, err := os.ReadDir(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("pending files = %d, want browser and coverage batches", len(entries))
	}
	batches := readQueuedBatches(t, filepath.Join(root, "queue", "pending"))
	batch := queuedBatchBySource(t, batches, "agent.browser")
	if batch.Source != "agent.browser" || batch.App != "example-com" {
		t.Fatalf("batch source/app = %s/%s, want agent.browser/example-com", batch.Source, batch.App)
	}
	if batch.Labels["site_slug"] != "example-com" || batch.Labels["domain"] != "example.com" {
		t.Fatalf("batch labels = %#v, want site context", batch.Labels)
	}
	if len(batch.Events) < 2 {
		t.Fatalf("events = %d, want crawl and script events", len(batch.Events))
	}
	coverage := queuedBatchBySource(t, batches, "agent.coverage")
	if len(coverage.Events) != 1 || coverage.Events[0].Type != "agent.config.coverage" {
		t.Fatalf("coverage batch = %#v", coverage)
	}
}

func TestAgentRunConfigQueuesDatabaseCoverageWarning(t *testing.T) {
	t.Setenv("AEGRAIL_TEST_MISSING_DB_DSN", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "agent.yaml")
	content := fmt.Sprintf(`schema: aegrail.agent.server_config.v1
hub:
  url: http://127.0.0.1:8787
  protocol: aegrail-wire-v1
  hub_public_key: test-hub-public-key
  node_secret: test-node-secret
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
    databases:
      - name: main
        engine: mysql
        dsn_env: AEGRAIL_TEST_MISSING_DB_DSN
        profile: wordpress
        table_prefix: wp_
        timeout: 2s
`, filepath.Join(root, "queue"), filepath.Join(root, "state"), filepath.Join(root, "site"))
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	stdout := runCLICapture(t, "agent", "run", "--once", "--config", configPath)
	if !strings.Contains(stdout, "Database collected 1 database(s)") {
		t.Fatalf("stdout = %q, want database summary", stdout)
	}
	if !strings.Contains(stdout, "example-com databases=1") {
		t.Fatalf("stdout = %q, want one database in site summary", stdout)
	}
	if !strings.Contains(stdout, "Config coverage checked 1 site(s); queued 1 update(s)") {
		t.Fatalf("stdout = %q, want coverage summary", stdout)
	}

	entries, err := os.ReadDir(filepath.Join(root, "queue", "pending"))
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("pending files = %d, want database and coverage batches", len(entries))
	}
	batches := readQueuedBatches(t, filepath.Join(root, "queue", "pending"))
	batch := queuedBatchBySource(t, batches, "agent.database")
	if batch.Source != "agent.database" || batch.Service != "database" {
		t.Fatalf("batch source/service = %s/%s, want agent.database/database", batch.Source, batch.Service)
	}
	if batch.Labels["db_name"] != "main" || batch.Labels["site_slug"] != "example-com" {
		t.Fatalf("batch labels = %#v, want database and site context", batch.Labels)
	}
	if len(batch.Events) != 2 {
		t.Fatalf("events = %d, want completed and warning events", len(batch.Events))
	}
	if batch.Events[1].Type != "db.coverage.warning" {
		t.Fatalf("event type = %s, want coverage warning", batch.Events[1].Type)
	}
	coverage := queuedBatchBySource(t, batches, "agent.coverage")
	if len(coverage.Events) != 1 {
		t.Fatalf("coverage batch = %#v", coverage)
	}
	if coverage.Events[0].Labels["coverage_level"] != "strong" {
		t.Fatalf("coverage batch = %#v", coverage)
	}
}

func TestAgentRunConfigBootstrapDoesNotQueueEvents(t *testing.T) {
	pageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Example</title><script src="/app.js"></script></head><body></body></html>`))
	}))
	defer pageServer.Close()

	root := t.TempDir()
	appRoot := filepath.Join(root, "site")
	if err := os.MkdirAll(filepath.Join(appRoot, "wp-content", "uploads"), 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	configPath := filepath.Join(root, "agent.yaml")
	content := fmt.Sprintf(`schema: aegrail.agent.server_config.v1
hub:
  url: http://127.0.0.1:8787
  protocol: aegrail-wire-v1
  hub_public_key: test-hub-public-key
  node_secret: test-node-secret
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
    browser_crawl:
      enabled: true
      rendered: false
      max_pages: 1
      timeout: 5s
      urls:
        - %q
`, filepath.Join(root, "queue"), filepath.Join(root, "state"), appRoot, pageServer.URL)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	pendingDir := filepath.Join(root, "queue", "pending")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatalf("MkdirAll pending returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pendingDir, "old-noise.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile pending returned error: %v", err)
	}

	stdout := runCLICapture(t, "agent", "run", "--once", "--bootstrap", "--discard-pending", "--config", configPath)
	if !strings.Contains(stdout, "Bootstrap mode enabled") {
		t.Fatalf("stdout = %q, want bootstrap confirmation", stdout)
	}
	if !strings.Contains(stdout, "Browser crawled 1 page(s); queued 0 event(s)") {
		t.Fatalf("stdout = %q, want bootstrap browser crawl summary without queued events", stdout)
	}
	if !strings.Contains(stdout, "Discarded 1 existing pending batch(es); pending 0") {
		t.Fatalf("stdout = %q, want discard summary", stdout)
	}
	if !strings.Contains(stdout, "Collector status:") ||
		!strings.Contains(stdout, "example-com files=baseline(0)") ||
		!strings.Contains(stdout, "browser=ok(1)") ||
		!strings.Contains(stdout, "config=skipped(bootstrap)") {
		t.Fatalf("stdout = %q, want clear collector status summary", stdout)
	}

	entries, err := os.ReadDir(pendingDir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("pending files = %d, want 0 in bootstrap mode", len(entries))
	}
	discardedEntries, err := os.ReadDir(filepath.Join(root, "queue", "discarded"))
	if err != nil {
		t.Fatalf("ReadDir discarded returned error: %v", err)
	}
	if len(discardedEntries) != 1 {
		t.Fatalf("discarded files = %d, want 1", len(discardedEntries))
	}
	statePath := filepath.Join(root, "state", "sites", "example-com", "file-watch.json")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("missing file watch state at %s: %v", statePath, err)
	}
}

func TestRunConfiguredDatabaseCollectorsCanSkipBySchedule(t *testing.T) {
	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	stateDir := filepath.Join(root, "state")
	appRoot := filepath.Join(root, "site")
	if err := os.MkdirAll(appRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	pendingDir := filepath.Join(queueDir, "pending")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatalf("MkdirAll pending returned error: %v", err)
	}

	t.Setenv("AEGRAIL_TEST_MISSING_DB_DSN", "")
	config := agent.ServerConfig{
		Runtime: agent.ServerRuntimeConfig{
			QueueDir: queueDir,
			StateDir: stateDir,
		},
		Identity: agent.ServerIdentityConfig{
			Region: "eu",
		},
		Sites: []agent.ServerSiteConfig{
			{
				Slug:    "example-com",
				App:     "example-com",
				Service: "frontend",
				Root:    appRoot,
				Databases: []agent.ServerDatabaseConfig{
					{
						Name:     "main",
						Engine:   "mysql",
						DSNEnv:   "AEGRAIL_TEST_MISSING_DB_DSN",
						Profile:  "wordpress",
						Timeout:  "2s",
						Schedule: "1m",
					},
				},
			},
		},
	}
	runtime := agent.NewRuntime(agent.Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   queueDir,
		Identity: &agent.Identity{
			HubURL:      "http://127.0.0.1:8787",
			QueueDir:    queueDir,
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
	})
	ctx := context.Background()
	statePath := agent.SiteStatePath(config, config.Sites[0], "db-main.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatalf("MkdirAll state dir returned error: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile state returned error: %v", err)
	}

	skipResult, err := runConfiguredDatabaseCollectors(ctx, runtime, config, false)
	if err != nil {
		t.Fatalf("runConfiguredDatabaseCollectors returned error: %v", err)
	}
	if skipResult.Sites[0].Databases != 1 {
		t.Fatalf("skip result databases=%d, want 1", skipResult.Sites[0].Databases)
	}
	if skipResult.Sites[0].Skipped != 1 {
		t.Fatalf("skip result skipped=%d, want 1", skipResult.Sites[0].Skipped)
	}
	if skipResult.Sites[0].Queued != 0 {
		t.Fatalf("skip result queued=%d, want 0", skipResult.Sites[0].Queued)
	}
	firstEntries, err := os.ReadDir(pendingDir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(firstEntries) != 0 {
		t.Fatalf("pending files=%d, want 0", len(firstEntries))
	}

	config.Sites[0].Databases[0].Schedule = "0s"
	runResult, err := runConfiguredDatabaseCollectors(ctx, runtime, config, false)
	if err != nil {
		t.Fatalf("runConfiguredDatabaseCollectors returned error: %v", err)
	}
	if runResult.Sites[0].Skipped != 0 {
		t.Fatalf("run result skipped=%d, want 0", runResult.Sites[0].Skipped)
	}
	if runResult.Sites[0].Queued == 0 {
		t.Fatalf("run result queued=%d, want more than 0", runResult.Sites[0].Queued)
	}
	secondEntries, err := os.ReadDir(pendingDir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(secondEntries) <= len(firstEntries) {
		t.Fatalf("second pending files=%d, want more than first run", len(secondEntries))
	}
}

func TestShouldSkipDatabaseCollection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	skip, err := shouldSkipDatabaseCollection(24*time.Hour, path)
	if err != nil {
		t.Fatalf("shouldSkipDatabaseCollection returned error: %v", err)
	}
	if !skip {
		t.Fatal("skip = false, want true for recent state within schedule window")
	}

	skip, err = shouldSkipDatabaseCollection(0, path)
	if err != nil {
		t.Fatalf("shouldSkipDatabaseCollection returned error: %v", err)
	}
	if skip {
		t.Fatal("skip = true, want false for zero schedule")
	}
}

func TestShouldSkipDatabaseCollectionMissingState(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing-state.json")
	skip, err := shouldSkipDatabaseCollection(24*time.Hour, path)
	if err != nil {
		t.Fatalf("shouldSkipDatabaseCollection returned error: %v", err)
	}
	if skip {
		t.Fatal("skip = true, want false when state file is missing")
	}
}

func TestRunConfiguredBrowserCrawlsCanSkipBySchedule(t *testing.T) {
	var requests int32
	pageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>Example</title><script src="/app.js"></script></head><body></body></html>`))
	}))
	defer pageServer.Close()

	root := t.TempDir()
	queueDir := filepath.Join(root, "queue")
	stateDir := filepath.Join(root, "state")
	appRoot := filepath.Join(root, "site")
	if err := os.MkdirAll(appRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	pendingDir := filepath.Join(queueDir, "pending")
	if err := os.MkdirAll(pendingDir, 0o700); err != nil {
		t.Fatalf("MkdirAll pending returned error: %v", err)
	}

	config := agent.ServerConfig{
		Runtime: agent.ServerRuntimeConfig{
			QueueDir: queueDir,
			StateDir: stateDir,
		},
		Identity: agent.ServerIdentityConfig{
			Region: "eu",
		},
		Sites: []agent.ServerSiteConfig{
			{
				Slug:    "example-com",
				App:     "example-com",
				Service: "frontend",
				Root:    appRoot,
				BrowserCrawl: agent.ServerBrowserCrawlConfig{
					Enabled:  true,
					Rendered: false,
					MaxPages: 1,
					Timeout:  "2s",
					Schedule: "1h",
					URLs:     []string{pageServer.URL},
				},
			},
		},
	}
	runtime := agent.NewRuntime(agent.Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   queueDir,
		Identity: &agent.Identity{
			HubURL:      "http://127.0.0.1:8787",
			QueueDir:    queueDir,
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
	})
	ctx := context.Background()
	statePath := browserStatePath(config, config.Sites[0])
	if err := touchCollectionState(statePath, time.Now().UTC()); err != nil {
		t.Fatalf("touchCollectionState returned error: %v", err)
	}

	skipResult, err := runConfiguredBrowserCrawls(ctx, runtime, config, false)
	if err != nil {
		t.Fatalf("runConfiguredBrowserCrawls returned error: %v", err)
	}
	if len(skipResult.Sites) != 1 || !skipResult.Sites[0].Skipped {
		t.Fatalf("skip result = %#v, want skipped site", skipResult)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("requests = %d, want 0 for scheduled skip", got)
	}

	config.Sites[0].BrowserCrawl.Schedule = "0s"
	runResult, err := runConfiguredBrowserCrawls(ctx, runtime, config, false)
	if err != nil {
		t.Fatalf("runConfiguredBrowserCrawls returned error: %v", err)
	}
	if runResult.Pages != 1 || runResult.Queued == 0 {
		t.Fatalf("run result = %#v, want one crawled page with queued events", runResult)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("requests = %d, want 1 after schedule disabled", got)
	}
	entries, err := os.ReadDir(pendingDir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("pending files=%d, want browser batch", len(entries))
	}
}

func TestAgentStartOnceSendsOneRequestForOneQueuedChange(t *testing.T) {
	var requests int32
	var mu sync.Mutex
	var batchIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		var envelope wire.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		if envelope.Schema != wire.EnvelopeSchema || envelope.NodeID != "agt_web_01" {
			t.Fatalf("envelope = %#v, want encrypted wire envelope for agt_web_01", envelope)
		}
		mu.Lock()
		batchIDs = append(batchIDs, envelope.NodeID)
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
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublic, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	runtime := agent.NewRuntime(agent.Config{ConfigPath: configPath, QueueDir: queueDir})
	if _, err := runtime.Install(context.Background(), agent.Identity{
		HubURL:       server.URL,
		HubProtocol:  "aegrail-wire-v1",
		HubPublicKey: hubPublic,
		NodeSecret:   nodeSecret,
		QueueDir:     queueDir,
		Org:          "smoke",
		Project:      "watcher",
		Environment:  "production",
		App:          "main-web",
		Service:      "frontend",
		Host:         "web-01",
		AgentID:      "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}

	runCLI(t, "agent", "start", "--once", "--config", configPath, "--queue-dir", queueDir, "--root", appRoot, "--profile", "wordpress")
	if err := os.WriteFile(filepath.Join(uploadsDir, "avatar.php"), []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	runCLI(t, "agent", "start", "--once", "--config", configPath, "--queue-dir", queueDir, "--root", appRoot, "--profile", "wordpress")

	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("requests = %d, want 1; batch ids: %v", got, batchIDs)
	}
}

func runCLI(t *testing.T, args ...string) {
	t.Helper()
	_ = runCLICapture(t, args...)
}

func readQueuedBatches(t *testing.T, dir string) []agent.QueuedBatch {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	batches := make([]agent.QueuedBatch, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}
		var batch agent.QueuedBatch
		if err := json.Unmarshal(content, &batch); err != nil {
			t.Fatalf("Unmarshal returned error: %v", err)
		}
		batches = append(batches, batch)
	}
	return batches
}

func queuedBatchBySource(t *testing.T, batches []agent.QueuedBatch, source string) agent.QueuedBatch {
	t.Helper()
	for _, batch := range batches {
		if batch.Source == source {
			return batch
		}
	}
	t.Fatalf("missing queued batch with source %s in %#v", source, batches)
	return agent.QueuedBatch{}
}

func runCLICapture(t *testing.T, args ...string) string {
	t.Helper()
	app := New(domain.AppMeta{Name: "Aegrail Agent", Binary: "agent", Version: "test"})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr
	if err := app.Run(args); err != nil {
		t.Fatalf("Run(%v) returned error: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}
