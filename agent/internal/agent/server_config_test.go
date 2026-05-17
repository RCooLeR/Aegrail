package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rcooler/aegrail/agent/internal/wire"
)

func TestLoadServerConfigExample(t *testing.T) {
	config, err := LoadServerConfig(filepath.Join("..", "..", "configs", "agent.multi-site.example.yaml"))
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}
	if config.Schema != ServerConfigSchema {
		t.Fatalf("schema = %q, want %q", config.Schema, ServerConfigSchema)
	}
	if len(config.Sites) != 6 {
		t.Fatalf("sites = %d, want 6", len(config.Sites))
	}
	if config.Sites[0].Slug != "example-com" || config.Sites[1].Kind != "prestashop" {
		t.Fatalf("unexpected sites: %+v", config.Sites)
	}
	if config.Sites[4].Kind != "yii2-rbac" || config.Sites[4].Files.Profiles[0] != "yii2-rbac" {
		t.Fatalf("yii2 rbac site = %+v, want yii2-rbac profile", config.Sites[4])
	}
	if config.Sites[5].Kind != "laravel" || config.Sites[5].Files.Profiles[0] != "laravel" {
		t.Fatalf("laravel site = %+v, want laravel profile", config.Sites[5])
	}
}

func testWireHubConfig(t *testing.T, url string) ServerHubConfig {
	t.Helper()
	nodeSecret, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, hubPublicKey, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	return ServerHubConfig{
		URL:          url,
		Protocol:     "aegrail-wire-v1",
		HubPublicKey: hubPublicKey,
		NodeSecret:   nodeSecret,
	}
}

func TestValidateServerConfigRejectsLiteralDSN(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "customer-site",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
			Interval: "30s",
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "example-com",
				Kind: "wordpress",
				Root: filepath.Join(root, "site"),
				Databases: []ServerDatabaseConfig{
					{Engine: "mysql", DSN: "mysql://user:pass@example/db", Profile: "wordpress"},
				},
			},
		},
	})
	err := ValidateServerConfig(config)
	if err == nil {
		t.Fatalf("ValidateServerConfig returned nil, want error")
	}
	if !strings.Contains(err.Error(), "dsn must not contain literal credentials") {
		t.Fatalf("error = %v, want literal DSN issue", err)
	}
}

func TestValidateServerConfigAcceptsWooCommerceKind(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "storefront",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
			Interval: "30s",
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "store",
				Kind: "woocommerce",
				Root: filepath.Join(root, "site"),
			},
		},
	})
	if err := ValidateServerConfig(config); err != nil {
		t.Fatalf("ValidateServerConfig returned error: %v", err)
	}
	if got := config.Sites[0].Files.Profiles; len(got) != 1 || got[0] != "wordpress" {
		t.Fatalf("files profiles = %#v, want wordpress profile", got)
	}
}

func TestNormalizeServerConfigExpandsPathEnvironmentVariables(t *testing.T) {
	t.Setenv("AEGRAIL_TEST_ROOT", filepath.Join(t.TempDir(), "site"))
	t.Setenv("AEGRAIL_TEST_STATE", filepath.Join(t.TempDir(), "state"))
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: "${AEGRAIL_TEST_STATE}/queue",
			StateDir: "${AEGRAIL_TEST_STATE}/state",
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "example-com",
				Kind: "wordpress",
				Root: "${AEGRAIL_TEST_ROOT}",
				Files: ServerFileWatchConfig{
					ExtraPaths: []string{"${AEGRAIL_TEST_ROOT}/wp-content"},
					Exclude:    []string{"${AEGRAIL_TEST_ROOT}/wp-content/cache"},
				},
				Logs: []ServerLogConfig{{Path: "${AEGRAIL_TEST_ROOT}/debug.log", Kind: "php_error"}},
			},
		},
	})

	if strings.Contains(config.Sites[0].Root, "AEGRAIL_TEST_ROOT") {
		t.Fatalf("root was not expanded: %q", config.Sites[0].Root)
	}
	if !filepath.IsAbs(config.Runtime.QueueDir) || !filepath.IsAbs(config.Runtime.StateDir) {
		t.Fatalf("runtime paths were not expanded: %#v", config.Runtime)
	}
	if !strings.HasPrefix(config.Sites[0].Files.ExtraPaths[0], config.Sites[0].Root) {
		t.Fatalf("extra path = %q, want under root %q", config.Sites[0].Files.ExtraPaths[0], config.Sites[0].Root)
	}
	if !strings.HasPrefix(config.Sites[0].Logs[0].Path, config.Sites[0].Root) {
		t.Fatalf("log path = %q, want under root %q", config.Sites[0].Logs[0].Path, config.Sites[0].Root)
	}
}

func TestRunServerConfigOnceUsesPerSiteContextAndState(t *testing.T) {
	root := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	siteOne := filepath.Join(root, "example")
	siteTwo := filepath.Join(root, "example2")
	for _, siteRoot := range []string{siteOne, siteTwo} {
		if err := os.MkdirAll(filepath.Join(siteRoot, "wp-content", "uploads"), 0o700); err != nil {
			t.Fatalf("MkdirAll returned error: %v", err)
		}
	}
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, server.URL),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
			Region:      "eu-central",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir:      filepath.Join(root, "queue"),
			StateDir:      filepath.Join(root, "state"),
			Interval:      "30s",
			SentRetention: "1h",
		},
		Sites: []ServerSiteConfig{
			{
				Slug:    "example-com",
				Domain:  "example.com",
				Kind:    "wordpress",
				App:     "example-com",
				Service: "frontend",
				Root:    siteOne,
				Files: ServerFileWatchConfig{
					Profiles: []string{"wordpress"},
				},
			},
			{
				Slug:    "example2-com",
				Domain:  "example2.com",
				Kind:    "wordpress",
				App:     "example2-com",
				Service: "frontend",
				Root:    siteTwo,
				Files: ServerFileWatchConfig{
					Profiles: []string{"wordpress"},
				},
			},
		},
	})
	runtime := NewRuntime(Config{})
	result, err := runtime.RunServerConfigOnce(context.Background(), config, 0, false)
	if err != nil {
		t.Fatalf("RunServerConfigOnce returned error: %v", err)
	}
	if result.Queued != 0 || len(result.Sites) != 2 {
		t.Fatalf("first result = %+v, want two baselines and no queued events", result)
	}

	shellPath := filepath.Join(siteTwo, "wp-content", "uploads", "avatar.php")
	if err := os.WriteFile(shellPath, []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	result, err = runtime.RunServerConfigOnce(context.Background(), config, 0, false)
	if err != nil {
		t.Fatalf("RunServerConfigOnce returned error after change: %v", err)
	}
	if result.Queued != 2 || result.Sent != 2 || result.Pending != 0 {
		t.Fatalf("second result = %+v, want file change plus clean scan heartbeat sent", result)
	}
	files, err := queueFiles(filepath.Join(root, "queue", "sent"))
	if err != nil {
		t.Fatalf("queueFiles returned error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("sent files = %d, want 2", len(files))
	}
	var batch QueuedBatch
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}
		var candidate QueuedBatch
		if err := json.Unmarshal(content, &candidate); err != nil {
			t.Fatalf("Unmarshal returned error: %v", err)
		}
		if len(candidate.Events) == 1 && candidate.Events[0].Type == "file.created" {
			batch = candidate
			break
		}
	}
	if len(batch.Events) != 1 {
		t.Fatalf("missing file.created batch in sent files")
	}
	if batch.App != "example2-com" || batch.Service != "frontend" {
		t.Fatalf("batch context = app %q service %q, want example2-com/frontend", batch.App, batch.Service)
	}
	if batch.Labels["site_slug"] != "example2-com" || batch.Labels["domain"] != "example2.com" {
		t.Fatalf("batch labels = %#v, want site labels", batch.Labels)
	}
	if len(batch.Events) != 1 || batch.Events[0].Labels["site_slug"] != "example2-com" {
		t.Fatalf("event labels = %#v, want site labels", batch.Events)
	}
	result, err = runtime.RunServerConfigOnce(context.Background(), config, 0, true)
	if err != nil {
		t.Fatalf("RunServerConfigOnce returned error in bootstrap: %v", err)
	}
	if result.Queued != 0 {
		t.Fatalf("bootstrap result = %+v, want zero queued events", result)
	}
	if !fileExists(filepath.Join(root, "state", "sites", "example-com", "file-watch.json")) {
		t.Fatalf("missing state for first site")
	}
	if !fileExists(filepath.Join(root, "state", "sites", "example2-com", "file-watch.json")) {
		t.Fatalf("missing state for second site")
	}
}

func TestRunServerConfigOnceBootstrapDoesNotSendPendingQueue(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	root := t.TempDir()
	siteRoot := filepath.Join(root, "site")
	uploadsDir := filepath.Join(siteRoot, "wp-content", "uploads")
	if err := os.MkdirAll(uploadsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, server.URL),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
			Interval: "30s",
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "example-com",
				Kind: "wordpress",
				Root: siteRoot,
				Files: ServerFileWatchConfig{
					Profiles: []string{"wordpress"},
				},
			},
		},
	})
	runtime := NewRuntime(Config{})
	if _, err := runtime.RunServerConfigOnce(context.Background(), config, 0, false); err != nil {
		t.Fatalf("initial RunServerConfigOnce returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(uploadsDir, "avatar.php"), []byte("<?php echo 'x';"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	result, err := runtime.RunServerConfigOnce(context.Background(), config, 0, false)
	if err != nil {
		t.Fatalf("change RunServerConfigOnce returned error: %v", err)
	}
	if result.Pending != 1 || result.Failed != 1 {
		t.Fatalf("result = %+v, want one failed pending event before bootstrap", result)
	}
	requestsBeforeBootstrap := atomic.LoadInt32(&requests)

	result, err = runtime.RunServerConfigOnce(context.Background(), config, 10, true)
	if err != nil {
		t.Fatalf("bootstrap RunServerConfigOnce returned error: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != requestsBeforeBootstrap {
		t.Fatalf("bootstrap sent %d new request(s), want 0", got-requestsBeforeBootstrap)
	}
	if result.Pending != 1 || result.Queued != 0 {
		t.Fatalf("bootstrap result = %+v, want pending queue preserved and no new events", result)
	}
}

func TestBuildServerConfigCoverageReportsClassifiesCoverage(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "example-com",
				Kind: "wordpress",
				Root: filepath.Join(root, "site"),
				Files: ServerFileWatchConfig{
					Profiles: []string{"wordpress"},
				},
				Logs: []ServerLogConfig{{Path: filepath.Join(root, "access.log"), Kind: "nginx_access"}},
				Databases: []ServerDatabaseConfig{{
					Name:    "main",
					Engine:  "mysql",
					DSNEnv:  "AEGRAIL_TEST_DSN",
					Profile: "wordpress",
				}},
				BrowserCrawl: ServerBrowserCrawlConfig{
					Enabled:  true,
					Rendered: true,
					URLs:     []string{"https://example.com/"},
				},
			},
		},
	})
	reports := BuildServerConfigCoverageReports(config, mustTime("2026-05-12T15:00:00Z"))
	if len(reports) != 1 {
		t.Fatalf("reports = %#v, want one report", reports)
	}
	report := reports[0]
	if report.Coverage.Level != "complete" || report.Signature == "" {
		t.Fatalf("coverage = %#v, want complete with signature", report.Coverage)
	}
	if !report.Coverage.Enabled {
		t.Fatalf("coverage enabled = false, want true")
	}
	if report.Coverage.Databases.Profiles[0] != "wordpress" || !report.Coverage.Databases.AllDSNEnvConfigured {
		t.Fatalf("database coverage = %#v", report.Coverage.Databases)
	}
}

func TestServerConfigAllowsManagedSiteWithoutFilesOrCoverage(t *testing.T) {
	root := t.TempDir()
	disabled := false
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "pantheon",
			AgentID:     "agt_pantheon",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
		},
		Sites: []ServerSiteConfig{
			{
				Slug:     "managed-site",
				Kind:     "wordpress",
				Files:    ServerFileWatchConfig{Enabled: &disabled},
				Coverage: ServerCoverageConfig{Enabled: &disabled},
				Databases: []ServerDatabaseConfig{{
					Name:    "main",
					Engine:  "mysql",
					DSNEnv:  "AEGRAIL_TEST_DSN",
					Profile: "wordpress",
				}},
				BrowserCrawl: ServerBrowserCrawlConfig{
					Enabled: true,
					URLs:    []string{"https://example.com/"},
				},
			},
		},
	})
	if err := ValidateServerConfig(config); err != nil {
		t.Fatalf("ValidateServerConfig returned error: %v", err)
	}
	if len(config.Sites[0].Files.Profiles) != 0 {
		t.Fatalf("file profiles = %#v, want no auto profile when files are disabled", config.Sites[0].Files.Profiles)
	}
	reports := BuildServerConfigCoverageReports(config, mustTime("2026-05-12T15:00:00Z"))
	if len(reports) != 1 {
		t.Fatalf("reports = %#v, want one report", reports)
	}
	report := reports[0]
	if report.Coverage.Enabled || report.Coverage.Level != "disabled" || report.Coverage.Files.Enabled {
		t.Fatalf("coverage = %#v, want disabled config and files", report.Coverage)
	}
}

func TestNormalizeServerConfigAutoSelectsMauticProfiles(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "marketing",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "mautic",
				Kind: "mautic",
				Root: filepath.Join(root, "site"),
				Databases: []ServerDatabaseConfig{{
					Name:    "main",
					Engine:  "mysql",
					DSNEnv:  "AEGRAIL_TEST_DSN",
					Profile: "mautic",
				}},
			},
		},
	})
	if err := ValidateServerConfig(config); err != nil {
		t.Fatalf("ValidateServerConfig returned error: %v", err)
	}
	if got := strings.Join(config.Sites[0].Files.Profiles, ","); got != "mautic" {
		t.Fatalf("file profiles = %q, want mautic", got)
	}
}

func TestServerConfigCoverageReportsSafeFileIgnorePaths(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "customer-site",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "example-com",
				Kind: "prestashop",
				Root: filepath.Join(root, "site"),
				Files: ServerFileWatchConfig{
					Profiles: []string{"prestashop"},
					Exclude: []string{
						filepath.Join(root, "site", "modules", "custom", "logs"),
						filepath.Join(root, "site"),
						filepath.Join(root, "outside", "private-cache"),
					},
				},
			},
		},
	})

	reports := BuildServerConfigCoverageReports(config, mustTime("2026-05-12T15:00:00Z"))
	if len(reports) != 1 {
		t.Fatalf("reports = %#v, want one report", reports)
	}
	ignores := reports[0].Coverage.Files.IgnoredPaths
	if len(ignores) != 3 {
		t.Fatalf("ignored paths = %#v, want three entries", ignores)
	}
	if ignores[0].Path != "modules/custom/logs" || ignores[0].Scope != "site_relative" || ignores[0].Risk != "low" {
		t.Fatalf("first ignore = %#v, want safe relative low-risk logs path", ignores[0])
	}
	if ignores[1].Path != "<site root>" || ignores[1].Scope != "site_root" || ignores[1].Risk != "high" {
		t.Fatalf("second ignore = %#v, want high-risk site root marker", ignores[1])
	}
	if ignores[2].Path != "[outside site root]/private-cache" || ignores[2].Scope != "outside_site_root" || ignores[2].Risk != "high" {
		t.Fatalf("third ignore = %#v, want redacted outside-root entry", ignores[2])
	}
}

func TestQueueServerConfigCoverageDedupesUnchangedConfig(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
		},
		Sites: []ServerSiteConfig{
			{
				Slug:    "example-com",
				Domain:  "example.com",
				Kind:    "wordpress",
				App:     "example-com",
				Service: "frontend",
				Root:    filepath.Join(root, "site"),
				Files: ServerFileWatchConfig{
					Profiles: []string{"wordpress"},
				},
			},
		},
	})
	runtime := NewRuntime(Config{})
	result, err := runtime.QueueServerConfigCoverage(context.Background(), config)
	if err != nil {
		t.Fatalf("QueueServerConfigCoverage returned error: %v", err)
	}
	if result.Sites != 1 || result.Queued != 1 {
		t.Fatalf("first result = %+v, want one queued coverage update", result)
	}
	result, err = runtime.QueueServerConfigCoverage(context.Background(), config)
	if err != nil {
		t.Fatalf("second QueueServerConfigCoverage returned error: %v", err)
	}
	if result.Queued != 0 {
		t.Fatalf("second result = %+v, want unchanged config deduped", result)
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
	if batch.Source != "agent.coverage" || batch.App != "example-com" || len(batch.Events) != 1 {
		t.Fatalf("coverage batch = %#v", batch)
	}
	if batch.Events[0].Type != "agent.config.coverage" || batch.Events[0].Labels["coverage_level"] != "partial" {
		t.Fatalf("coverage event = %#v", batch.Events[0])
	}
}

func TestQueueServerConfigCoverageRequeuesAfterHeartbeat(t *testing.T) {
	root := t.TempDir()
	now := mustTime("2026-05-12T15:00:00Z")
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    testWireHubConfig(t, "http://127.0.0.1:8787"),
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
		},
		Sites: []ServerSiteConfig{
			{
				Slug: "example-com",
				Kind: "wordpress",
				Root: filepath.Join(root, "site"),
				Files: ServerFileWatchConfig{
					Profiles: []string{"wordpress"},
				},
			},
		},
	})
	runtime := NewRuntime(Config{})
	runtime.now = func() time.Time { return now }
	result, err := runtime.QueueServerConfigCoverage(context.Background(), config)
	if err != nil {
		t.Fatalf("QueueServerConfigCoverage returned error: %v", err)
	}
	if result.Queued != 1 {
		t.Fatalf("first result = %+v, want one queued coverage update", result)
	}
	result, err = runtime.QueueServerConfigCoverage(context.Background(), config)
	if err != nil {
		t.Fatalf("second QueueServerConfigCoverage returned error: %v", err)
	}
	if result.Queued != 0 {
		t.Fatalf("second result = %+v, want unchanged config deduped inside heartbeat window", result)
	}
	now = now.Add(DefaultServerConfigCoverageHeartbeatInterval + time.Second)
	result, err = runtime.QueueServerConfigCoverage(context.Background(), config)
	if err != nil {
		t.Fatalf("third QueueServerConfigCoverage returned error: %v", err)
	}
	if result.Queued != 1 {
		t.Fatalf("third result = %+v, want heartbeat coverage update", result)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}
