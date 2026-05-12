package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadServerConfigExample(t *testing.T) {
	config, err := LoadServerConfig(filepath.Join("..", "..", "configs", "agent.multi-site.yaml.example"))
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}
	if config.Schema != ServerConfigSchema {
		t.Fatalf("schema = %q, want %q", config.Schema, ServerConfigSchema)
	}
	if len(config.Sites) != 3 {
		t.Fatalf("sites = %d, want 3", len(config.Sites))
	}
	if config.Sites[0].Slug != "example-com" || config.Sites[1].Kind != "prestashop" {
		t.Fatalf("unexpected sites: %+v", config.Sites)
	}
}

func TestValidateServerConfigRejectsLiteralDSN(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub: ServerHubConfig{
			URL: "http://127.0.0.1:8787",
		},
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

func TestRunServerConfigOnceUsesPerSiteContextAndState(t *testing.T) {
	root := t.TempDir()
	siteOne := filepath.Join(root, "example")
	siteTwo := filepath.Join(root, "example2")
	for _, siteRoot := range []string{siteOne, siteTwo} {
		if err := os.MkdirAll(filepath.Join(siteRoot, "wp-content", "uploads"), 0o700); err != nil {
			t.Fatalf("MkdirAll returned error: %v", err)
		}
	}
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub: ServerHubConfig{
			URL: "http://127.0.0.1:8787",
		},
		Identity: ServerIdentityConfig{
			Org:         "acme",
			Project:     "hosted-sites",
			Environment: "production",
			Host:        "web-01",
			AgentID:     "agt_web_01",
			Region:      "eu-central",
		},
		Runtime: ServerRuntimeConfig{
			QueueDir: filepath.Join(root, "queue"),
			StateDir: filepath.Join(root, "state"),
			Interval: "30s",
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
	result, err := runtime.RunServerConfigOnce(context.Background(), config, "", 0)
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
	result, err = runtime.RunServerConfigOnce(context.Background(), config, "", 0)
	if err != nil {
		t.Fatalf("RunServerConfigOnce returned error after change: %v", err)
	}
	if result.Queued != 1 || result.Pending != 1 {
		t.Fatalf("second result = %+v, want one queued pending event", result)
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
	if batch.App != "example2-com" || batch.Service != "frontend" {
		t.Fatalf("batch context = app %q service %q, want example2-com/frontend", batch.App, batch.Service)
	}
	if batch.Labels["site_slug"] != "example2-com" || batch.Labels["domain"] != "example2.com" {
		t.Fatalf("batch labels = %#v, want site labels", batch.Labels)
	}
	if len(batch.Events) != 1 || batch.Events[0].Labels["site_slug"] != "example2-com" {
		t.Fatalf("event labels = %#v, want site labels", batch.Events)
	}
	if !fileExists(filepath.Join(root, "state", "sites", "example-com", "file-watch.json")) {
		t.Fatalf("missing state for first site")
	}
	if !fileExists(filepath.Join(root, "state", "sites", "example2-com", "file-watch.json")) {
		t.Fatalf("missing state for second site")
	}
}

func TestBuildServerConfigCoverageReportsClassifiesCoverage(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    ServerHubConfig{URL: "http://127.0.0.1:8787"},
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
	if report.Coverage.Databases.Profiles[0] != "wordpress" || !report.Coverage.Databases.AllDSNEnvConfigured {
		t.Fatalf("database coverage = %#v", report.Coverage.Databases)
	}
}

func TestQueueServerConfigCoverageDedupesUnchangedConfig(t *testing.T) {
	root := t.TempDir()
	config := NormalizeServerConfig(ServerConfig{
		Schema: ServerConfigSchema,
		Hub:    ServerHubConfig{URL: "http://127.0.0.1:8787"},
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
