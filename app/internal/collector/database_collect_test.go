package collector

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeDatabaseDSNConvertsMySQLURL(t *testing.T) {
	dsn, err := normalizeDatabaseDSN("mysql", "mysql://user:pass@127.0.0.1:3306/site_db?charset=utf8mb4")
	if err != nil {
		t.Fatalf("normalizeDatabaseDSN returned error: %v", err)
	}
	if !strings.Contains(dsn, "user:pass@tcp(127.0.0.1:3306)/site_db") {
		t.Fatalf("dsn = %q, want formatted tcp DSN", dsn)
	}
	if !strings.Contains(dsn, "parseTime=true") || !strings.Contains(dsn, "charset=utf8mb4") {
		t.Fatalf("dsn = %q, want query params preserved", dsn)
	}
}

func TestCollectDatabaseSnapshotUnsupportedEngineReturnsWarning(t *testing.T) {
	runtime := NewRuntime(Config{Name: "database"})
	result, err := runtime.CollectDatabaseSnapshot(context.Background(), DatabaseCollectInput{
		Name:    "main",
		Engine:  "postgres",
		Profile: "wordpress",
		DSN:     "postgres://example",
	})
	if err != nil {
		t.Fatalf("CollectDatabaseSnapshot returned error: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("warnings = %#v, want unsupported engine warning", result.Warnings)
	}
	if len(result.Checks) != 0 {
		t.Fatalf("checks = %d, want no checks for unsupported engine", len(result.Checks))
	}
}

func TestBuildDatabaseSnapshotEventsRedactsDigestValues(t *testing.T) {
	result := DatabaseCollectResult{
		Name:    "main",
		Engine:  "mysql",
		Profile: "wordpress",
		Checks: []DatabaseCheckResult{
			{
				Name:        "wordpress.active_plugins.digest",
				Status:      "ok",
				Metric:      "active_plugins",
				Table:       "wp_options",
				OptionName:  "active_plugins",
				ValueSHA256: "abc123",
				ValueBytes:  42,
			},
		},
	}
	events := BuildDatabaseSnapshotEvents(result, map[string]string{"site_slug": "example-com"})
	if len(events) != 2 {
		t.Fatalf("events = %d, want completed and check events", len(events))
	}
	check := events[1]
	if check.Type != "db.snapshot.check" || check.Payload["value_sha256"] != "abc123" {
		t.Fatalf("check event = %#v, want digest payload", check)
	}
	if _, ok := check.Payload["value"]; ok {
		t.Fatalf("payload leaked raw value: %#v", check.Payload)
	}
	if check.Labels["collector"] != "database" || check.Labels["site_slug"] != "example-com" {
		t.Fatalf("labels = %#v, want database and site context", check.Labels)
	}
}
