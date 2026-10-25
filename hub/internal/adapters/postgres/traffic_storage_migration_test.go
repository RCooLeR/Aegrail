package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrafficStoragePerformanceMigrationContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "migrations", "00011_traffic_storage_performance.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read traffic storage migration: %v", err)
	}
	up, down, found := strings.Cut(string(content), "-- +goose Down")
	if !found {
		t.Fatal("traffic storage migration is missing goose Down marker")
	}

	upFragments := []string{
		"-- +goose NO TRANSACTION",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_ingest_events_traffic_backfill_idx",
		"ON hub_ingest_events (event_time DESC, created_at DESC, id DESC)",
		"WHERE event_type = 'log.access'",
		"DROP INDEX CONCURRENTLY IF EXISTS hub_access_requests_scope_path_time_idx",
	}
	for _, fragment := range upFragments {
		if !strings.Contains(up, fragment) {
			t.Errorf("migration Up is missing %q", fragment)
		}
	}

	downFragments := []string{
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_access_requests_scope_path_time_idx",
		"ON hub_access_requests (organization_id, project_id, environment_id, md5(path), event_time DESC)",
		"WHERE path <> ''",
		"DROP INDEX CONCURRENTLY IF EXISTS hub_ingest_events_traffic_backfill_idx",
	}
	for _, fragment := range downFragments {
		if !strings.Contains(down, fragment) {
			t.Errorf("migration Down is missing %q", fragment)
		}
	}

	backfillSource, err := os.ReadFile("traffic_backfill.go")
	if err != nil {
		t.Fatalf("read traffic backfill source: %v", err)
	}
	backfillQuery := string(backfillSource)
	for _, fragment := range []string{
		"e.event_type = 'log.access'",
		"ORDER BY e.event_time DESC, e.created_at DESC, e.id DESC",
	} {
		if !strings.Contains(backfillQuery, fragment) {
			t.Errorf("backfill query no longer matches the partial index contract: missing %q", fragment)
		}
	}

	trafficSource, err := os.ReadFile("traffic.go")
	if err != nil {
		t.Fatalf("read traffic query source: %v", err)
	}
	if strings.Contains(string(trafficSource), "md5(path)") {
		t.Error("traffic queries use md5(path); dropping the path-hash index is no longer safe")
	}
}
