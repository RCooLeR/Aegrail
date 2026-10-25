package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestHubMaintenanceRepositoryKeepsOpenFindingEvidenceIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubMaintenanceIntegrationPool(t, ctx)
	defer cleanup()
	repo := NewHubMaintenanceRepository(pool)
	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	old := now.Add(-200 * 24 * time.Hour)
	protectedEventID := "11111111-1111-1111-1111-111111111111"
	prunedEventID := "22222222-2222-2222-2222-222222222222"

	if _, err := pool.Exec(ctx, `
		INSERT INTO hub_ingest_batches (id, created_at)
		VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', $1),
			('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', $1)
	`, old); err != nil {
		t.Fatalf("insert batches: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO hub_ingest_events (id, batch_id, created_at)
		VALUES ($1, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', $3),
			($2, 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', $3)
	`, protectedEventID, prunedEventID, old); err != nil {
		t.Fatalf("insert events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO hub_findings (id, status, event_ids, updated_at)
		VALUES ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'open', ARRAY[$1::text], $2)
	`, protectedEventID, old); err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	result, err := repo.PruneHubData(ctx, domain.HubMaintenancePruneOptions{
		Now:            now,
		EventRetention: 180 * 24 * time.Hour,
		BatchSize:      10,
	})
	if err != nil {
		t.Fatalf("PruneHubData returned error: %v", err)
	}
	if result.IngestEventsDeleted != 1 {
		t.Fatalf("IngestEventsDeleted = %d, want 1", result.IngestEventsDeleted)
	}

	var protectedCount, prunedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_ingest_events WHERE id = $1`, protectedEventID).Scan(&protectedCount); err != nil {
		t.Fatalf("count protected event: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_ingest_events WHERE id = $1`, prunedEventID).Scan(&prunedCount); err != nil {
		t.Fatalf("count pruned event: %v", err)
	}
	if protectedCount != 1 || prunedCount != 0 {
		t.Fatalf("protected event count=%d pruned event count=%d, want 1 and 0", protectedCount, prunedCount)
	}
}

func TestHubMaintenanceRepositoryKeepsRecentlyCreatedResolvedFindingsIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubMaintenanceIntegrationPool(t, ctx)
	defer cleanup()
	repo := NewHubMaintenanceRepository(pool)
	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	old := now.Add(-40 * 24 * time.Hour)
	recent := now.Add(-24 * time.Hour)
	oldFindingID := "33333333-3333-3333-3333-333333333333"
	recentFindingID := "44444444-4444-4444-4444-444444444444"
	highFindingID := "55555555-5555-5555-5555-555555555555"

	if _, err := pool.Exec(ctx, `
		INSERT INTO hub_findings (id, status, severity, created_at, updated_at, last_event_at)
		VALUES ($1, 'resolved', 'medium', $4, $4, $4),
			($2, 'resolved', 'medium', $5, $4, $5),
			($3, 'resolved', 'high', $4, $4, $4)
	`, oldFindingID, recentFindingID, highFindingID, old, recent); err != nil {
		t.Fatalf("insert findings: %v", err)
	}

	result, err := repo.PruneHubData(ctx, domain.HubMaintenancePruneOptions{
		Now:                      now,
		ResolvedFindingRetention: 30 * 24 * time.Hour,
		BatchSize:                10,
	})
	if err != nil {
		t.Fatalf("PruneHubData returned error: %v", err)
	}
	if result.ResolvedFindingsDeleted != 1 {
		t.Fatalf("ResolvedFindingsDeleted = %d, want 1", result.ResolvedFindingsDeleted)
	}

	var oldCount, recentCount, highCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_findings WHERE id = $1`, oldFindingID).Scan(&oldCount); err != nil {
		t.Fatalf("count old finding: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_findings WHERE id = $1`, recentFindingID).Scan(&recentCount); err != nil {
		t.Fatalf("count recent finding: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hub_findings WHERE id = $1`, highFindingID).Scan(&highCount); err != nil {
		t.Fatalf("count high finding: %v", err)
	}
	if oldCount != 0 || recentCount != 1 || highCount != 1 {
		t.Fatalf("old finding count=%d recent finding count=%d high finding count=%d, want 0, 1, and 1", oldCount, recentCount, highCount)
	}
}

func newHubMaintenanceIntegrationPool(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_POSTGRES_URL to run PostgreSQL adapter integration tests")
	}
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	schema := "aegrail_maintenance_test_" + randomMaintenanceHexForTest(t, 8)
	schemaIdent := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schemaIdent); err != nil {
		adminPool.Close()
		t.Fatalf("create test schema: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("parse postgres url: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("connect test pool: %v", err)
	}
	if _, err := pool.Exec(ctx, hubMaintenanceIntegrationSchemaSQL); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("create maintenance test schema: %v", err)
	}
	return pool, func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
	}
}

func randomMaintenanceHexForTest(t *testing.T, bytesLen int) string {
	t.Helper()
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(buf)
}

const hubMaintenanceIntegrationSchemaSQL = `
CREATE TABLE hub_ingest_batches (
	id uuid PRIMARY KEY,
	created_at timestamptz NOT NULL
);

CREATE TABLE hub_ingest_events (
	id uuid PRIMARY KEY,
	batch_id uuid NOT NULL,
	created_at timestamptz NOT NULL
);

CREATE TABLE hub_findings (
	id uuid PRIMARY KEY,
	status text NOT NULL,
	severity text NOT NULL DEFAULT 'medium',
	event_ids text[] NOT NULL DEFAULT '{}',
	created_at timestamptz NOT NULL DEFAULT now(),
	last_event_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL
);

CREATE TABLE hub_maintenance_runs (
	kind text NOT NULL,
	started_at timestamptz NOT NULL,
	finished_at timestamptz NOT NULL,
	result jsonb NOT NULL
);
`
