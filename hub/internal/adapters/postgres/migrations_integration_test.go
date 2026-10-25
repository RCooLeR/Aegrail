package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestMigratorUpUsesPostgresLeaseLock(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_POSTGRES_URL to run PostgreSQL migration integration tests")
	}

	ctx := context.Background()
	admin, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open admin database: %v", err)
	}
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("ping admin database: %v", err)
	}

	schema := "aegrail_migrator_test_" + randomMigrationHex(t, 8)
	schemaIdentifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schemaIdentifier); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schemaIdentifier+" CASCADE")
	}()

	migrationsDir := t.TempDir()
	migration := []byte("-- +goose Up\nCREATE TABLE migration_applied (id integer PRIMARY KEY);\n" +
		"-- +goose Down\nDROP TABLE migration_applied;\n")
	if err := os.WriteFile(filepath.Join(migrationsDir, "00001_create_migration_applied.sql"), migration, 0o600); err != nil {
		t.Fatalf("write test migration: %v", err)
	}

	migrator := NewMigrator(withMigrationSearchPath(t, databaseURL, schema), migrationsDir)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("reapply current migrations: %v", err)
	}
	if err := migrator.EnsureCurrent(ctx); err != nil {
		t.Fatalf("ensure current migrations: %v", err)
	}

	for _, table := range []string{"migration_applied", "goose_db_version", "goose_lock"} {
		var exists bool
		if err := admin.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.tables
				WHERE table_schema = $1 AND table_name = $2
			)
		`, schema, table).Scan(&exists); err != nil {
			t.Fatalf("check %s table: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %s.%s does not exist", schema, table)
		}
	}
}

func TestProjectMigrationsPostgres18Integration(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_POSTGRES_URL to run PostgreSQL migration integration tests")
	}

	ctx := context.Background()
	admin, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open admin database: %v", err)
	}
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("ping admin database: %v", err)
	}

	schema := "aegrail_project_migrations_test_" + randomMigrationHex(t, 8)
	schemaIdentifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schemaIdentifier); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schemaIdentifier+" CASCADE")
	}()

	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	migrator := NewMigrator(withMigrationSearchPath(t, databaseURL, schema), migrationsDir)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("apply project migrations: %v", err)
	}
	if err := migrator.EnsureCurrent(ctx); err != nil {
		t.Fatalf("ensure project migrations current: %v", err)
	}

	var serverVersion int
	if err := admin.QueryRowContext(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&serverVersion); err != nil {
		t.Fatalf("read PostgreSQL version: %v", err)
	}
	if serverVersion < 180000 || serverVersion >= 190000 {
		t.Fatalf("PostgreSQL server version = %d, want 18.x", serverVersion)
	}
	var vectorVersion string
	if err := admin.QueryRowContext(ctx, "SELECT extversion FROM pg_extension WHERE extname = 'vector'").Scan(&vectorVersion); err != nil {
		t.Fatalf("read pgvector version: %v", err)
	}
	if vectorVersion != "0.8.7" {
		t.Fatalf("pgvector version = %q, want 0.8.7", vectorVersion)
	}
	var uuidV7Defaults int
	if err := admin.QueryRowContext(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = $1 AND column_default LIKE '%uuidv7()%'
	`, schema).Scan(&uuidV7Defaults); err != nil {
		t.Fatalf("count UUIDv7 defaults: %v", err)
	}
	if uuidV7Defaults == 0 {
		t.Fatal("project migrations did not install PostgreSQL 18 UUIDv7 defaults")
	}
}

func TestProjectMigrationsUpgradePgvectorFromPreviouslySupportedVersion(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_PGVECTOR_UPGRADE_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_PGVECTOR_UPGRADE_URL to run the pgvector upgrade integration test")
	}

	ctx := context.Background()
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open pgvector upgrade database: %v", err)
	}
	defer database.Close()
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("ping pgvector upgrade database: %v", err)
	}

	var vectorVersion string
	if err := database.QueryRowContext(ctx, "SELECT extversion FROM pg_extension WHERE extname = 'vector'").Scan(&vectorVersion); err != nil {
		t.Fatalf("read pgvector fixture version: %v", err)
	}
	if vectorVersion != "0.8.2" {
		t.Fatalf("pgvector fixture version = %q, want 0.8.2", vectorVersion)
	}

	migrationsDir := filepath.Join("..", "..", "..", "migrations")
	migrator := NewMigrator(databaseURL, migrationsDir)
	if err := migrator.Up(ctx); err != nil {
		t.Fatalf("migrate pgvector 0.8.2 fixture: %v", err)
	}

	if err := database.QueryRowContext(ctx, "SELECT extversion FROM pg_extension WHERE extname = 'vector'").Scan(&vectorVersion); err != nil {
		t.Fatalf("read upgraded pgvector version: %v", err)
	}
	if vectorVersion != "0.8.7" {
		t.Fatalf("pgvector version = %q, want 0.8.7", vectorVersion)
	}
}

func withMigrationSearchPath(t *testing.T, databaseURL string, schema string) string {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err == nil && parsed.Scheme != "" {
		query := parsed.Query()
		query.Set("search_path", schema+",public")
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return databaseURL + " search_path=" + schema + ",public"
}

func randomMigrationHex(t *testing.T, byteCount int) string {
	t.Helper()
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(buffer)
}
