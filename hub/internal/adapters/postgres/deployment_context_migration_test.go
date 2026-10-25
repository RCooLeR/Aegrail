package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeploymentContextOnlyMigrationRiskRepairContract(t *testing.T) {
	sql := deploymentContextOnlyMigrationSQL(t)
	required := []string{
		"severity = metadata #>> '{deployment_context,adjusted_severity}'",
		"NOT LIKE 'severity:%'",
		"<> 'context:deployment_adjusted'",
		"jsonb_agg(factor ORDER BY ordinality)",
		"'{risk,version}'",
		"'{risk,severity}'",
		"'{risk,factors}'",
		"'{risk,score}'",
		"'{risk,band}'",
	}
	for _, fragment := range required {
		if !strings.Contains(sql, fragment) {
			t.Errorf("migration is missing risk-repair contract fragment %q", fragment)
		}
	}
}

func TestDeploymentContextOnlyMigrationRepairsLegacyRiskIntegration(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_POSTGRES_URL to run PostgreSQL migration integration tests")
	}

	ctx := context.Background()
	pool, cleanup := newDeploymentMigrationIntegrationPool(t, ctx, databaseURL)
	defer cleanup()

	legacyMetadata := `{
		"operator_action":{"primary_action":"preserve me"},
		"unrelated":{"keep":true},
		"deployment_context":{"active":true,"severity_adjusted":true,"original_severity":"medium","adjusted_severity":"low"},
		"risk":{
			"version":"2026-05-13.1","score":29,"band":"low","severity":"low","confidence":"high","custom":"preserve me",
			"factors":[
				{"id":"severity:low","points":22,"reason":"finding severity"},
				{"id":"confidence:high","points":8,"reason":"finding confidence"},
				{"id":"context:deployment_adjusted","points":-5,"reason":"active deployment lowered expected-change risk"},
				{"id":"rule:custom","points":4,"reason":"unrelated factor"}
			]
		}
	}`
	if _, err := pool.Exec(ctx, `
		INSERT INTO hub_findings (id, severity, status, status_reason, metadata)
		VALUES
			('legacy-machine-state', 'low', 'acknowledged', 'deployment_window', $1::jsonb),
			('later-status-action', 'low', 'false_positive', 'operator_review', $1::jsonb),
			('later-severity-action', 'high', 'open', 'operator_severity_change', $1::jsonb)
	`, legacyMetadata); err != nil {
		t.Fatalf("insert legacy findings: %v", err)
	}

	if _, err := pool.Exec(ctx, deploymentContextOnlyMigrationSQL(t)); err != nil {
		t.Fatalf("apply deployment context migration: %v", err)
	}

	legacy := loadDeploymentMigrationFinding(t, ctx, pool, "legacy-machine-state")
	if legacy.severity != "medium" || legacy.status != "open" || legacy.statusReason != "deployment_context_only_migration" {
		t.Fatalf("legacy machine state = severity %q, status %q/%q", legacy.severity, legacy.status, legacy.statusReason)
	}
	assertRepairedDeploymentRisk(t, legacy.metadata)

	laterStatus := loadDeploymentMigrationFinding(t, ctx, pool, "later-status-action")
	if laterStatus.severity != "medium" || laterStatus.status != "false_positive" || laterStatus.statusReason != "operator_review" {
		t.Fatalf("later status action = severity %q, status %q/%q", laterStatus.severity, laterStatus.status, laterStatus.statusReason)
	}
	assertRepairedDeploymentRisk(t, laterStatus.metadata)

	laterSeverity := loadDeploymentMigrationFinding(t, ctx, pool, "later-severity-action")
	if laterSeverity.severity != "high" || laterSeverity.statusReason != "operator_severity_change" {
		t.Fatalf("later severity action = severity %q, status reason %q", laterSeverity.severity, laterSeverity.statusReason)
	}
	deploymentContext := jsonObject(t, laterSeverity.metadata, "deployment_context")
	if deploymentContext["severity_adjusted"] != true || jsonObject(t, laterSeverity.metadata, "risk")["score"] != float64(29) {
		t.Fatalf("later severity action metadata was overwritten: %#v", laterSeverity.metadata)
	}
}

func assertRepairedDeploymentRisk(t *testing.T, metadata map[string]any) {
	t.Helper()
	if jsonObject(t, metadata, "operator_action")["primary_action"] != "preserve me" ||
		jsonObject(t, metadata, "unrelated")["keep"] != true {
		t.Fatalf("unrelated metadata was not preserved: %#v", metadata)
	}
	deploymentContext := jsonObject(t, metadata, "deployment_context")
	if deploymentContext["severity_adjusted"] != false || deploymentContext["original_severity"] != "medium" || deploymentContext["adjusted_severity"] != "medium" {
		t.Fatalf("deployment context = %#v, want restored medium severity", deploymentContext)
	}
	risk := jsonObject(t, metadata, "risk")
	if risk["version"] != "2026-08-04.1" || risk["severity"] != "medium" || risk["score"] != float64(58) || risk["band"] != "medium" || risk["custom"] != "preserve me" {
		t.Fatalf("risk metadata = %#v, want repaired score with custom data preserved", risk)
	}
	factors, ok := risk["factors"].([]any)
	if !ok {
		t.Fatalf("risk factors = %#v, want array", risk["factors"])
	}
	wantIDs := []string{"severity:medium", "confidence:high", "rule:custom"}
	if len(factors) != len(wantIDs) {
		t.Fatalf("risk factors = %#v, want %v", factors, wantIDs)
	}
	for index, wantID := range wantIDs {
		factor, ok := factors[index].(map[string]any)
		if !ok || factor["id"] != wantID {
			t.Fatalf("risk factor %d = %#v, want id %q", index, factors[index], wantID)
		}
	}
}

type deploymentMigrationFinding struct {
	severity     string
	status       string
	statusReason string
	metadata     map[string]any
}

func loadDeploymentMigrationFinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) deploymentMigrationFinding {
	t.Helper()
	var finding deploymentMigrationFinding
	var metadataJSON []byte
	if err := pool.QueryRow(ctx, `
		SELECT severity, status, status_reason, metadata
		FROM hub_findings
		WHERE id = $1
	`, id).Scan(&finding.severity, &finding.status, &finding.statusReason, &metadataJSON); err != nil {
		t.Fatalf("load finding %q: %v", id, err)
	}
	if err := json.Unmarshal(metadataJSON, &finding.metadata); err != nil {
		t.Fatalf("decode finding %q metadata: %v", id, err)
	}
	return finding
}

func jsonObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, parent[key])
	}
	return value
}

func newDeploymentMigrationIntegrationPool(t *testing.T, ctx context.Context, databaseURL string) (*pgxpool.Pool, func()) {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		adminPool.Close()
		t.Fatalf("create schema suffix: %v", err)
	}
	schemaName := "aegrail_deployment_migration_test_" + hex.EncodeToString(randomBytes)
	schemaIdent := pgx.Identifier{schemaName}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schemaIdent); err != nil {
		adminPool.Close()
		t.Fatalf("create test schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("parse postgres URL: %v", err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["search_path"] = schemaName
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("connect test pool: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE hub_findings (
			id text PRIMARY KEY,
			severity text NOT NULL,
			status text NOT NULL,
			status_reason text NOT NULL DEFAULT '',
			status_note text NOT NULL DEFAULT '',
			status_actor text NOT NULL DEFAULT '',
			status_updated_at timestamptz NOT NULL DEFAULT now(),
			metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
			updated_at timestamptz NOT NULL DEFAULT now()
		)
	`); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("create findings table: %v", err)
	}
	return pool, func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
	}
}

func deploymentContextOnlyMigrationSQL(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "migrations", "00010_deployment_context_only.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read deployment migration: %v", err)
	}
	up, _, found := strings.Cut(string(content), "-- +goose Down")
	if !found {
		t.Fatal("deployment migration is missing goose Down marker")
	}
	return up
}
