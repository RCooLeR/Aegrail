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
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestHubFindingRepositoryPaginatesByImmutableCreationOrderWithScopeSummaryIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubFindingPaginationIntegrationPool(t, ctx)
	defer cleanup()

	environmentID := domain.ID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	appID := domain.ID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	otherAppID := domain.ID("cccccccc-cccc-cccc-cccc-cccccccccccc")
	base := time.Date(2026, 7, 29, 5, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `
		INSERT INTO hub_findings (
			id, organization_id, project_id, environment_id, app_id,
			rule_id, rule_version, dedupe_key, severity, confidence,
			title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_updated_at, metadata, created_at, updated_at
		)
		VALUES
			('10000000-0000-0000-0000-000000000000', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', $1, $2, 'rule-1', 'v1', 'key-1', 'high', 'high', 'literal 100%_match', '', '', '{}', $4, $4, 'open', $4, '{}', $4, $4),
			('30000000-0000-0000-0000-000000000000', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', $1, $2, 'rule-2', 'v1', 'key-2', 'medium', 'high', 'two', '', '', '{}', $4, $5, 'open', $5, '{}', $5, $5),
			('20000000-0000-0000-0000-000000000000', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', $1, $2, 'rule-3', 'v1', 'key-3', 'high', 'high', 'three', '', '', '{}', $4, $5, 'resolved', $5, '{}', $5, $5),
			('40000000-0000-0000-0000-000000000000', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', $1, $3, 'rule-4', 'v1', 'key-4', 'low', 'high', 'other app', '', '', '{}', $4, $6, 'open', $6, '{}', $6, $6)
	`, environmentID, appID, otherAppID, base, base.Add(-time.Minute), base.Add(time.Minute)); err != nil {
		t.Fatalf("insert findings: %v", err)
	}

	repository := NewHubFindingRepository(pool)
	firstPage, err := repository.ListHubFindingsPage(ctx, environmentID, appID, ports.HubFindingPageOptions{Limit: 2})
	if err != nil {
		t.Fatalf("ListHubFindingsPage first page: %v", err)
	}
	if len(firstPage.Findings) != 2 || !firstPage.HasMore {
		t.Fatalf("first page count=%d has_more=%v, want 2/true", len(firstPage.Findings), firstPage.HasMore)
	}
	if firstPage.Findings[0].ID != "10000000-0000-0000-0000-000000000000" ||
		firstPage.Findings[1].ID != "30000000-0000-0000-0000-000000000000" {
		t.Fatalf("first page ids = %q, %q", firstPage.Findings[0].ID, firstPage.Findings[1].ID)
	}
	if firstPage.Summary.Total != 3 ||
		firstPage.Summary.StatusCounts["open"] != 2 ||
		firstPage.Summary.StatusCounts["resolved"] != 1 ||
		firstPage.Summary.SeverityCounts["high"] != 2 ||
		firstPage.Summary.OpenSeverityCounts["high"] != 1 {
		t.Fatalf("summary = %#v", firstPage.Summary)
	}
	if !firstPage.MatchedTotalIncluded || firstPage.MatchedTotal != 3 {
		t.Fatalf("first page matched total = %d included=%v, want exact unfiltered total", firstPage.MatchedTotal, firstPage.MatchedTotalIncluded)
	}

	filteredPage, err := repository.ListHubFindingsPage(ctx, environmentID, appID, ports.HubFindingPageOptions{
		Limit:      1,
		Statuses:   []string{"open", "resolved"},
		Severities: []string{"high"},
		Query:      "KEY-",
	})
	if err != nil {
		t.Fatalf("ListHubFindingsPage filtered first page: %v", err)
	}
	if len(filteredPage.Findings) != 1 || !filteredPage.HasMore ||
		!filteredPage.SummaryIncluded || filteredPage.Summary.Total != 3 ||
		!filteredPage.MatchedTotalIncluded || filteredPage.MatchedTotal != 2 {
		t.Fatalf("filtered first page = %#v, want one of two matches with unfiltered summary", filteredPage)
	}
	filteredLast := filteredPage.Findings[len(filteredPage.Findings)-1]
	filteredSecondPage, err := repository.ListHubFindingsPage(ctx, environmentID, appID, ports.HubFindingPageOptions{
		Limit:       1,
		SkipSummary: true,
		After: &ports.HubFindingPageCursor{
			CreatedAt: filteredLast.CreatedAt,
			ID:        filteredLast.ID,
		},
		Statuses:   []string{"open", "resolved"},
		Severities: []string{"high"},
		Query:      "key-",
	})
	if err != nil {
		t.Fatalf("ListHubFindingsPage filtered second page: %v", err)
	}
	if len(filteredSecondPage.Findings) != 1 || filteredSecondPage.HasMore ||
		filteredSecondPage.SummaryIncluded || filteredSecondPage.MatchedTotalIncluded {
		t.Fatalf("filtered second page = %#v, want final match without recomputed totals", filteredSecondPage)
	}
	if filteredSecondPage.Findings[0].ID == filteredPage.Findings[0].ID {
		t.Fatalf("filtered cursor repeated finding %q", filteredSecondPage.Findings[0].ID)
	}

	literalQueryPage, err := repository.ListHubFindingsPage(ctx, environmentID, appID, ports.HubFindingPageOptions{
		Limit: 10,
		Query: "%_",
	})
	if err != nil {
		t.Fatalf("ListHubFindingsPage literal query: %v", err)
	}
	if literalQueryPage.MatchedTotal != 1 || len(literalQueryPage.Findings) != 1 ||
		literalQueryPage.Findings[0].ID != "10000000-0000-0000-0000-000000000000" {
		t.Fatalf("literal query page = %#v, want only the finding containing literal %%_", literalQueryPage)
	}

	last := firstPage.Findings[len(firstPage.Findings)-1]
	// Refresh a not-yet-read finding between requests. Exhaustive pagination
	// must not lose it merely because its mutable last_event_at moved forward.
	if _, err := pool.Exec(ctx, `
		UPDATE hub_findings
		SET last_event_at = $2, updated_at = $2
		WHERE id = $1
	`, "20000000-0000-0000-0000-000000000000", base.Add(time.Hour)); err != nil {
		t.Fatalf("refresh unread finding between pages: %v", err)
	}
	secondPage, err := repository.ListHubFindingsPage(ctx, environmentID, appID, ports.HubFindingPageOptions{
		Limit:       2,
		SkipSummary: true,
		After: &ports.HubFindingPageCursor{
			CreatedAt: last.CreatedAt,
			ID:        last.ID,
		},
	})
	if err != nil {
		t.Fatalf("ListHubFindingsPage second page: %v", err)
	}
	if len(secondPage.Findings) != 1 || secondPage.HasMore {
		t.Fatalf("second page count=%d has_more=%v, want 1/false", len(secondPage.Findings), secondPage.HasMore)
	}
	if secondPage.Findings[0].ID != "20000000-0000-0000-0000-000000000000" {
		t.Fatalf("second page id = %q", secondPage.Findings[0].ID)
	}
	if secondPage.SummaryIncluded || secondPage.Summary.Total != 0 {
		t.Fatalf("second page unexpectedly recomputed the scope summary: %#v", secondPage)
	}
	if secondPage.MatchedTotalIncluded {
		t.Fatalf("second page unexpectedly recomputed matched total: %#v", secondPage)
	}

	environmentPage, err := repository.ListHubFindingsPage(ctx, environmentID, "", ports.HubFindingPageOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListHubFindingsPage environment scope: %v", err)
	}
	if environmentPage.Summary.Total != 4 || len(environmentPage.Findings) != 4 {
		t.Fatalf("environment page total=%d count=%d, want 4/4", environmentPage.Summary.Total, len(environmentPage.Findings))
	}
}

func TestHubFindingRepositoryStableDedupeMergesEvidenceWithoutRecreatingIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubFindingPaginationIntegrationPool(t, ctx)
	defer cleanup()

	repository := NewHubFindingRepository(pool)
	firstAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	base := domain.HubFinding{
		OrganizationID: "dddddddd-dddd-dddd-dddd-dddddddddddd",
		ProjectID:      "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
		EnvironmentID:  "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		AppID:          "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		RuleID:         "web-error-rate-spike",
		RuleVersion:    "v1",
		DedupeKey:      "stable-window",
		Severity:       domain.SeverityMedium,
		Confidence:     domain.ConfidenceHigh,
		Title:          "Web error rate spike",
		Summary:        "six errors",
		EventIDs:       []domain.ID{"event-1"},
		FirstEventAt:   firstAt,
		LastEventAt:    firstAt.Add(time.Minute),
		Metadata:       map[string]any{"source": "test"},
	}
	first, err := repository.SaveHubFindings(ctx, []domain.HubFinding{base})
	if err != nil {
		t.Fatalf("first SaveHubFindings: %v", err)
	}
	if len(first) != 1 || !hubFindingSaveCreatedForIntegration(first[0]) {
		t.Fatalf("first save = %#v, want one newly created finding", first)
	}

	updated := base
	updated.Summary = "seven errors"
	updated.EventIDs = []domain.ID{"event-2"}
	updated.FirstEventAt = firstAt.Add(30 * time.Second)
	updated.LastEventAt = firstAt.Add(2 * time.Minute)
	second, err := repository.SaveHubFindings(ctx, []domain.HubFinding{updated})
	if err != nil {
		t.Fatalf("second SaveHubFindings: %v", err)
	}
	if len(second) != 1 || hubFindingSaveCreatedForIntegration(second[0]) {
		t.Fatalf("second save = %#v, want an update without a created marker", second)
	}
	if second[0].ID != first[0].ID {
		t.Fatalf("finding ID changed across stable dedupe: %q != %q", second[0].ID, first[0].ID)
	}
	if !second[0].FirstEventAt.Equal(firstAt) || !second[0].LastEventAt.Equal(firstAt.Add(2*time.Minute)) {
		t.Fatalf("merged event range = %s..%s", second[0].FirstEventAt, second[0].LastEventAt)
	}
	if len(second[0].EventIDs) != 2 || second[0].EventIDs[0] != "event-1" || second[0].EventIDs[1] != "event-2" {
		t.Fatalf("merged event IDs = %#v, want both evidence IDs", second[0].EventIDs)
	}
}

func hubFindingSaveCreatedForIntegration(finding domain.HubFinding) bool {
	created, _ := finding.Metadata[domain.HubFindingMetadataSaveCreated].(bool)
	return created
}

func newHubFindingPaginationIntegrationPool(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_POSTGRES_URL to run PostgreSQL adapter integration tests")
	}
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		adminPool.Close()
		t.Fatalf("create schema suffix: %v", err)
	}
	schemaIdent := pgx.Identifier{"aegrail_findings_page_test_" + hex.EncodeToString(randomBytes)}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schemaIdent); err != nil {
		adminPool.Close()
		t.Fatalf("create test schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("parse postgres url: %v", err)
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["search_path"] = strings.Trim(schemaIdent, `"`)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("connect test pool: %v", err)
	}
	if _, err := pool.Exec(ctx, hubFindingPaginationIntegrationSchemaSQL); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("create findings schema: %v", err)
	}
	return pool, func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
	}
}

const hubFindingPaginationIntegrationSchemaSQL = `
CREATE TABLE hub_findings (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	organization_id uuid NOT NULL,
	project_id uuid NOT NULL,
	environment_id uuid NOT NULL,
	app_id uuid,
	rule_id text NOT NULL,
	rule_version text NOT NULL,
	dedupe_key text NOT NULL,
	severity text NOT NULL,
	confidence text NOT NULL,
	title text NOT NULL,
	summary text NOT NULL,
	description text NOT NULL,
	event_ids text[] NOT NULL DEFAULT '{}',
	first_event_at timestamptz NOT NULL,
	last_event_at timestamptz NOT NULL,
	status text NOT NULL DEFAULT 'open',
	status_reason text NOT NULL DEFAULT '',
	status_note text NOT NULL DEFAULT '',
	status_actor text NOT NULL DEFAULT '',
	status_updated_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX hub_findings_scope_rule_dedupe_unique_idx
	ON hub_findings (
		environment_id,
		(coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid)),
		rule_id,
		dedupe_key
	);
`
