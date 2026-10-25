package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type HubFindingRepository struct {
	pool                   *pgxpool.Pool
	notificationTransports []string
}

type hubFindingQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type hubFindingRowsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type hubFindingScanner interface {
	Scan(dest ...any) error
}

func NewHubFindingRepository(pool *pgxpool.Pool) *HubFindingRepository {
	return &HubFindingRepository{pool: pool}
}

func (r *HubFindingRepository) SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error) {
	return r.saveHubFindings(ctx, findings, nil)
}

func (r *HubFindingRepository) SaveHubFindingsObserved(ctx context.Context, findings []domain.HubFinding, source string) ([]domain.HubFinding, error) {
	return r.saveHubFindings(ctx, findings, &source)
}

func (r *HubFindingRepository) saveHubFindings(ctx context.Context, findings []domain.HubFinding, notificationSource *string) ([]domain.HubFinding, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	const query = `
		INSERT INTO hub_findings (
			organization_id,
			project_id,
			environment_id,
			app_id,
			rule_id,
			rule_version,
			dedupe_key,
			severity,
			confidence,
			title,
			summary,
			description,
			event_ids,
			first_event_at,
			last_event_at,
			metadata
		)
		VALUES (
			$1, $2, $3,
			nullif($4::text, '')::uuid,
			$5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
		ON CONFLICT (environment_id, (coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid)), rule_id, dedupe_key) DO UPDATE
		SET rule_version = EXCLUDED.rule_version,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			title = EXCLUDED.title,
			summary = EXCLUDED.summary,
			description = EXCLUDED.description,
			event_ids = ARRAY(
				SELECT DISTINCT merged.event_id
				FROM unnest(hub_findings.event_ids || EXCLUDED.event_ids) AS merged(event_id)
				ORDER BY merged.event_id
			),
			first_event_at = LEAST(hub_findings.first_event_at, EXCLUDED.first_event_at),
			last_event_at = GREATEST(hub_findings.last_event_at, EXCLUDED.last_event_at),
			metadata = EXCLUDED.metadata,
			updated_at = now()
		WHERE hub_findings.rule_version IS DISTINCT FROM EXCLUDED.rule_version
			OR hub_findings.severity IS DISTINCT FROM EXCLUDED.severity
			OR hub_findings.confidence IS DISTINCT FROM EXCLUDED.confidence
			OR hub_findings.title IS DISTINCT FROM EXCLUDED.title
			OR hub_findings.summary IS DISTINCT FROM EXCLUDED.summary
			OR hub_findings.description IS DISTINCT FROM EXCLUDED.description
			OR hub_findings.event_ids IS DISTINCT FROM ARRAY(
				SELECT DISTINCT merged.event_id
				FROM unnest(hub_findings.event_ids || EXCLUDED.event_ids) AS merged(event_id)
				ORDER BY merged.event_id
			)
			OR hub_findings.first_event_at IS DISTINCT FROM LEAST(hub_findings.first_event_at, EXCLUDED.first_event_at)
			OR hub_findings.last_event_at IS DISTINCT FROM GREATEST(hub_findings.last_event_at, EXCLUDED.last_event_at)
			OR hub_findings.metadata IS DISTINCT FROM EXCLUDED.metadata
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at, (xmax = 0)
	`

	batch := &pgx.Batch{}
	for _, finding := range findings {
		batch.Queue(
			query,
			finding.OrganizationID,
			finding.ProjectID,
			finding.EnvironmentID,
			string(finding.AppID),
			finding.RuleID,
			finding.RuleVersion,
			finding.DedupeKey,
			string(finding.Severity),
			string(finding.Confidence),
			finding.Title,
			finding.Summary,
			finding.Description,
			stringIDs(finding.EventIDs),
			finding.FirstEventAt,
			finding.LastEventAt,
			nonNilAnyMap(finding.Metadata),
		)
	}
	results := tx.SendBatch(ctx, batch)
	saved := make([]domain.HubFinding, len(findings))
	missing := make([]int, 0)
	var scanErr error
	for index := range findings {
		item, err := scanHubFindingSaveResult(results.QueryRow())
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				missing = append(missing, index)
				continue
			}
			if scanErr == nil {
				scanErr = err
			}
			continue
		}
		saved[index] = item
	}
	if err := results.Close(); scanErr == nil && err != nil {
		scanErr = err
	}
	if scanErr != nil {
		return nil, scanErr
	}
	for _, index := range missing {
		finding := findings[index]
		item, err := r.getHubFindingByDedupeKey(ctx, tx, finding.EnvironmentID, finding.AppID, finding.RuleID, finding.DedupeKey)
		if err != nil {
			return nil, err
		}
		markHubFindingSaveCreated(&item, false)
		saved[index] = item
	}

	if notificationSource != nil {
		if err := r.enqueueObservedFindingNotifications(ctx, tx, saved, *notificationSource); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return saved, nil
}

func scanHubFindingSaveResult(row hubFindingScanner) (domain.HubFinding, error) {
	var item domain.HubFinding
	var eventIDs []string
	var inserted bool
	if err := row.Scan(
		&item.ID,
		&item.OrganizationID,
		&item.ProjectID,
		&item.EnvironmentID,
		&item.AppID,
		&item.RuleID,
		&item.RuleVersion,
		&item.DedupeKey,
		&item.Severity,
		&item.Confidence,
		&item.Title,
		&item.Summary,
		&item.Description,
		&eventIDs,
		&item.FirstEventAt,
		&item.LastEventAt,
		&item.Status,
		&item.StatusReason,
		&item.StatusNote,
		&item.StatusActor,
		&item.StatusUpdatedAt,
		&item.Metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
		&inserted,
	); err != nil {
		return domain.HubFinding{}, err
	}
	item.EventIDs = domainIDs(eventIDs)
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	markHubFindingSaveCreated(&item, inserted)
	return item, nil
}

func markHubFindingSaveCreated(finding *domain.HubFinding, created bool) {
	if finding.Metadata == nil {
		finding.Metadata = map[string]any{}
	}
	finding.Metadata[domain.HubFindingMetadataSaveCreated] = created
}

func (r *HubFindingRepository) getHubFindingByDedupeKey(ctx context.Context, row hubFindingQuerier, environmentID domain.ID, appID domain.ID, ruleID string, dedupeKey string) (domain.HubFinding, error) {
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE environment_id = $1
			AND coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid) =
				coalesce(nullif($2::text, '')::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
			AND rule_id = $3
			AND dedupe_key = $4
	`
	var item domain.HubFinding
	var eventIDs []string
	if err := row.QueryRow(ctx, query, environmentID, string(appID), ruleID, dedupeKey).Scan(
		&item.ID,
		&item.OrganizationID,
		&item.ProjectID,
		&item.EnvironmentID,
		&item.AppID,
		&item.RuleID,
		&item.RuleVersion,
		&item.DedupeKey,
		&item.Severity,
		&item.Confidence,
		&item.Title,
		&item.Summary,
		&item.Description,
		&eventIDs,
		&item.FirstEventAt,
		&item.LastEventAt,
		&item.Status,
		&item.StatusReason,
		&item.StatusNote,
		&item.StatusActor,
		&item.StatusUpdatedAt,
		&item.Metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.HubFinding{}, ports.ErrHubNotFound
		}
		return domain.HubFinding{}, err
	}
	item.EventIDs = domainIDs(eventIDs)
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	return item, nil
}

func scanHubFinding(row hubFindingScanner) (domain.HubFinding, error) {
	var item domain.HubFinding
	var eventIDs []string
	if err := row.Scan(
		&item.ID,
		&item.OrganizationID,
		&item.ProjectID,
		&item.EnvironmentID,
		&item.AppID,
		&item.RuleID,
		&item.RuleVersion,
		&item.DedupeKey,
		&item.Severity,
		&item.Confidence,
		&item.Title,
		&item.Summary,
		&item.Description,
		&eventIDs,
		&item.FirstEventAt,
		&item.LastEventAt,
		&item.Status,
		&item.StatusReason,
		&item.StatusNote,
		&item.StatusActor,
		&item.StatusUpdatedAt,
		&item.Metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return domain.HubFinding{}, err
	}
	item.EventIDs = domainIDs(eventIDs)
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	return item, nil
}

func (r *HubFindingRepository) ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error) {
	return listHubFindingRows(ctx, r.pool, environmentID, appID, ports.HubFindingPageOptions{
		Limit: normalizeHubFindingPageLimit(limit),
	})
}

func (r *HubFindingRepository) ListHubFindingsPage(ctx context.Context, environmentID domain.ID, appID domain.ID, options ports.HubFindingPageOptions) (ports.HubFindingPage, error) {
	options.Limit = normalizeHubFindingPageLimit(options.Limit)
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return ports.HubFindingPage{}, err
	}
	defer tx.Rollback(ctx)

	var summary ports.HubFindingSummary
	summaryIncluded := !options.SkipSummary
	var matchedTotal int64
	matchedTotalIncluded := !options.SkipSummary
	if summaryIncluded {
		summary, err = queryHubFindingSummary(ctx, tx, environmentID, appID)
		if err != nil {
			return ports.HubFindingPage{}, err
		}
		if hubFindingPageHasFilters(options) {
			matchedTotal, err = queryHubFindingMatchedTotal(ctx, tx, environmentID, appID, options)
			if err != nil {
				return ports.HubFindingPage{}, err
			}
		} else {
			matchedTotal = summary.Total
		}
	}
	queryOptions := options
	queryOptions.Limit++
	findings, err := listHubFindingRows(ctx, tx, environmentID, appID, queryOptions)
	if err != nil {
		return ports.HubFindingPage{}, err
	}
	hasMore := len(findings) > options.Limit
	if hasMore {
		findings = findings[:options.Limit]
	}
	if err := tx.Commit(ctx); err != nil {
		return ports.HubFindingPage{}, err
	}
	return ports.HubFindingPage{
		Findings:             findings,
		Summary:              summary,
		SummaryIncluded:      summaryIncluded,
		MatchedTotal:         matchedTotal,
		MatchedTotalIncluded: matchedTotalIncluded,
		HasMore:              hasMore,
	}, nil
}

func listHubFindingRows(ctx context.Context, querier hubFindingRowsQuerier, environmentID domain.ID, appID domain.ID, options ports.HubFindingPageOptions) ([]domain.HubFinding, error) {
	limit := normalizeHubFindingPageLimit(options.Limit)
	if options.Limit > 500 {
		// The paginated repository fetches one extra record to determine
		// has_more, while public callers remain capped at 500 records.
		limit = 501
	}
	if limit <= 0 {
		limit = 20
	}
	where, args := hubFindingPageWhere(environmentID, appID, options)
	args = append(args, limit)
	query := `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE ` + where + `
		ORDER BY created_at DESC, id DESC
		LIMIT ` + fmt.Sprintf("$%d", len(args))
	rows, err := querier.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []domain.HubFinding
	for rows.Next() {
		item, err := scanHubFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, item)
	}
	return findings, rows.Err()
}

func hubFindingPageWhere(environmentID domain.ID, appID domain.ID, options ports.HubFindingPageOptions) (string, []any) {
	clauses := []string{"environment_id = $1"}
	args := []any{environmentID}
	if strings.TrimSpace(string(appID)) != "" {
		args = append(args, string(appID))
		clauses = append(clauses, fmt.Sprintf("app_id = $%d::uuid", len(args)))
	}
	if len(options.Statuses) > 0 {
		args = append(args, options.Statuses)
		clauses = append(clauses, fmt.Sprintf("status = ANY($%d::text[])", len(args)))
	}
	if len(options.Severities) > 0 {
		args = append(args, options.Severities)
		clauses = append(clauses, fmt.Sprintf("severity = ANY($%d::text[])", len(args)))
	}
	if query := strings.ToLower(strings.TrimSpace(options.Query)); query != "" {
		args = append(args, escapeHubFindingLikePattern(query))
		placeholder := fmt.Sprintf("$%d::text", len(args))
		clauses = append(clauses, fmt.Sprintf(`(
			lower(
				coalesce(title, '') || E'\x1f' ||
				coalesce(summary, '') || E'\x1f' ||
				coalesce(description, '') || E'\x1f' ||
				coalesce(rule_id, '') || E'\x1f' ||
				coalesce(dedupe_key, '')
			) LIKE '%%' || %[1]s || '%%' ESCAPE E'\\'
		)`, placeholder))
	}
	if options.After != nil {
		args = append(args, options.After.CreatedAt.UTC())
		createdAtPlaceholder := len(args)
		args = append(args, string(options.After.ID))
		clauses = append(clauses, fmt.Sprintf(
			"(created_at, id) < ($%d, $%d::uuid)",
			createdAtPlaceholder,
			len(args),
		))
	}
	return strings.Join(clauses, "\n\t\t\tAND "), args
}

func escapeHubFindingLikePattern(value string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	).Replace(strings.ToLower(strings.TrimSpace(value)))
}

func hubFindingPageHasFilters(options ports.HubFindingPageOptions) bool {
	return len(options.Statuses) > 0 || len(options.Severities) > 0 || strings.TrimSpace(options.Query) != ""
}

func queryHubFindingMatchedTotal(ctx context.Context, querier hubFindingQuerier, environmentID domain.ID, appID domain.ID, options ports.HubFindingPageOptions) (int64, error) {
	options.After = nil
	where, args := hubFindingPageWhere(environmentID, appID, options)
	var total int64
	if err := querier.QueryRow(ctx, "SELECT count(*)::bigint FROM hub_findings WHERE "+where, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func normalizeHubFindingPageLimit(limit int) int {
	if limit <= 0 {
		return 20
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func queryHubFindingSummary(ctx context.Context, querier hubFindingRowsQuerier, environmentID domain.ID, appID domain.ID) (ports.HubFindingSummary, error) {
	const environmentQuery = `
		SELECT lower(coalesce(nullif(btrim(status), ''), 'open')) AS finding_status,
			lower(coalesce(nullif(btrim(severity), ''), 'unknown')) AS finding_severity,
			count(*)::bigint
		FROM hub_findings
		WHERE environment_id = $1
		GROUP BY 1, 2
	`
	const appQuery = `
		SELECT lower(coalesce(nullif(btrim(status), ''), 'open')) AS finding_status,
			lower(coalesce(nullif(btrim(severity), ''), 'unknown')) AS finding_severity,
			count(*)::bigint
		FROM hub_findings
		WHERE environment_id = $1
			AND app_id = $2::uuid
		GROUP BY 1, 2
	`
	query := environmentQuery
	args := []any{environmentID}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID)}
	}
	rows, err := querier.Query(ctx, query, args...)
	if err != nil {
		return ports.HubFindingSummary{}, err
	}
	defer rows.Close()

	summary := newHubFindingSummary()
	for rows.Next() {
		var status string
		var severity string
		var count int64
		if err := rows.Scan(&status, &severity, &count); err != nil {
			return ports.HubFindingSummary{}, err
		}
		summary.Total += count
		summary.StatusCounts[status] += count
		summary.SeverityCounts[severity] += count
		if status == "open" {
			summary.OpenSeverityCounts[severity] += count
		}
	}
	return summary, rows.Err()
}

func newHubFindingSummary() ports.HubFindingSummary {
	statusCounts := map[string]int64{}
	for _, status := range []string{"open", "acknowledged", "false_positive", "resolved"} {
		statusCounts[status] = 0
	}
	severityCounts := map[string]int64{}
	openSeverityCounts := map[string]int64{}
	for _, severity := range []string{"info", "low", "medium", "high", "critical"} {
		severityCounts[severity] = 0
		openSeverityCounts[severity] = 0
	}
	return ports.HubFindingSummary{
		StatusCounts:       statusCounts,
		SeverityCounts:     severityCounts,
		OpenSeverityCounts: openSeverityCounts,
	}
}

func (r *HubFindingRepository) GetHubFinding(ctx context.Context, findingID domain.ID, environmentID domain.ID, appID domain.ID) (domain.HubFinding, error) {
	const environmentQuery = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE id = $1
			AND environment_id = $2
	`
	const appQuery = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE id = $1
			AND environment_id = $2
			AND app_id = $3::uuid
	`
	query := environmentQuery
	args := []any{findingID, environmentID}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{findingID, environmentID, string(appID)}
	}
	item, err := scanHubFinding(r.pool.QueryRow(ctx, query, args...))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.HubFinding{}, ports.ErrHubNotFound
		}
		return domain.HubFinding{}, err
	}
	return item, nil
}

func (r *HubFindingRepository) ListModelAnalysisQueueScopes(ctx context.Context, limit int) ([]ports.ModelAnalysisQueueScope, error) {
	if limit <= 0 {
		limit = 5
	}
	if limit > 500 {
		limit = 500
	}
	const query = `
		SELECT DISTINCT
			o.id::text, o.slug::text AS organization_slug, o.name, o.created_at, o.updated_at,
			p.id::text, p.organization_id::text, p.slug::text AS project_slug, p.name, p.created_at, p.updated_at,
			e.id::text, e.project_id::text, e.slug::text AS environment_slug, e.name, e.created_at, e.updated_at
		FROM hub_findings f
		JOIN organizations o ON o.id = f.organization_id
		JOIN projects p ON p.id = f.project_id
		JOIN environments e ON e.id = f.environment_id
		WHERE coalesce(nullif(f.status, ''), 'open') = 'open'
			AND NOT EXISTS (
				SELECT 1
				FROM hub_model_analysis_reports r
				WHERE r.environment_id = f.environment_id
					AND coalesce(r.app_id, '00000000-0000-0000-0000-000000000000'::uuid) =
						coalesce(f.app_id, '00000000-0000-0000-0000-000000000000'::uuid)
					AND r.source_finding_ids @> ARRAY[f.id::text]::text[]
					AND r.status = 'completed'
			)
		ORDER BY organization_slug, project_slug, environment_slug
		LIMIT $1
	`
	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var scopes []ports.ModelAnalysisQueueScope
	for rows.Next() {
		var scope ports.ModelAnalysisQueueScope
		if err := rows.Scan(
			&scope.Organization.ID, &scope.Organization.Slug, &scope.Organization.Name, &scope.Organization.CreatedAt, &scope.Organization.UpdatedAt,
			&scope.Project.ID, &scope.Project.OrganizationID, &scope.Project.Slug, &scope.Project.Name, &scope.Project.CreatedAt, &scope.Project.UpdatedAt,
			&scope.Environment.ID, &scope.Environment.ProjectID, &scope.Environment.Slug, &scope.Environment.Name, &scope.Environment.CreatedAt, &scope.Environment.UpdatedAt,
		); err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, rows.Err()
}

func (r *HubFindingRepository) UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error) {
	const query = `
		UPDATE hub_findings
		SET status = $3,
			status_reason = $4,
			status_note = $5,
			status_actor = $6,
			status_updated_at = now(),
			updated_at = now()
		WHERE id = $1
			AND environment_id = $2
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
	`
	var item domain.HubFinding
	var eventIDs []string
	if err := r.pool.QueryRow(
		ctx,
		query,
		findingID,
		environmentID,
		update.Status,
		update.Reason,
		update.Note,
		update.Actor,
	).Scan(
		&item.ID,
		&item.OrganizationID,
		&item.ProjectID,
		&item.EnvironmentID,
		&item.AppID,
		&item.RuleID,
		&item.RuleVersion,
		&item.DedupeKey,
		&item.Severity,
		&item.Confidence,
		&item.Title,
		&item.Summary,
		&item.Description,
		&eventIDs,
		&item.FirstEventAt,
		&item.LastEventAt,
		&item.Status,
		&item.StatusReason,
		&item.StatusNote,
		&item.StatusActor,
		&item.StatusUpdatedAt,
		&item.Metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.HubFinding{}, ports.ErrHubNotFound
		}
		return domain.HubFinding{}, err
	}
	item.EventIDs = domainIDs(eventIDs)
	return item, nil
}

func (r *HubFindingRepository) UpdateOpenHubFindingStatuses(ctx context.Context, environmentID domain.ID, appID domain.ID, update domain.HubFindingStatusUpdate) (int, error) {
	const environmentQuery = `
		UPDATE hub_findings
		SET status = $2,
			status_reason = $3,
			status_note = $4,
			status_actor = $5,
			status_updated_at = now(),
			updated_at = now()
		WHERE environment_id = $1
			AND status = 'open'
			AND severity NOT IN ('high', 'critical')
	`
	const appQuery = `
		UPDATE hub_findings
		SET status = $3,
			status_reason = $4,
			status_note = $5,
			status_actor = $6,
			status_updated_at = now(),
			updated_at = now()
		WHERE environment_id = $1
			AND app_id = $2::uuid
			AND status = 'open'
			AND severity NOT IN ('high', 'critical')
	`
	query := environmentQuery
	args := []any{environmentID, update.Status, update.Reason, update.Note, update.Actor}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), update.Status, update.Reason, update.Note, update.Actor}
	}
	commandTag, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return int(commandTag.RowsAffected()), nil
}

func stringIDs(ids []domain.ID) []string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, string(id))
	}
	return values
}

func domainIDs(values []string) []domain.ID {
	ids := make([]domain.ID, 0, len(values))
	for _, value := range values {
		ids = append(ids, domain.ID(value))
	}
	return ids
}
