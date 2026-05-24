package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type HubFindingRepository struct {
	pool *pgxpool.Pool
}

type hubFindingQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type hubFindingScanner interface {
	Scan(dest ...any) error
}

func NewHubFindingRepository(pool *pgxpool.Pool) *HubFindingRepository {
	return &HubFindingRepository{pool: pool}
}

func (r *HubFindingRepository) SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error) {
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
			event_ids = EXCLUDED.event_ids,
			first_event_at = EXCLUDED.first_event_at,
			last_event_at = EXCLUDED.last_event_at,
			metadata = EXCLUDED.metadata,
			updated_at = now()
		WHERE hub_findings.rule_version IS DISTINCT FROM EXCLUDED.rule_version
			OR hub_findings.severity IS DISTINCT FROM EXCLUDED.severity
			OR hub_findings.confidence IS DISTINCT FROM EXCLUDED.confidence
			OR hub_findings.title IS DISTINCT FROM EXCLUDED.title
			OR hub_findings.summary IS DISTINCT FROM EXCLUDED.summary
			OR hub_findings.description IS DISTINCT FROM EXCLUDED.description
			OR hub_findings.event_ids IS DISTINCT FROM EXCLUDED.event_ids
			OR hub_findings.first_event_at IS DISTINCT FROM EXCLUDED.first_event_at
			OR hub_findings.last_event_at IS DISTINCT FROM EXCLUDED.last_event_at
			OR hub_findings.metadata IS DISTINCT FROM EXCLUDED.metadata
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
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
		item, err := scanHubFinding(results.QueryRow())
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
		saved[index] = item
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return saved, nil
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
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	const environmentQuery = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE environment_id = $1
		ORDER BY first_event_at DESC, created_at DESC
		LIMIT $2
	`
	const appQuery = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE environment_id = $1
			AND app_id = $2::uuid
		ORDER BY first_event_at DESC, created_at DESC
		LIMIT $3
	`
	query := environmentQuery
	args := []any{environmentID, limit}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), limit}
	}
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []domain.HubFinding
	for rows.Next() {
		var item domain.HubFinding
		var eventIDs []string
		if err := rows.Scan(
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
			return nil, err
		}
		item.EventIDs = domainIDs(eventIDs)
		findings = append(findings, item)
	}
	return findings, rows.Err()
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

func (r *HubFindingRepository) UpdateOpenHubFindingStatusesForRulesInWindow(ctx context.Context, environmentID domain.ID, appID domain.ID, ruleIDs []string, windowStart time.Time, windowEnd time.Time, update domain.HubFindingStatusUpdate) (int, error) {
	if len(ruleIDs) == 0 || windowStart.IsZero() || windowEnd.IsZero() {
		return 0, nil
	}
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
			AND rule_id = ANY($6::text[])
			AND first_event_at <= $8
			AND last_event_at >= $7
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
			AND rule_id = ANY($7::text[])
			AND first_event_at <= $9
			AND last_event_at >= $8
	`
	query := environmentQuery
	args := []any{environmentID, update.Status, update.Reason, update.Note, update.Actor, ruleIDs, windowStart.UTC(), windowEnd.UTC()}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), update.Status, update.Reason, update.Note, update.Actor, ruleIDs, windowStart.UTC(), windowEnd.UTC()}
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
