package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
)

type HubFindingRepository struct {
	pool *pgxpool.Pool
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
		ON CONFLICT (environment_id, rule_id, dedupe_key) DO UPDATE
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
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
	`

	saved := make([]domain.HubFinding, 0, len(findings))
	for _, finding := range findings {
		var item domain.HubFinding
		var eventIDs []string
		if err := tx.QueryRow(
			ctx,
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
			return nil, err
		}
		item.EventIDs = domainIDs(eventIDs)
		saved = append(saved, item)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return saved, nil
}

func (r *HubFindingRepository) ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), rule_id, rule_version, dedupe_key, severity,
			confidence, title, summary, description, event_ids, first_event_at,
			last_event_at, status, status_reason, status_note, status_actor,
			status_updated_at, metadata, created_at, updated_at
		FROM hub_findings
		WHERE environment_id = $1
			AND ($2::text = '' OR app_id = nullif($2::text, '')::uuid)
		ORDER BY first_event_at DESC, created_at DESC
		LIMIT $3
	`
	rows, err := r.pool.Query(ctx, query, environmentID, string(appID), limit)
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
		return domain.HubFinding{}, err
	}
	item.EventIDs = domainIDs(eventIDs)
	return item, nil
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
