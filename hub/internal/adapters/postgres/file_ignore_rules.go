package postgres

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

type HubFileIgnoreRuleRepository struct {
	pool *pgxpool.Pool
}

func NewHubFileIgnoreRuleRepository(pool *pgxpool.Pool) *HubFileIgnoreRuleRepository {
	return &HubFileIgnoreRuleRepository{pool: pool}
}

func (r *HubFileIgnoreRuleRepository) SaveHubFileIgnoreRule(ctx context.Context, rule domain.HubFileIgnoreRule) (domain.HubFileIgnoreRule, error) {
	const query = `
		INSERT INTO hub_file_ignore_rules (
			organization_id,
			project_id,
			environment_id,
			app_id,
			match_kind,
			match_value,
			normalized_value,
			reason,
			created_by,
			status
		)
		VALUES ($1, $2, $3, nullif($4::text, '')::uuid, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (environment_id, (coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid)), match_kind, normalized_value)
		DO UPDATE SET
			match_value = EXCLUDED.match_value,
			reason = EXCLUDED.reason,
			created_by = EXCLUDED.created_by,
			status = EXCLUDED.status,
			updated_at = now()
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), match_kind, match_value, normalized_value, reason,
			created_by, status, created_at, updated_at
	`
	var saved domain.HubFileIgnoreRule
	if err := r.pool.QueryRow(
		ctx,
		query,
		rule.OrganizationID,
		rule.ProjectID,
		rule.EnvironmentID,
		string(rule.AppID),
		rule.MatchKind,
		rule.MatchValue,
		rule.NormalizedValue,
		rule.Reason,
		rule.CreatedBy,
		nonEmptyString(rule.Status, "active"),
	).Scan(
		&saved.ID,
		&saved.OrganizationID,
		&saved.ProjectID,
		&saved.EnvironmentID,
		&saved.AppID,
		&saved.MatchKind,
		&saved.MatchValue,
		&saved.NormalizedValue,
		&saved.Reason,
		&saved.CreatedBy,
		&saved.Status,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	); err != nil {
		return domain.HubFileIgnoreRule{}, err
	}
	return saved, nil
}

func (r *HubFileIgnoreRuleRepository) ListActiveHubFileIgnoreRules(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.HubFileIgnoreRule, error) {
	const environmentQuery = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), match_kind, match_value, normalized_value, reason,
			created_by, status, created_at, updated_at
		FROM hub_file_ignore_rules
		WHERE environment_id = $1
			AND status = 'active'
		ORDER BY created_at DESC
	`
	const appQuery = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), match_kind, match_value, normalized_value, reason,
			created_by, status, created_at, updated_at
		FROM hub_file_ignore_rules
		WHERE environment_id = $1
			AND status = 'active'
			AND app_id IS NULL
		UNION ALL
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), match_kind, match_value, normalized_value, reason,
			created_by, status, created_at, updated_at
		FROM hub_file_ignore_rules
		WHERE environment_id = $1
			AND status = 'active'
			AND app_id = $2::uuid
		ORDER BY created_at DESC
	`
	query := environmentQuery
	args := []any{environmentID}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID)}
	}
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []domain.HubFileIgnoreRule
	for rows.Next() {
		var rule domain.HubFileIgnoreRule
		if err := rows.Scan(
			&rule.ID,
			&rule.OrganizationID,
			&rule.ProjectID,
			&rule.EnvironmentID,
			&rule.AppID,
			&rule.MatchKind,
			&rule.MatchValue,
			&rule.NormalizedValue,
			&rule.Reason,
			&rule.CreatedBy,
			&rule.Status,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func nonEmptyString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
