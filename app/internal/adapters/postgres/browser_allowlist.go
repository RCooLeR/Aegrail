package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
)

type BrowserScriptAllowlistRepository struct {
	pool *pgxpool.Pool
}

func NewBrowserScriptAllowlistRepository(pool *pgxpool.Pool) *BrowserScriptAllowlistRepository {
	return &BrowserScriptAllowlistRepository{pool: pool}
}

func (r *BrowserScriptAllowlistRepository) SaveBrowserScriptAllowlistEntry(ctx context.Context, entry domain.BrowserScriptAllowlistEntry) (domain.BrowserScriptAllowlistEntry, error) {
	const query = `
		INSERT INTO hub_browser_script_allowlist (
			organization_id,
			project_id,
			environment_id,
			app_id,
			page_url,
			kind,
			value,
			reason,
			approved_by,
			status
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (environment_id, app_id, page_url, kind, value) DO UPDATE
		SET reason = EXCLUDED.reason,
			approved_by = EXCLUDED.approved_by,
			status = EXCLUDED.status,
			updated_at = now()
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			app_id::text, page_url, kind, value, reason, approved_by, status, created_at, updated_at
	`
	var saved domain.BrowserScriptAllowlistEntry
	if err := r.pool.QueryRow(
		ctx,
		query,
		entry.OrganizationID,
		entry.ProjectID,
		entry.EnvironmentID,
		entry.AppID,
		entry.PageURL,
		entry.Kind,
		entry.Value,
		entry.Reason,
		entry.ApprovedBy,
		entry.Status,
	).Scan(
		&saved.ID,
		&saved.OrganizationID,
		&saved.ProjectID,
		&saved.EnvironmentID,
		&saved.AppID,
		&saved.PageURL,
		&saved.Kind,
		&saved.Value,
		&saved.Reason,
		&saved.ApprovedBy,
		&saved.Status,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	); err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	return saved, nil
}

func (r *BrowserScriptAllowlistRepository) ListBrowserScriptAllowlistEntries(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.BrowserScriptAllowlistEntry, error) {
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			app_id::text, page_url, kind, value, reason, approved_by, status, created_at, updated_at
		FROM hub_browser_script_allowlist
		WHERE environment_id = $1
			AND app_id = $2
		ORDER BY page_url ASC, kind ASC, value ASC
	`
	rows, err := r.pool.Query(ctx, query, environmentID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []domain.BrowserScriptAllowlistEntry
	for rows.Next() {
		var entry domain.BrowserScriptAllowlistEntry
		if err := rows.Scan(
			&entry.ID,
			&entry.OrganizationID,
			&entry.ProjectID,
			&entry.EnvironmentID,
			&entry.AppID,
			&entry.PageURL,
			&entry.Kind,
			&entry.Value,
			&entry.Reason,
			&entry.ApprovedBy,
			&entry.Status,
			&entry.CreatedAt,
			&entry.UpdatedAt,
		); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
