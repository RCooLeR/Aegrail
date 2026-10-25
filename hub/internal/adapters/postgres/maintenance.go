package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

const minimumResolvedFindingRetention = 30 * 24 * time.Hour

type HubMaintenanceRepository struct {
	pool *pgxpool.Pool
}

func NewHubMaintenanceRepository(pool *pgxpool.Pool) *HubMaintenanceRepository {
	return &HubMaintenanceRepository{pool: pool}
}

func (r *HubMaintenanceRepository) PruneHubData(ctx context.Context, options domain.HubMaintenancePruneOptions) (domain.HubMaintenancePruneResult, error) {
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 5000
	}
	if batchSize > 5000 {
		batchSize = 5000
	}
	result := domain.HubMaintenancePruneResult{StartedAt: now.UTC()}
	var err error
	if options.EventRetention > 0 {
		cutoff := now.Add(-options.EventRetention)
		result.IngestEventsDeleted, err = r.pruneIngestEvents(ctx, cutoff, batchSize)
		if err != nil {
			return result, err
		}
		result.IngestBatchesDeleted, err = r.pruneEmptyIngestBatches(ctx, cutoff, batchSize)
		if err != nil {
			return result, err
		}
	}
	if options.ResolvedFindingRetention >= minimumResolvedFindingRetention {
		cutoff := now.Add(-options.ResolvedFindingRetention)
		result.ResolvedFindingsDeleted, err = r.pruneResolvedFindings(ctx, cutoff, batchSize)
		if err != nil {
			return result, err
		}
	}
	if options.ModelReportRetention > 0 {
		cutoff := now.Add(-options.ModelReportRetention)
		result.ModelReportsDeleted, err = r.pruneModelReports(ctx, cutoff, batchSize)
		if err != nil {
			return result, err
		}
	}
	if options.AuthEventRetention > 0 {
		cutoff := now.Add(-options.AuthEventRetention)
		result.AuthEventsDeleted, err = r.pruneAuthEvents(ctx, cutoff, batchSize)
		if err != nil {
			return result, err
		}
	}
	result.FinishedAt = time.Now().UTC()
	_, _ = r.pool.Exec(ctx, `
		INSERT INTO hub_maintenance_runs (kind, started_at, finished_at, result)
		VALUES ('retention_prune', $1, $2, $3)
	`, result.StartedAt, result.FinishedAt, map[string]any{
		"ingest_events_deleted":     result.IngestEventsDeleted,
		"ingest_batches_deleted":    result.IngestBatchesDeleted,
		"resolved_findings_deleted": result.ResolvedFindingsDeleted,
		"model_reports_deleted":     result.ModelReportsDeleted,
		"auth_events_deleted":       result.AuthEventsDeleted,
	})
	return result, nil
}

func (r *HubMaintenanceRepository) pruneIngestEvents(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	const query = `
		DELETE FROM hub_ingest_events
		WHERE id IN (
			SELECT e.id
			FROM hub_ingest_events e
			WHERE e.created_at < $1
				-- Keep evidence for anything still actionable in the dashboard.
				AND NOT EXISTS (
					SELECT 1
					FROM hub_findings f
					WHERE f.status IN ('open', 'acknowledged')
						AND f.event_ids @> ARRAY[e.id::text]
				)
			ORDER BY e.created_at ASC
			LIMIT $2
		)
	`
	return r.deleteInBatches(ctx, query, cutoff, batchSize)
}

func (r *HubMaintenanceRepository) pruneEmptyIngestBatches(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	const query = `
		DELETE FROM hub_ingest_batches
		WHERE id IN (
			SELECT b.id
			FROM hub_ingest_batches b
			WHERE b.created_at < $1
				AND NOT EXISTS (
					SELECT 1
					FROM hub_ingest_events e
					WHERE e.batch_id = b.id
				)
			ORDER BY b.created_at ASC
			LIMIT $2
		)
	`
	return r.deleteInBatches(ctx, query, cutoff, batchSize)
}

func (r *HubMaintenanceRepository) pruneResolvedFindings(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	const query = `
		DELETE FROM hub_findings
		WHERE id IN (
			SELECT id
			FROM hub_findings
			WHERE status IN ('resolved', 'false_positive')
				AND severity NOT IN ('high', 'critical')
				AND created_at < $1
				AND updated_at < $1
				AND last_event_at < $1
			ORDER BY updated_at ASC
			LIMIT $2
		)
	`
	return r.deleteInBatches(ctx, query, cutoff, batchSize)
}

func (r *HubMaintenanceRepository) pruneModelReports(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	const query = `
		DELETE FROM hub_model_analysis_reports
		WHERE id IN (
			SELECT r.id
			FROM hub_model_analysis_reports r
			WHERE r.generated_at < $1
				AND NOT EXISTS (
					SELECT 1
					FROM hub_findings f
					WHERE f.status IN ('open', 'acknowledged')
						AND r.source_finding_ids @> ARRAY[f.id::text]
				)
			ORDER BY r.generated_at ASC
			LIMIT $2
		)
	`
	return r.deleteInBatches(ctx, query, cutoff, batchSize)
}

func (r *HubMaintenanceRepository) pruneAuthEvents(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	const query = `
		DELETE FROM hub_auth_events
		WHERE id IN (
			SELECT id
			FROM hub_auth_events
			WHERE created_at < $1
			ORDER BY created_at ASC
			LIMIT $2
		)
	`
	return r.deleteInBatches(ctx, query, cutoff, batchSize)
}

func (r *HubMaintenanceRepository) deleteInBatches(ctx context.Context, query string, cutoff time.Time, batchSize int) (int, error) {
	total := 0
	for {
		tag, err := r.pool.Exec(ctx, query, cutoff, batchSize)
		if err != nil {
			return total, err
		}
		affected := int(tag.RowsAffected())
		total += affected
		if affected < batchSize {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (r *HubMaintenanceRepository) GetHubSystemStatus(ctx context.Context) (domain.HubSystemStatus, error) {
	status := domain.HubSystemStatus{GeneratedAt: time.Now().UTC()}
	if err := r.pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&status.DatabaseSizeBytes); err != nil {
		return domain.HubSystemStatus{}, err
	}
	const query = `
		SELECT c.relname, greatest(c.reltuples::bigint, 0), pg_total_relation_size(c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
			AND c.relkind IN ('r', 'p')
			AND c.relname = ANY($1)
		ORDER BY pg_total_relation_size(c.oid) DESC, c.relname ASC
	`
	rows, err := r.pool.Query(ctx, query, []string{
		"hub_ingest_events",
		"hub_ingest_batches",
		"hub_findings",
		"hub_model_analysis_reports",
		"hub_auth_events",
		"hub_user_sessions",
	})
	if err != nil {
		return domain.HubSystemStatus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.HubSystemTableStats
		if err := rows.Scan(&item.Name, &item.Rows, &item.Bytes); err != nil {
			return domain.HubSystemStatus{}, err
		}
		status.Tables = append(status.Tables, item)
	}
	return status, rows.Err()
}
