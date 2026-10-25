package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const (
	maximumTrafficBackfillBatchSize = 1000
	maximumTrafficBackfillWindow    = 30 * 24 * time.Hour
)

// BackfillRecentTrafficBatch projects one bounded batch of legacy log.access
// rows. The NOT EXISTS predicate makes the operation idempotent; callers can
// yield between calls and continue until this returns zero.
func (r *TrafficRepository) BackfillRecentTrafficBatch(ctx context.Context, since time.Time, until time.Time, limit int) (int, error) {
	if r == nil || r.pool == nil {
		return 0, errors.New("traffic repository is not configured")
	}
	since, until, limit, err := normalizeTrafficBackfillBatch(since, until, limit)
	if err != nil {
		return 0, err
	}

	// Emergency pending-migration mode may start a binary before migration
	// 00009 exists. Treat that as no backfill work instead of turning the
	// optional background upgrade task into a startup/runtime failure loop.
	var projectionTableAvailable bool
	if err := r.pool.QueryRow(ctx, `SELECT to_regclass('hub_access_requests') IS NOT NULL`).Scan(&projectionTableAvailable); err != nil {
		return 0, err
	}
	if !projectionTableAvailable {
		return 0, nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	const query = `
		SELECT e.id::text, e.organization_id::text, e.project_id::text,
			e.environment_id::text, coalesce(e.app_id::text, ''),
			coalesce(e.service_id::text, ''), e.host_id::text,
			e.agent_id::text, e.event_time, e.event_type,
			e.payload, e.created_at
		FROM hub_ingest_events e
		WHERE e.event_type = 'log.access'
			AND e.event_time >= $1 AND e.event_time < $2
			AND NOT EXISTS (
				SELECT 1 FROM hub_access_requests request WHERE request.event_id = e.id
			)
		ORDER BY e.event_time DESC, e.created_at DESC, e.id DESC
		LIMIT $3
		FOR UPDATE OF e SKIP LOCKED
	`
	rows, err := tx.Query(ctx, query, since, until, limit)
	if err != nil {
		return 0, err
	}
	events := make([]domain.IngestEvent, 0, limit)
	for rows.Next() {
		var event domain.IngestEvent
		if err := rows.Scan(
			&event.ID,
			&event.OrganizationID,
			&event.ProjectID,
			&event.EnvironmentID,
			&event.AppID,
			&event.ServiceID,
			&event.HostID,
			&event.AgentID,
			&event.EventTime,
			&event.EventType,
			&event.Payload,
			&event.CreatedAt,
		); err != nil {
			rows.Close()
			return 0, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	if err := projectTrafficRequests(ctx, tx, events); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(events), nil
}

func normalizeTrafficBackfillBatch(since time.Time, until time.Time, limit int) (time.Time, time.Time, int, error) {
	since = since.UTC()
	until = until.UTC()
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return time.Time{}, time.Time{}, 0, errors.New("traffic backfill requires a valid time window")
	}
	if until.Sub(since) > maximumTrafficBackfillWindow {
		return time.Time{}, time.Time{}, 0, errors.New("traffic backfill window must not exceed 30 days")
	}
	if limit <= 0 {
		limit = maximumTrafficBackfillBatchSize
	}
	if limit > maximumTrafficBackfillBatchSize {
		limit = maximumTrafficBackfillBatchSize
	}
	return since, until, limit, nil
}
