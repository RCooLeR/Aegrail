package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
)

type IngestRepository struct {
	pool *pgxpool.Pool
}

func NewIngestRepository(pool *pgxpool.Pool) *IngestRepository {
	return &IngestRepository{pool: pool}
}

func (r *IngestRepository) SaveIngestBatch(ctx context.Context, batch domain.IngestBatch, events []domain.IngestEvent) (domain.IngestBatch, []domain.IngestEvent, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.IngestBatch{}, nil, false, err
	}
	defer tx.Rollback(ctx)

	const insertBatch = `
		INSERT INTO hub_ingest_batches (
			external_id,
			organization_id,
			project_id,
			environment_id,
			app_id,
			service_id,
			host_id,
			agent_id,
			source,
			body_sha256,
			signature,
			status,
			event_count,
			received_at,
			metadata
		)
		VALUES (
			$1, $2, $3, $4,
			nullif($5::text, '')::uuid,
			nullif($6::text, '')::uuid,
			$7, $8, $9, $10, $11, $12, $13, $14, $15
		)
		ON CONFLICT (agent_id, external_id) DO UPDATE
		SET external_id = hub_ingest_batches.external_id
		RETURNING id::text, external_id, organization_id::text, project_id::text,
			environment_id::text, coalesce(app_id::text, ''), coalesce(service_id::text, ''),
			host_id::text, agent_id::text, source, body_sha256, signature, status,
			event_count, received_at, metadata, created_at, (xmax = 0) AS created
	`

	var savedBatch domain.IngestBatch
	var created bool
	err = tx.QueryRow(
		ctx,
		insertBatch,
		batch.ExternalID,
		batch.OrganizationID,
		batch.ProjectID,
		batch.EnvironmentID,
		string(batch.AppID),
		string(batch.ServiceID),
		batch.HostID,
		batch.AgentID,
		batch.Source,
		batch.BodySHA256,
		batch.Signature,
		batch.Status,
		len(events),
		batch.ReceivedAt,
		nonNilAnyMap(batch.Metadata),
	).Scan(
		&savedBatch.ID,
		&savedBatch.ExternalID,
		&savedBatch.OrganizationID,
		&savedBatch.ProjectID,
		&savedBatch.EnvironmentID,
		&savedBatch.AppID,
		&savedBatch.ServiceID,
		&savedBatch.HostID,
		&savedBatch.AgentID,
		&savedBatch.Source,
		&savedBatch.BodySHA256,
		&savedBatch.Signature,
		&savedBatch.Status,
		&savedBatch.EventCount,
		&savedBatch.ReceivedAt,
		&savedBatch.Metadata,
		&savedBatch.CreatedAt,
		&created,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		existingBatch, existingEvents, err := r.findIngestBatch(ctx, tx, batch.AgentID, batch.ExternalID)
		if err != nil {
			return domain.IngestBatch{}, nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.IngestBatch{}, nil, false, err
		}
		return existingBatch, existingEvents, false, nil
	}
	if err != nil {
		return domain.IngestBatch{}, nil, false, err
	}
	if !created {
		existingBatch, existingEvents, err := r.findIngestBatch(ctx, tx, batch.AgentID, batch.ExternalID)
		if err != nil {
			return domain.IngestBatch{}, nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.IngestBatch{}, nil, false, err
		}
		return existingBatch, existingEvents, false, nil
	}

	savedEvents := make([]domain.IngestEvent, 0, len(events))
	for _, event := range events {
		event.BatchID = savedBatch.ID
		const insertEvent = `
			INSERT INTO hub_ingest_events (
				batch_id,
				organization_id,
				project_id,
				environment_id,
				app_id,
				service_id,
				host_id,
				agent_id,
				event_time,
				received_at,
				event_type,
				target,
				severity,
				message,
				region,
				labels,
				payload
			)
			VALUES (
				$1, $2, $3, $4,
				nullif($5::text, '')::uuid,
				nullif($6::text, '')::uuid,
				$7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
			)
			RETURNING id::text, batch_id::text, organization_id::text, project_id::text,
				environment_id::text, coalesce(app_id::text, ''), coalesce(service_id::text, ''),
				host_id::text, agent_id::text, event_time, received_at, event_type,
				target, severity, message, region, labels, payload, created_at
		`
		var savedEvent domain.IngestEvent
		if err := tx.QueryRow(
			ctx,
			insertEvent,
			event.BatchID,
			event.OrganizationID,
			event.ProjectID,
			event.EnvironmentID,
			string(event.AppID),
			string(event.ServiceID),
			event.HostID,
			event.AgentID,
			event.EventTime,
			event.ReceivedAt,
			event.EventType,
			event.Target,
			string(event.Severity),
			event.Message,
			event.Region,
			nonNilStringMap(event.Labels),
			nonNilAnyMap(event.Payload),
		).Scan(
			&savedEvent.ID,
			&savedEvent.BatchID,
			&savedEvent.OrganizationID,
			&savedEvent.ProjectID,
			&savedEvent.EnvironmentID,
			&savedEvent.AppID,
			&savedEvent.ServiceID,
			&savedEvent.HostID,
			&savedEvent.AgentID,
			&savedEvent.EventTime,
			&savedEvent.ReceivedAt,
			&savedEvent.EventType,
			&savedEvent.Target,
			&savedEvent.Severity,
			&savedEvent.Message,
			&savedEvent.Region,
			&savedEvent.Labels,
			&savedEvent.Payload,
			&savedEvent.CreatedAt,
		); err != nil {
			return domain.IngestBatch{}, nil, false, err
		}
		savedEvents = append(savedEvents, savedEvent)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.IngestBatch{}, nil, false, err
	}
	return savedBatch, savedEvents, true, nil
}

func (r *IngestRepository) ListIngestBatches(ctx context.Context, environmentID domain.ID, limit int) ([]domain.IngestBatch, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	const query = `
		SELECT id::text, external_id, organization_id::text, project_id::text,
			environment_id::text, coalesce(app_id::text, ''), coalesce(service_id::text, ''),
			host_id::text, agent_id::text, source, body_sha256, signature, status,
			event_count, received_at, metadata, created_at
		FROM hub_ingest_batches
		WHERE environment_id = $1
		ORDER BY received_at DESC
		LIMIT $2
	`
	rows, err := r.pool.Query(ctx, query, environmentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []domain.IngestBatch
	for rows.Next() {
		var item domain.IngestBatch
		if err := rows.Scan(
			&item.ID,
			&item.ExternalID,
			&item.OrganizationID,
			&item.ProjectID,
			&item.EnvironmentID,
			&item.AppID,
			&item.ServiceID,
			&item.HostID,
			&item.AgentID,
			&item.Source,
			&item.BodySHA256,
			&item.Signature,
			&item.Status,
			&item.EventCount,
			&item.ReceivedAt,
			&item.Metadata,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (r *IngestRepository) findIngestBatch(ctx context.Context, q queryer, agentID domain.ID, externalID string) (domain.IngestBatch, []domain.IngestEvent, error) {
	const batchQuery = `
		SELECT id::text, external_id, organization_id::text, project_id::text,
			environment_id::text, coalesce(app_id::text, ''), coalesce(service_id::text, ''),
			host_id::text, agent_id::text, source, body_sha256, signature, status,
			event_count, received_at, metadata, created_at
		FROM hub_ingest_batches
		WHERE agent_id = $1 AND external_id = $2
	`
	var batch domain.IngestBatch
	if err := q.QueryRow(ctx, batchQuery, agentID, externalID).Scan(
		&batch.ID,
		&batch.ExternalID,
		&batch.OrganizationID,
		&batch.ProjectID,
		&batch.EnvironmentID,
		&batch.AppID,
		&batch.ServiceID,
		&batch.HostID,
		&batch.AgentID,
		&batch.Source,
		&batch.BodySHA256,
		&batch.Signature,
		&batch.Status,
		&batch.EventCount,
		&batch.ReceivedAt,
		&batch.Metadata,
		&batch.CreatedAt,
	); err != nil {
		return domain.IngestBatch{}, nil, err
	}

	const eventsQuery = `
		SELECT id::text, batch_id::text, organization_id::text, project_id::text,
			environment_id::text, coalesce(app_id::text, ''), coalesce(service_id::text, ''),
			host_id::text, agent_id::text, event_time, received_at, event_type,
			target, severity, message, region, labels, payload, created_at
		FROM hub_ingest_events
		WHERE batch_id = $1
		ORDER BY event_time ASC, created_at ASC
	`
	rows, err := q.Query(ctx, eventsQuery, batch.ID)
	if err != nil {
		return domain.IngestBatch{}, nil, err
	}
	defer rows.Close()

	var events []domain.IngestEvent
	for rows.Next() {
		var event domain.IngestEvent
		if err := rows.Scan(
			&event.ID,
			&event.BatchID,
			&event.OrganizationID,
			&event.ProjectID,
			&event.EnvironmentID,
			&event.AppID,
			&event.ServiceID,
			&event.HostID,
			&event.AgentID,
			&event.EventTime,
			&event.ReceivedAt,
			&event.EventType,
			&event.Target,
			&event.Severity,
			&event.Message,
			&event.Region,
			&event.Labels,
			&event.Payload,
			&event.CreatedAt,
		); err != nil {
			return domain.IngestBatch{}, nil, err
		}
		events = append(events, event)
	}
	return batch, events, rows.Err()
}

func nonNilStringMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}

func nonNilAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return map[string]any{}
	}
	return values
}
