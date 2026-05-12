package postgres

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

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

func (r *IngestRepository) ListFileStateObservations(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.FileStateObservation, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	const query = `
		SELECT e.id::text, e.environment_id::text, coalesce(e.app_id::text, ''),
			e.host_id::text, e.agent_id::text, h.slug::text, h.hostname,
			a.agent_id::text, e.event_time, e.event_type, e.target, e.severity,
			e.payload
		FROM hub_ingest_events e
		INNER JOIN hosts h ON h.id = e.host_id
		INNER JOIN agents a ON a.id = e.agent_id
		WHERE e.environment_id = $1
			AND ($2::text = '' OR e.app_id = nullif($2::text, '')::uuid)
			AND e.event_time >= $3
			AND e.event_type IN ('file.created', 'file.modified', 'file.deleted')
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $4
	`
	rows, err := r.pool.Query(ctx, query, environmentID, string(appID), since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []domain.FileStateObservation
	for rows.Next() {
		var item domain.FileStateObservation
		var payload map[string]any
		if err := rows.Scan(
			&item.EventID,
			&item.EnvironmentID,
			&item.AppID,
			&item.HostID,
			&item.AgentID,
			&item.HostSlug,
			&item.Hostname,
			&item.AgentExternalID,
			&item.EventTime,
			&item.EventType,
			&item.Target,
			&item.Severity,
			&payload,
		); err != nil {
			return nil, err
		}
		item.Path = payloadString(payload, "path", item.Target)
		item.RelativePath = normalizedRelativePath(payloadString(payload, "relative_path", ""))
		if item.RelativePath == "" {
			item.RelativePath = normalizedRelativePath(item.Path)
		}
		item.SHA256 = payloadString(payload, "sha256", "")
		item.PreviousSHA256 = payloadString(payload, "previous_sha256", "")
		item.SizeBytes = payloadInt64(payload, "size_bytes")
		item.HashSkipped = payloadBool(payload, "hash_skipped")
		item.Deleted = item.EventType == "file.deleted"
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *IngestRepository) ListTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	const query = `
		SELECT e.id::text, e.batch_id::text, e.organization_id::text, e.project_id::text,
			e.environment_id::text, coalesce(e.app_id::text, ''), coalesce(ma.slug::text, ''),
			coalesce(e.service_id::text, ''), coalesce(s.slug::text, ''),
			e.host_id::text, h.slug::text, h.hostname, e.agent_id::text, a.agent_id::text,
			e.event_time, e.received_at, e.event_type, e.target, e.severity, e.message,
			e.region, e.labels, e.payload, e.created_at
		FROM hub_ingest_events e
		LEFT JOIN monitored_apps ma ON ma.id = e.app_id
		LEFT JOIN services s ON s.id = e.service_id
		INNER JOIN hosts h ON h.id = e.host_id
		INNER JOIN agents a ON a.id = e.agent_id
		WHERE e.environment_id = $1
			AND ($2::text = '' OR e.app_id = nullif($2::text, '')::uuid)
			AND e.event_time >= $3
		ORDER BY e.event_time ASC, e.created_at ASC
		LIMIT $4
	`
	rows, err := r.pool.Query(ctx, query, environmentID, string(appID), since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []domain.TimelineEvent
	for rows.Next() {
		var item domain.TimelineEvent
		if err := rows.Scan(
			&item.ID,
			&item.BatchID,
			&item.OrganizationID,
			&item.ProjectID,
			&item.EnvironmentID,
			&item.AppID,
			&item.AppSlug,
			&item.ServiceID,
			&item.ServiceSlug,
			&item.HostID,
			&item.HostSlug,
			&item.Hostname,
			&item.AgentID,
			&item.AgentExternalID,
			&item.EventTime,
			&item.ReceivedAt,
			&item.EventType,
			&item.Target,
			&item.Severity,
			&item.Message,
			&item.Region,
			&item.Labels,
			&item.Payload,
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

func payloadString(payload map[string]any, key string, fallback string) string {
	if payload == nil {
		return fallback
	}
	value, ok := payload[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return fallback
		}
		return typed
	default:
		return fallback
	}
}

func payloadInt64(payload map[string]any, key string) int64 {
	if payload == nil {
		return 0
	}
	value := payload[key]
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return 0
		}
		return int64(typed)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err == nil {
			return parsed
		}
	case jsonNumber:
		parsed, err := typed.Int64()
		if err == nil {
			return parsed
		}
	}
	return 0
}

func payloadBool(payload map[string]any, key string) bool {
	if payload == nil {
		return false
	}
	value, ok := payload[key].(bool)
	return ok && value
}

func normalizedRelativePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.TrimLeft(strings.ReplaceAll(value, "\\", "/"), "/")
}

type jsonNumber interface {
	Int64() (int64, error)
}
