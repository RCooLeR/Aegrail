package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
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
		ON CONFLICT (agent_id, external_id) DO NOTHING
		RETURNING id::text, external_id, organization_id::text, project_id::text,
			environment_id::text, coalesce(app_id::text, ''), coalesce(service_id::text, ''),
			host_id::text, agent_id::text, source, body_sha256, signature, status,
			event_count, received_at, metadata, created_at
	`

	var savedBatch domain.IngestBatch
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
	)
	if errors.Is(err, pgx.ErrNoRows) {
		existingBatch, existingEvents, err := r.findIngestBatch(ctx, tx, batch.AgentID, batch.ExternalID)
		if err != nil {
			return domain.IngestBatch{}, nil, false, err
		}
		if err := touchIngestAgentLastSeen(ctx, tx, existingBatch.AgentID, batch.ReceivedAt); err != nil {
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

	savedEvents := make([]domain.IngestEvent, 0, len(events))
	if len(events) > 0 {
		createdAt := time.Now().UTC()
		const insertEvent = `
			INSERT INTO hub_ingest_events (
				id,
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
				payload,
				created_at
			)
			VALUES (
				$1::uuid, $2::uuid, $3::uuid, $4::uuid,
				$5::uuid,
				nullif($6::text, '')::uuid,
				nullif($7::text, '')::uuid,
				$8::uuid, $9::uuid, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
			)
		`
		eventBatch := &pgx.Batch{}
		for _, event := range events {
			eventID, err := newUUIDString()
			if err != nil {
				return domain.IngestBatch{}, nil, false, err
			}
			event.ID = domain.ID(eventID)
			event.BatchID = savedBatch.ID
			event.CreatedAt = createdAt
			savedEvents = append(savedEvents, event)
			eventBatch.Queue(
				insertEvent,
				event.ID,
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
				event.CreatedAt,
			)
		}
		results := tx.SendBatch(ctx, eventBatch)
		var insertErr error
		for index := range savedEvents {
			if _, err := results.Exec(); err != nil && insertErr == nil {
				insertErr = fmt.Errorf("insert ingest event %d: %w", index, err)
			}
		}
		if err := results.Close(); insertErr == nil && err != nil {
			insertErr = err
		}
		if insertErr != nil {
			return domain.IngestBatch{}, nil, false, insertErr
		}
	}

	if err := touchIngestAgentLastSeen(ctx, tx, savedBatch.AgentID, savedBatch.ReceivedAt); err != nil {
		return domain.IngestBatch{}, nil, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.IngestBatch{}, nil, false, err
	}
	return savedBatch, savedEvents, true, nil
}

func touchIngestAgentLastSeen(ctx context.Context, tx pgx.Tx, agentID domain.ID, seenAt time.Time) error {
	const updateAgentLastSeen = `
		UPDATE agents
		SET last_seen_at = $2::timestamptz,
			updated_at = $2::timestamptz
		WHERE id = $1
			AND (last_seen_at IS NULL OR last_seen_at < $2::timestamptz - interval '15 seconds')
	`
	_, err := tx.Exec(ctx, updateAgentLastSeen, agentID, seenAt)
	return err
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
	const environmentQuery = `
		SELECT e.id::text, e.environment_id::text, coalesce(e.app_id::text, ''),
			e.host_id::text, e.agent_id::text, h.slug::text, h.hostname,
			a.agent_id::text, e.event_time, e.event_type, e.target, e.severity,
			e.payload
		FROM hub_ingest_events e
		INNER JOIN hosts h ON h.id = e.host_id
		INNER JOIN agents a ON a.id = e.agent_id
		WHERE e.environment_id = $1
			AND e.event_time >= $2
			AND e.event_type IN ('file.created', 'file.modified', 'file.deleted')
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $3
	`
	const appQuery = `
		SELECT e.id::text, e.environment_id::text, coalesce(e.app_id::text, ''),
			e.host_id::text, e.agent_id::text, h.slug::text, h.hostname,
			a.agent_id::text, e.event_time, e.event_type, e.target, e.severity,
			e.payload
		FROM hub_ingest_events e
		INNER JOIN hosts h ON h.id = e.host_id
		INNER JOIN agents a ON a.id = e.agent_id
		WHERE e.environment_id = $1
			AND e.app_id = $2::uuid
			AND e.event_time >= $3
			AND e.event_type IN ('file.created', 'file.modified', 'file.deleted')
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $4
	`
	query := environmentQuery
	args := []any{environmentID, since.UTC(), limit}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), since.UTC(), limit}
	}
	rows, err := r.pool.Query(ctx, query, args...)
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
	const environmentQuery = `
		WITH recent_events AS (
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
			AND e.event_time >= $2
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $3
		)
		SELECT * FROM recent_events
		ORDER BY event_time ASC, created_at ASC
	`
	const appQuery = `
		WITH recent_events AS (
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
			AND e.app_id = $2::uuid
			AND e.event_time >= $3
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $4
		)
		SELECT * FROM recent_events
		ORDER BY event_time ASC, created_at ASC
	`
	query := environmentQuery
	args := []any{environmentID, since.UTC(), limit}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), since.UTC(), limit}
	}
	rows, err := r.pool.Query(ctx, query, args...)
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

func (r *IngestRepository) ListCorrelationTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	const correlationPredicate = `
		AND (
			e.event_type LIKE 'db.%'
			OR e.event_type IN ('file.created', 'file.modified', 'file.deleted', 'log.php_error')
			OR (
				e.event_type = 'log.access'
				AND (
					lower(coalesce(e.payload->>'remote_network', '')) = 'tor_exit'
					OR lower(coalesce(e.payload->>'remote_is_tor', '')) IN ('true', '1', 'yes')
					OR (coalesce(e.payload->>'status_code', '') ~ '^[0-9]+$' AND (e.payload->>'status_code')::int >= 400)
					OR lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%admin%'
					OR lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%login%'
					OR lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%password%'
					OR lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%reset%'
					OR (
						upper(coalesce(e.payload->>'method', '')) = 'POST'
						AND (
							lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%login%'
							OR lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%password%'
							OR lower(coalesce(e.payload->>'path', e.target, '')) LIKE '%reset%'
						)
					)
				)
			)
		)
	`
	environmentQuery := `
		WITH recent_events AS (
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
			AND e.event_time >= $2
	` + correlationPredicate + `
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $3
		)
		SELECT * FROM recent_events
		ORDER BY event_time ASC, created_at ASC
	`
	appQuery := `
		WITH recent_events AS (
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
			AND e.app_id = $2::uuid
			AND e.event_time >= $3
	` + correlationPredicate + `
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $4
		)
		SELECT * FROM recent_events
		ORDER BY event_time ASC, created_at ASC
	`
	query := environmentQuery
	args := []any{environmentID, since.UTC(), limit}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), since.UTC(), limit}
	}
	rows, err := r.pool.Query(ctx, query, args...)
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

func (r *IngestRepository) ListTimelineEventsByTypes(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, eventTypes []string, limit int) ([]domain.TimelineEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	types := make([]string, 0, len(eventTypes))
	seen := map[string]struct{}{}
	for _, eventType := range eventTypes {
		eventType = strings.TrimSpace(eventType)
		if eventType == "" {
			continue
		}
		if _, ok := seen[eventType]; ok {
			continue
		}
		seen[eventType] = struct{}{}
		types = append(types, eventType)
	}
	if len(types) == 0 {
		return []domain.TimelineEvent{}, nil
	}
	const environmentQuery = `
		WITH recent_events AS (
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
			AND e.event_time >= $2
			AND e.event_type = ANY($3::text[])
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $4
		)
		SELECT * FROM recent_events
		ORDER BY event_time ASC, created_at ASC
	`
	const appQuery = `
		WITH recent_events AS (
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
			AND e.app_id = $2::uuid
			AND e.event_time >= $3
			AND e.event_type = ANY($4::text[])
		ORDER BY e.event_time DESC, e.created_at DESC
		LIMIT $5
		)
		SELECT * FROM recent_events
		ORDER BY event_time ASC, created_at ASC
	`
	query := environmentQuery
	args := []any{environmentID, since.UTC(), types, limit}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), since.UTC(), types, limit}
	}
	rows, err := r.pool.Query(ctx, query, args...)
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

func (r *IngestRepository) ListTimelineEventsByID(ctx context.Context, environmentID domain.ID, appID domain.ID, eventIDs []domain.ID) ([]domain.TimelineEvent, error) {
	if len(eventIDs) == 0 {
		return []domain.TimelineEvent{}, nil
	}
	if len(eventIDs) > 200 {
		eventIDs = eventIDs[:200]
	}
	values := make([]string, 0, len(eventIDs))
	seen := map[string]struct{}{}
	for _, eventID := range eventIDs {
		value := strings.TrimSpace(string(eventID))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	if len(values) == 0 {
		return []domain.TimelineEvent{}, nil
	}
	const environmentQuery = `
		WITH requested AS (
			SELECT value AS id, ord
			FROM unnest($2::text[]) WITH ORDINALITY AS input(value, ord)
		)
		SELECT e.id::text, e.batch_id::text, e.organization_id::text, e.project_id::text,
			e.environment_id::text, coalesce(e.app_id::text, ''), coalesce(ma.slug::text, ''),
			coalesce(e.service_id::text, ''), coalesce(s.slug::text, ''),
			e.host_id::text, h.slug::text, h.hostname, e.agent_id::text, a.agent_id::text,
			e.event_time, e.received_at, e.event_type, e.target, e.severity, e.message,
			e.region, e.labels, e.payload, e.created_at
		FROM requested
		INNER JOIN hub_ingest_events e ON e.id::text = requested.id
		LEFT JOIN monitored_apps ma ON ma.id = e.app_id
		LEFT JOIN services s ON s.id = e.service_id
		INNER JOIN hosts h ON h.id = e.host_id
		INNER JOIN agents a ON a.id = e.agent_id
		WHERE e.environment_id = $1
		ORDER BY requested.ord ASC
	`
	const appQuery = `
		WITH requested AS (
			SELECT value AS id, ord
			FROM unnest($3::text[]) WITH ORDINALITY AS input(value, ord)
		)
		SELECT e.id::text, e.batch_id::text, e.organization_id::text, e.project_id::text,
			e.environment_id::text, coalesce(e.app_id::text, ''), coalesce(ma.slug::text, ''),
			coalesce(e.service_id::text, ''), coalesce(s.slug::text, ''),
			e.host_id::text, h.slug::text, h.hostname, e.agent_id::text, a.agent_id::text,
			e.event_time, e.received_at, e.event_type, e.target, e.severity, e.message,
			e.region, e.labels, e.payload, e.created_at
		FROM requested
		INNER JOIN hub_ingest_events e ON e.id::text = requested.id
		LEFT JOIN monitored_apps ma ON ma.id = e.app_id
		LEFT JOIN services s ON s.id = e.service_id
		INNER JOIN hosts h ON h.id = e.host_id
		INNER JOIN agents a ON a.id = e.agent_id
		WHERE e.environment_id = $1
			AND e.app_id = $2::uuid
		ORDER BY requested.ord ASC
	`
	query := environmentQuery
	args := []any{environmentID, values}
	if strings.TrimSpace(string(appID)) != "" {
		query = appQuery
		args = []any{environmentID, string(appID), values}
	}
	rows, err := r.pool.Query(ctx, query, args...)
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

func newUUIDString() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80

	var out [36]byte
	hex.Encode(out[0:8], raw[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], raw[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], raw[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], raw[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], raw[10:16])
	return string(out[:]), nil
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
