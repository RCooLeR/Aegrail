package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

const findingNotificationErrorMaxLength = 4000

func NewHubFindingRepositoryWithNotificationTransports(pool *pgxpool.Pool, transports []string) *HubFindingRepository {
	repository := NewHubFindingRepository(pool)
	repository.notificationTransports = normalizedNotificationTransports(transports)
	return repository
}

func normalizedNotificationTransports(transports []string) []string {
	unique := make(map[string]struct{}, len(transports))
	for _, transport := range transports {
		transport = strings.TrimSpace(transport)
		if transport != "" {
			unique[transport] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for transport := range unique {
		result = append(result, transport)
	}
	sort.Strings(result)
	return result
}

func (r *HubFindingRepository) enqueueObservedFindingNotifications(ctx context.Context, tx pgx.Tx, findings []domain.HubFinding, source string) error {
	if len(r.notificationTransports) == 0 {
		return nil
	}
	const query = `
		INSERT INTO hub_finding_notification_outbox (
			finding_id,
			event_type,
			transport,
			payload,
			next_attempt_at
		)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (event_type, finding_id, transport) DO NOTHING
	`
	sentAt := time.Now().UTC()
	batch := &pgx.Batch{}
	for _, finding := range findings {
		if !postgresHubFindingSaveCreated(finding) || postgresFindingStatus(finding.Status) != "open" {
			continue
		}
		notificationFinding := finding
		notificationFinding.Metadata = cloneNotificationMetadata(finding.Metadata)
		delete(notificationFinding.Metadata, domain.HubFindingMetadataSaveCreated)
		payload, err := json.Marshal(ports.HubFindingNotification{
			Type:     "finding.observed",
			SentAt:   sentAt,
			Finding:  notificationFinding,
			Metadata: map[string]any{"source": strings.TrimSpace(source)},
		})
		if err != nil {
			return fmt.Errorf("marshal finding notification outbox payload: %w", err)
		}
		for _, transport := range r.notificationTransports {
			batch.Queue(query, finding.ID, "finding.observed", transport, payload, sentAt)
		}
	}
	if batch.Len() == 0 {
		return nil
	}
	results := tx.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		return fmt.Errorf("enqueue finding notification outbox: %w", err)
	}
	return nil
}

func postgresHubFindingSaveCreated(finding domain.HubFinding) bool {
	value, ok := finding.Metadata[domain.HubFindingMetadataSaveCreated]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true") || strings.TrimSpace(typed) == "1"
	default:
		return false
	}
}

func postgresFindingStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "open"
	}
	return status
}

func cloneNotificationMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(metadata))
	maps.Copy(cloned, metadata)
	return cloned
}

func (r *HubFindingRepository) ClaimHubFindingNotifications(ctx context.Context, options ports.HubFindingNotificationClaimOptions) ([]ports.HubFindingNotificationOutboxItem, error) {
	limit := options.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	leaseDuration := options.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = time.Minute
	}
	findingIDs := make([]string, 0, len(options.FindingIDs))
	for _, findingID := range options.FindingIDs {
		if strings.TrimSpace(string(findingID)) != "" {
			findingIDs = append(findingIDs, string(findingID))
		}
	}
	const query = `
		WITH candidates AS (
			SELECT id
			FROM hub_finding_notification_outbox
			WHERE delivered_at IS NULL
				AND next_attempt_at <= $1
				AND (leased_until IS NULL OR leased_until <= $1)
				AND (cardinality($4::uuid[]) = 0 OR finding_id = ANY($4::uuid[]))
			ORDER BY (transport <> 'email'), next_attempt_at, created_at, id
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		),
		claimed AS (
			UPDATE hub_finding_notification_outbox AS outbox
			SET attempt_count = outbox.attempt_count + 1,
				leased_until = $3,
				lease_token = gen_random_uuid(),
				updated_at = $1
			FROM candidates
			WHERE outbox.id = candidates.id
			RETURNING outbox.id, outbox.lease_token, outbox.transport,
				outbox.payload, outbox.attempt_count, outbox.created_at,
				outbox.next_attempt_at
		)
		SELECT id::text, lease_token::text, transport, payload,
			attempt_count, created_at
		FROM claimed
		ORDER BY (transport <> 'email'), next_attempt_at, created_at, id
	`
	rows, err := r.pool.Query(ctx, query, now, limit, now.Add(leaseDuration), findingIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ports.HubFindingNotificationOutboxItem, 0)
	for rows.Next() {
		var item ports.HubFindingNotificationOutboxItem
		var payload []byte
		if err := rows.Scan(
			&item.ID,
			&item.LeaseToken,
			&item.Transport,
			&payload,
			&item.AttemptCount,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &item.Notification); err != nil {
			return nil, fmt.Errorf("decode finding notification outbox payload %s: %w", item.ID, err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *HubFindingRepository) CompleteHubFindingNotification(ctx context.Context, itemID domain.ID, leaseToken domain.ID, deliveredAt time.Time) error {
	if deliveredAt.IsZero() {
		deliveredAt = time.Now().UTC()
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE hub_finding_notification_outbox
		SET delivered_at = $3,
			leased_until = NULL,
			lease_token = NULL,
			last_error = '',
			updated_at = $3
		WHERE id = $1
			AND lease_token = $2
			AND delivered_at IS NULL
	`, itemID, leaseToken, deliveredAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ports.ErrHubFindingNotificationLeaseLost
	}
	return nil
}

func (r *HubFindingRepository) RetryHubFindingNotification(ctx context.Context, itemID domain.ID, leaseToken domain.ID, nextAttemptAt time.Time, lastError string) error {
	if nextAttemptAt.IsZero() {
		nextAttemptAt = time.Now().UTC()
	}
	lastError = strings.TrimSpace(lastError)
	if len(lastError) > findingNotificationErrorMaxLength {
		lastError = strings.TrimSpace(lastError[:findingNotificationErrorMaxLength])
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE hub_finding_notification_outbox
		SET next_attempt_at = $3,
			leased_until = NULL,
			lease_token = NULL,
			last_error = $4,
			updated_at = now()
		WHERE id = $1
			AND lease_token = $2
			AND delivered_at IS NULL
	`, itemID, leaseToken, nextAttemptAt.UTC(), lastError)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ports.ErrHubFindingNotificationLeaseLost
	}
	return nil
}
