package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

type HubPushSubscriptionRepository struct {
	pool *pgxpool.Pool
}

func NewHubPushSubscriptionRepository(pool *pgxpool.Pool) *HubPushSubscriptionRepository {
	return &HubPushSubscriptionRepository{pool: pool}
}

func (r *HubPushSubscriptionRepository) SaveHubPushSubscription(ctx context.Context, subscription domain.HubPushSubscription) (domain.HubPushSubscription, error) {
	query := `INSERT INTO hub_push_subscriptions (
			user_id, endpoint, p256dh, auth, user_agent, status, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, 'active', now())
		ON CONFLICT (endpoint) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			p256dh = EXCLUDED.p256dh,
			auth = EXCLUDED.auth,
			user_agent = EXCLUDED.user_agent,
			status = 'active',
			updated_at = now(),
			last_seen_at = now()
		RETURNING ` + hubPushSubscriptionColumns
	return scanHubPushSubscription(r.pool.QueryRow(ctx, query, subscription.UserID, subscription.Endpoint, subscription.P256DH, subscription.Auth, subscription.UserAgent))
}

func (r *HubPushSubscriptionRepository) ListActiveHubPushSubscriptions(ctx context.Context) ([]domain.HubPushSubscription, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+hubPushSubscriptionColumns+` FROM hub_push_subscriptions WHERE status = 'active' ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subscriptions []domain.HubPushSubscription
	for rows.Next() {
		subscription, err := scanHubPushSubscription(rows)
		if err != nil {
			return nil, err
		}
		subscriptions = append(subscriptions, subscription)
	}
	return subscriptions, rows.Err()
}

func (r *HubPushSubscriptionRepository) DisableHubPushSubscription(ctx context.Context, endpoint string) error {
	_, err := r.pool.Exec(ctx, `UPDATE hub_push_subscriptions SET status = 'disabled', updated_at = now() WHERE endpoint = $1`, endpoint)
	return err
}

func (r *HubPushSubscriptionRepository) DeleteHubPushSubscription(ctx context.Context, userID domain.ID, endpoint string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE hub_push_subscriptions SET status = 'disabled', updated_at = now() WHERE user_id = $1 AND endpoint = $2`, userID, endpoint)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

const hubPushSubscriptionColumns = `id::text, user_id::text, endpoint, p256dh, auth, user_agent, status, created_at, updated_at, last_seen_at`

type pushSubscriptionScanner interface {
	Scan(dest ...any) error
}

func scanHubPushSubscription(row pushSubscriptionScanner) (domain.HubPushSubscription, error) {
	var subscription domain.HubPushSubscription
	err := row.Scan(
		&subscription.ID,
		&subscription.UserID,
		&subscription.Endpoint,
		&subscription.P256DH,
		&subscription.Auth,
		&subscription.UserAgent,
		&subscription.Status,
		&subscription.CreatedAt,
		&subscription.UpdatedAt,
		&subscription.LastSeenAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.HubPushSubscription{}, err
	}
	return subscription, err
}
