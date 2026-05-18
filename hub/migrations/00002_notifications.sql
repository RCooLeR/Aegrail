-- +goose Up
CREATE TABLE IF NOT EXISTS hub_push_subscriptions (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id uuid NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
	endpoint text NOT NULL,
	p256dh text NOT NULL,
	auth text NOT NULL,
	user_agent text NOT NULL DEFAULT '',
	status text NOT NULL DEFAULT 'active',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_push_subscriptions_endpoint_present CHECK (length(trim(endpoint)) > 0),
	CONSTRAINT hub_push_subscriptions_keys_present CHECK (length(trim(p256dh)) > 0 AND length(trim(auth)) > 0),
	CONSTRAINT hub_push_subscriptions_status_shape CHECK (status IN ('active', 'disabled'))
);

CREATE UNIQUE INDEX IF NOT EXISTS hub_push_subscriptions_endpoint_idx ON hub_push_subscriptions (endpoint);
CREATE INDEX IF NOT EXISTS hub_push_subscriptions_user_status_idx ON hub_push_subscriptions (user_id, status);

-- +goose Down
DROP TABLE IF EXISTS hub_push_subscriptions;
