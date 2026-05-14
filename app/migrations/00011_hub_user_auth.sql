-- +goose Up
ALTER TABLE hub_users
	ADD COLUMN password_hash text NOT NULL DEFAULT '',
	ADD COLUMN password_set_at timestamptz;

CREATE TABLE hub_user_sessions (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id uuid NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
	token_hash text NOT NULL,
	expires_at timestamptz NOT NULL,
	revoked_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_user_sessions_token_hash_present CHECK (length(trim(token_hash)) > 0)
);

CREATE UNIQUE INDEX hub_user_sessions_token_hash_idx ON hub_user_sessions (token_hash);
CREATE INDEX hub_user_sessions_user_id_idx ON hub_user_sessions (user_id);
CREATE INDEX hub_user_sessions_active_idx ON hub_user_sessions (expires_at) WHERE revoked_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS hub_user_sessions_active_idx;
DROP INDEX IF EXISTS hub_user_sessions_user_id_idx;
DROP INDEX IF EXISTS hub_user_sessions_token_hash_idx;
DROP TABLE IF EXISTS hub_user_sessions;

ALTER TABLE hub_users
	DROP COLUMN IF EXISTS password_set_at,
	DROP COLUMN IF EXISTS password_hash;
