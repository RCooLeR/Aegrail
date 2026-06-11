-- +goose Up
ALTER TABLE hub_users
	ADD COLUMN IF NOT EXISTS failed_login_attempts integer NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS locked_until timestamptz;

CREATE TABLE IF NOT EXISTS hub_auth_events (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id uuid REFERENCES hub_users(id) ON DELETE SET NULL,
	email_normalized text NOT NULL DEFAULT '',
	event text NOT NULL,
	remote_ip inet,
	user_agent text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_auth_events_event_shape CHECK (
		event IN (
			'login_success',
			'login_failure',
			'logout',
			'totp_failure',
			'lockout',
			'password_change',
			'session_revoked'
		)
	)
);

CREATE TABLE IF NOT EXISTS hub_maintenance_runs (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	kind text NOT NULL,
	started_at timestamptz NOT NULL,
	finished_at timestamptz NOT NULL,
	result jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_maintenance_runs_kind_present CHECK (length(trim(kind)) > 0)
);

CREATE INDEX IF NOT EXISTS hub_users_locked_until_idx ON hub_users (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS hub_auth_events_created_idx ON hub_auth_events (created_at DESC);
CREATE INDEX IF NOT EXISTS hub_auth_events_email_created_idx ON hub_auth_events (lower(email_normalized), created_at DESC);
CREATE INDEX IF NOT EXISTS hub_auth_events_user_created_idx ON hub_auth_events (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS hub_maintenance_runs_kind_finished_idx ON hub_maintenance_runs (kind, finished_at DESC);

-- +goose Down
DROP INDEX IF EXISTS hub_maintenance_runs_kind_finished_idx;
DROP INDEX IF EXISTS hub_auth_events_user_created_idx;
DROP INDEX IF EXISTS hub_auth_events_email_created_idx;
DROP INDEX IF EXISTS hub_auth_events_created_idx;
DROP INDEX IF EXISTS hub_users_locked_until_idx;
DROP TABLE IF EXISTS hub_maintenance_runs;
DROP TABLE IF EXISTS hub_auth_events;
ALTER TABLE hub_users
	DROP COLUMN IF EXISTS locked_until,
	DROP COLUMN IF EXISTS failed_login_attempts;
