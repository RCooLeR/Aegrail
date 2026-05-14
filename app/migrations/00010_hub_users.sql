-- +goose Up
CREATE TABLE hub_users (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	email text NOT NULL,
	display_name text NOT NULL DEFAULT '',
	access_level text NOT NULL DEFAULT 'viewer',
	status text NOT NULL DEFAULT 'active',
	two_factor_required boolean NOT NULL DEFAULT true,
	two_factor_enabled boolean NOT NULL DEFAULT false,
	totp_secret_ciphertext text NOT NULL DEFAULT '',
	totp_enrolled_at timestamptz,
	last_login_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_users_email_present CHECK (length(trim(email)) > 0),
	CONSTRAINT hub_users_access_level_shape CHECK (access_level IN ('owner', 'admin', 'operator', 'viewer')),
	CONSTRAINT hub_users_status_shape CHECK (status IN ('active', 'invited', 'disabled'))
);

CREATE UNIQUE INDEX hub_users_email_lower_idx ON hub_users (lower(email));
CREATE INDEX hub_users_access_level_idx ON hub_users (access_level);
CREATE INDEX hub_users_status_idx ON hub_users (status);
CREATE INDEX hub_users_two_factor_idx ON hub_users (two_factor_required, two_factor_enabled);

-- +goose Down
DROP INDEX IF EXISTS hub_users_two_factor_idx;
DROP INDEX IF EXISTS hub_users_status_idx;
DROP INDEX IF EXISTS hub_users_access_level_idx;
DROP INDEX IF EXISTS hub_users_email_lower_idx;
DROP TABLE IF EXISTS hub_users;
