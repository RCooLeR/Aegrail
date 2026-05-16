-- +goose Up
ALTER TABLE hub_users
	ADD COLUMN pending_totp_secret_ciphertext text NOT NULL DEFAULT '',
	ADD COLUMN pending_totp_started_at timestamptz;

-- +goose Down
ALTER TABLE hub_users
	DROP COLUMN IF EXISTS pending_totp_started_at,
	DROP COLUMN IF EXISTS pending_totp_secret_ciphertext;
