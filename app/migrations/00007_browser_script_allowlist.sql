-- +goose Up
CREATE TABLE hub_browser_script_allowlist (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid NOT NULL REFERENCES monitored_apps(id) ON DELETE CASCADE,
	page_url text NOT NULL DEFAULT '',
	kind text NOT NULL,
	value text NOT NULL,
	reason text NOT NULL DEFAULT '',
	approved_by text NOT NULL DEFAULT '',
	status text NOT NULL DEFAULT 'active',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (environment_id, app_id, page_url, kind, value),
	CONSTRAINT hub_browser_script_allowlist_kind_shape CHECK (kind IN ('domain', 'inline_hash', 'tag_manager_id')),
	CONSTRAINT hub_browser_script_allowlist_value_present CHECK (length(trim(value)) > 0),
	CONSTRAINT hub_browser_script_allowlist_status_shape CHECK (status IN ('active', 'disabled'))
);

CREATE INDEX hub_browser_script_allowlist_environment_idx ON hub_browser_script_allowlist (environment_id, app_id, kind);
CREATE INDEX hub_browser_script_allowlist_status_idx ON hub_browser_script_allowlist (status);

-- +goose Down
DROP INDEX IF EXISTS hub_browser_script_allowlist_status_idx;
DROP INDEX IF EXISTS hub_browser_script_allowlist_environment_idx;
DROP TABLE IF EXISTS hub_browser_script_allowlist;
