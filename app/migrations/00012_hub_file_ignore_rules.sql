-- +goose Up
CREATE TABLE hub_file_ignore_rules (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE CASCADE,
	match_kind text NOT NULL,
	match_value text NOT NULL,
	normalized_value text NOT NULL,
	reason text NOT NULL DEFAULT '',
	created_by text NOT NULL DEFAULT '',
	status text NOT NULL DEFAULT 'active',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_file_ignore_rules_kind_shape CHECK (match_kind IN ('file_path_prefix')),
	CONSTRAINT hub_file_ignore_rules_status_shape CHECK (status IN ('active', 'disabled')),
	CONSTRAINT hub_file_ignore_rules_value_present CHECK (length(trim(normalized_value)) > 0)
);

CREATE UNIQUE INDEX hub_file_ignore_rules_unique_idx
	ON hub_file_ignore_rules (environment_id, coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid), match_kind, normalized_value);
CREATE INDEX hub_file_ignore_rules_scope_idx ON hub_file_ignore_rules (environment_id, app_id, status);

-- +goose Down
DROP INDEX IF EXISTS hub_file_ignore_rules_scope_idx;
DROP INDEX IF EXISTS hub_file_ignore_rules_unique_idx;
DROP TABLE IF EXISTS hub_file_ignore_rules;
