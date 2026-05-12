-- +goose Up
CREATE TABLE hub_findings (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	rule_id text NOT NULL,
	rule_version text NOT NULL,
	dedupe_key text NOT NULL,
	severity text NOT NULL,
	confidence text NOT NULL,
	title text NOT NULL,
	summary text NOT NULL DEFAULT '',
	description text NOT NULL DEFAULT '',
	event_ids text[] NOT NULL DEFAULT '{}',
	first_event_at timestamptz NOT NULL,
	last_event_at timestamptz NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (environment_id, rule_id, dedupe_key),
	CONSTRAINT hub_findings_rule_id_present CHECK (length(trim(rule_id)) > 0),
	CONSTRAINT hub_findings_rule_version_present CHECK (length(trim(rule_version)) > 0),
	CONSTRAINT hub_findings_dedupe_key_present CHECK (length(trim(dedupe_key)) > 0),
	CONSTRAINT hub_findings_severity_shape CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT hub_findings_confidence_shape CHECK (confidence IN ('low', 'medium', 'high')),
	CONSTRAINT hub_findings_time_order CHECK (last_event_at >= first_event_at)
);

CREATE INDEX hub_findings_environment_event_idx ON hub_findings (environment_id, first_event_at DESC);
CREATE INDEX hub_findings_app_event_idx ON hub_findings (app_id, first_event_at DESC);
CREATE INDEX hub_findings_severity_idx ON hub_findings (severity);
CREATE INDEX hub_findings_metadata_gin_idx ON hub_findings USING gin (metadata);

-- +goose Down
DROP INDEX IF EXISTS hub_findings_metadata_gin_idx;
DROP INDEX IF EXISTS hub_findings_severity_idx;
DROP INDEX IF EXISTS hub_findings_app_event_idx;
DROP INDEX IF EXISTS hub_findings_environment_event_idx;
DROP TABLE IF EXISTS hub_findings;
