-- +goose Up
CREATE TABLE hub_model_analysis_reports (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	report_schema text NOT NULL,
	status text NOT NULL,
	model_provider text NOT NULL DEFAULT '',
	model_name text NOT NULL DEFAULT '',
	prompt_template_id text NOT NULL,
	prompt_template_version text NOT NULL,
	prompt_template_sha256 text NOT NULL,
	prompt_sha256 text NOT NULL,
	evidence_bundle_schema text NOT NULL,
	evidence_bundle_sha256 text NOT NULL,
	evidence_bundle_redaction_version text NOT NULL,
	evidence_bundle_generated_at timestamptz NOT NULL,
	source_finding_ids text[] NOT NULL DEFAULT '{}',
	analysis text NOT NULL DEFAULT '',
	error text NOT NULL DEFAULT '',
	total_duration_millis bigint NOT NULL DEFAULT 0,
	prompt_eval_count integer NOT NULL DEFAULT 0,
	eval_count integer NOT NULL DEFAULT 0,
	generated_at timestamptz NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_model_analysis_reports_status_shape CHECK (status IN ('completed', 'offline', 'failed')),
	CONSTRAINT hub_model_analysis_reports_schema_present CHECK (length(trim(report_schema)) > 0),
	CONSTRAINT hub_model_analysis_reports_prompt_template_id_present CHECK (length(trim(prompt_template_id)) > 0),
	CONSTRAINT hub_model_analysis_reports_prompt_template_version_present CHECK (length(trim(prompt_template_version)) > 0),
	CONSTRAINT hub_model_analysis_reports_prompt_template_sha_present CHECK (length(trim(prompt_template_sha256)) > 0),
	CONSTRAINT hub_model_analysis_reports_prompt_sha_present CHECK (length(trim(prompt_sha256)) > 0),
	CONSTRAINT hub_model_analysis_reports_bundle_sha_present CHECK (length(trim(evidence_bundle_sha256)) > 0)
);

CREATE INDEX hub_model_analysis_reports_environment_generated_idx ON hub_model_analysis_reports (environment_id, generated_at DESC);
CREATE INDEX hub_model_analysis_reports_app_generated_idx ON hub_model_analysis_reports (app_id, generated_at DESC);
CREATE INDEX hub_model_analysis_reports_status_idx ON hub_model_analysis_reports (status);
CREATE INDEX hub_model_analysis_reports_bundle_sha_idx ON hub_model_analysis_reports (evidence_bundle_sha256);
CREATE INDEX hub_model_analysis_reports_prompt_template_idx ON hub_model_analysis_reports (prompt_template_id, prompt_template_version);
CREATE INDEX hub_model_analysis_reports_metadata_gin_idx ON hub_model_analysis_reports USING gin (metadata);

-- +goose Down
DROP INDEX IF EXISTS hub_model_analysis_reports_metadata_gin_idx;
DROP INDEX IF EXISTS hub_model_analysis_reports_prompt_template_idx;
DROP INDEX IF EXISTS hub_model_analysis_reports_bundle_sha_idx;
DROP INDEX IF EXISTS hub_model_analysis_reports_status_idx;
DROP INDEX IF EXISTS hub_model_analysis_reports_app_generated_idx;
DROP INDEX IF EXISTS hub_model_analysis_reports_environment_generated_idx;
DROP TABLE IF EXISTS hub_model_analysis_reports;
