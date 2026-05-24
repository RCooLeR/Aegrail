-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE organizations (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	slug citext NOT NULL UNIQUE,
	name text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT organizations_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

CREATE TABLE projects (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	slug citext NOT NULL,
	name text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (organization_id, slug),
	CONSTRAINT projects_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

CREATE TABLE environments (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	slug citext NOT NULL,
	name text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (project_id, slug),
	CONSTRAINT environments_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

CREATE TABLE monitored_apps (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	slug citext NOT NULL,
	name text NOT NULL,
	kind text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (environment_id, slug),
	CONSTRAINT monitored_apps_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

CREATE TABLE services (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	app_id uuid NOT NULL REFERENCES monitored_apps(id) ON DELETE CASCADE,
	slug citext NOT NULL,
	name text NOT NULL,
	role text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (app_id, slug),
	CONSTRAINT services_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

CREATE TABLE hosts (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	slug citext NOT NULL,
	hostname text NOT NULL,
	region text NOT NULL DEFAULT '',
	labels jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (environment_id, slug),
	CONSTRAINT hosts_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$')
);

CREATE TABLE agents (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	agent_id citext NOT NULL UNIQUE,
	fingerprint text NOT NULL,
	version text NOT NULL DEFAULT '',
	last_seen_at timestamptz,
	wire_protocol text NOT NULL DEFAULT 'aegrail.agent.wire.v1',
	node_public_key text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (host_id, agent_id)
);

CREATE TABLE deployment_markers (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	version text NOT NULL,
	commit_sha text NOT NULL DEFAULT '',
	actor text NOT NULL DEFAULT '',
	started_at timestamptz NOT NULL,
	finished_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hub_ingest_batches (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	external_id text NOT NULL,
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	service_id uuid REFERENCES services(id) ON DELETE SET NULL,
	host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	source text NOT NULL DEFAULT '',
	body_sha256 text NOT NULL DEFAULT '',
	signature text NOT NULL DEFAULT '',
	status text NOT NULL DEFAULT 'accepted',
	event_count integer NOT NULL DEFAULT 0,
	received_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (agent_id, external_id),
	CONSTRAINT hub_ingest_batches_external_id_present CHECK (length(trim(external_id)) > 0),
	CONSTRAINT hub_ingest_batches_status_shape CHECK (status IN ('accepted', 'rejected'))
);

CREATE TABLE hub_ingest_events (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	batch_id uuid NOT NULL REFERENCES hub_ingest_batches(id) ON DELETE CASCADE,
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	service_id uuid REFERENCES services(id) ON DELETE SET NULL,
	host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	event_time timestamptz NOT NULL,
	received_at timestamptz NOT NULL DEFAULT now(),
	event_type text NOT NULL,
	target text NOT NULL DEFAULT '',
	severity text NOT NULL DEFAULT 'info',
	message text NOT NULL DEFAULT '',
	region text NOT NULL DEFAULT '',
	labels jsonb NOT NULL DEFAULT '{}'::jsonb,
	payload jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_ingest_events_type_present CHECK (length(trim(event_type)) > 0),
	CONSTRAINT hub_ingest_events_severity_shape CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

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
	status text NOT NULL DEFAULT 'open',
	status_reason text NOT NULL DEFAULT '',
	status_note text NOT NULL DEFAULT '',
	status_actor text NOT NULL DEFAULT '',
	status_updated_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_findings_rule_id_present CHECK (length(trim(rule_id)) > 0),
	CONSTRAINT hub_findings_rule_version_present CHECK (length(trim(rule_version)) > 0),
	CONSTRAINT hub_findings_dedupe_key_present CHECK (length(trim(dedupe_key)) > 0),
	CONSTRAINT hub_findings_severity_shape CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT hub_findings_confidence_shape CHECK (confidence IN ('low', 'medium', 'high')),
	CONSTRAINT hub_findings_status_shape CHECK (status IN ('open', 'acknowledged', 'false_positive', 'resolved')),
	CONSTRAINT hub_findings_time_order CHECK (last_event_at >= first_event_at)
);

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

CREATE TABLE hub_users (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	email text NOT NULL,
	display_name text NOT NULL DEFAULT '',
	access_level text NOT NULL DEFAULT 'viewer',
	status text NOT NULL DEFAULT 'active',
	password_hash text NOT NULL DEFAULT '',
	password_set_at timestamptz,
	two_factor_required boolean NOT NULL DEFAULT true,
	two_factor_enabled boolean NOT NULL DEFAULT false,
	totp_secret_ciphertext text NOT NULL DEFAULT '',
	totp_enrolled_at timestamptz,
	pending_totp_secret_ciphertext text NOT NULL DEFAULT '',
	pending_totp_started_at timestamptz,
	last_login_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_users_email_present CHECK (length(trim(email)) > 0),
	CONSTRAINT hub_users_access_level_shape CHECK (access_level IN ('owner', 'admin', 'operator', 'viewer')),
	CONSTRAINT hub_users_status_shape CHECK (status IN ('active', 'invited', 'disabled'))
);

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

CREATE TABLE hub_push_subscriptions (
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

CREATE INDEX projects_org_idx ON projects (organization_id);
CREATE INDEX environments_project_idx ON environments (project_id);
CREATE INDEX monitored_apps_environment_idx ON monitored_apps (environment_id);
CREATE INDEX monitored_apps_kind_idx ON monitored_apps (kind);
CREATE INDEX services_app_idx ON services (app_id);
CREATE INDEX services_role_idx ON services (role);
CREATE INDEX hosts_environment_idx ON hosts (environment_id);
CREATE INDEX hosts_labels_gin_idx ON hosts USING gin (labels);
CREATE INDEX agents_host_idx ON agents (host_id);
CREATE INDEX agents_last_seen_idx ON agents (last_seen_at DESC);
CREATE UNIQUE INDEX agents_node_public_key_unique_idx ON agents (node_public_key) WHERE node_public_key <> '';
CREATE INDEX deployment_markers_environment_started_idx ON deployment_markers (environment_id, started_at DESC);
CREATE INDEX deployment_markers_app_started_idx ON deployment_markers (app_id, started_at DESC);

CREATE INDEX hub_ingest_batches_environment_received_idx ON hub_ingest_batches (environment_id, received_at DESC);
CREATE INDEX hub_ingest_batches_agent_received_idx ON hub_ingest_batches (agent_id, received_at DESC);
CREATE INDEX hub_ingest_events_environment_time_idx ON hub_ingest_events (environment_id, event_time DESC);
CREATE INDEX hub_ingest_events_environment_type_time_idx ON hub_ingest_events (environment_id, event_type, event_time DESC, created_at DESC);
CREATE INDEX hub_ingest_events_environment_app_time_idx ON hub_ingest_events (environment_id, app_id, event_time DESC, created_at DESC);
CREATE INDEX hub_ingest_events_environment_app_type_time_idx ON hub_ingest_events (environment_id, app_id, event_type, event_time DESC, created_at DESC);
CREATE INDEX hub_ingest_events_host_time_idx ON hub_ingest_events (host_id, event_time DESC);
CREATE INDEX hub_ingest_events_agent_time_idx ON hub_ingest_events (agent_id, event_time DESC);
CREATE INDEX hub_ingest_events_type_idx ON hub_ingest_events (event_type);
CREATE INDEX hub_ingest_events_severity_idx ON hub_ingest_events (severity);
CREATE INDEX hub_ingest_events_labels_gin_idx ON hub_ingest_events USING gin (labels);
CREATE INDEX hub_ingest_events_payload_gin_idx ON hub_ingest_events USING gin (payload);

CREATE INDEX hub_findings_environment_event_idx ON hub_findings (environment_id, first_event_at DESC);
CREATE INDEX hub_findings_app_event_idx ON hub_findings (app_id, first_event_at DESC);
CREATE INDEX hub_findings_environment_app_event_idx ON hub_findings (environment_id, app_id, first_event_at DESC, created_at DESC);
CREATE INDEX hub_findings_environment_app_status_event_idx ON hub_findings (environment_id, app_id, status, last_event_at DESC, updated_at DESC);
CREATE INDEX hub_findings_severity_idx ON hub_findings (severity);
CREATE INDEX hub_findings_status_idx ON hub_findings (status);
CREATE INDEX hub_findings_metadata_gin_idx ON hub_findings USING gin (metadata);
CREATE UNIQUE INDEX hub_findings_scope_rule_dedupe_unique_idx
	ON hub_findings (environment_id, (coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid)), rule_id, dedupe_key);

CREATE INDEX hub_browser_script_allowlist_environment_idx ON hub_browser_script_allowlist (environment_id, app_id, kind);
CREATE INDEX hub_browser_script_allowlist_status_idx ON hub_browser_script_allowlist (status);

CREATE INDEX hub_model_analysis_reports_environment_generated_idx ON hub_model_analysis_reports (environment_id, generated_at DESC);
CREATE INDEX hub_model_analysis_reports_app_generated_idx ON hub_model_analysis_reports (app_id, generated_at DESC);
CREATE INDEX hub_model_analysis_reports_environment_app_generated_idx ON hub_model_analysis_reports (environment_id, app_id, generated_at DESC, created_at DESC);
CREATE INDEX hub_model_analysis_reports_scope_status_idx ON hub_model_analysis_reports (environment_id, app_id, status);
CREATE INDEX hub_model_analysis_reports_status_idx ON hub_model_analysis_reports (status);
CREATE INDEX hub_model_analysis_reports_bundle_sha_idx ON hub_model_analysis_reports (evidence_bundle_sha256);
CREATE INDEX hub_model_analysis_reports_prompt_template_idx ON hub_model_analysis_reports (prompt_template_id, prompt_template_version);
CREATE INDEX hub_model_analysis_reports_metadata_gin_idx ON hub_model_analysis_reports USING gin (metadata);
CREATE INDEX hub_model_analysis_reports_source_finding_ids_gin_idx ON hub_model_analysis_reports USING gin (source_finding_ids);

CREATE UNIQUE INDEX hub_users_email_lower_idx ON hub_users (lower(email));
CREATE INDEX hub_users_access_level_idx ON hub_users (access_level);
CREATE INDEX hub_users_status_idx ON hub_users (status);
CREATE INDEX hub_users_two_factor_idx ON hub_users (two_factor_required, two_factor_enabled);

CREATE UNIQUE INDEX hub_user_sessions_token_hash_idx ON hub_user_sessions (token_hash);
CREATE INDEX hub_user_sessions_user_id_idx ON hub_user_sessions (user_id);
CREATE INDEX hub_user_sessions_active_idx ON hub_user_sessions (expires_at) WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX hub_push_subscriptions_endpoint_idx ON hub_push_subscriptions (endpoint);
CREATE INDEX hub_push_subscriptions_user_status_idx ON hub_push_subscriptions (user_id, status);
CREATE INDEX hub_push_subscriptions_status_updated_idx ON hub_push_subscriptions (status, updated_at DESC);

CREATE UNIQUE INDEX hub_file_ignore_rules_unique_idx
	ON hub_file_ignore_rules (environment_id, coalesce(app_id, '00000000-0000-0000-0000-000000000000'::uuid), match_kind, normalized_value);
CREATE INDEX hub_file_ignore_rules_scope_idx ON hub_file_ignore_rules (environment_id, app_id, status);

-- +goose Down
DROP TABLE IF EXISTS hub_file_ignore_rules;
DROP TABLE IF EXISTS hub_push_subscriptions;
DROP TABLE IF EXISTS hub_user_sessions;
DROP TABLE IF EXISTS hub_users;
DROP TABLE IF EXISTS hub_model_analysis_reports;
DROP TABLE IF EXISTS hub_browser_script_allowlist;
DROP TABLE IF EXISTS hub_findings;
DROP TABLE IF EXISTS hub_ingest_events;
DROP TABLE IF EXISTS hub_ingest_batches;
DROP TABLE IF EXISTS deployment_markers;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS monitored_apps;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS organizations;

DROP EXTENSION IF EXISTS citext;
DROP EXTENSION IF EXISTS btree_gin;
DROP EXTENSION IF EXISTS vector;
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS pgcrypto;
