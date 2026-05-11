-- +goose Up
CREATE TYPE evidence_import_status AS ENUM (
	'pending',
	'processing',
	'completed',
	'failed'
);

CREATE TABLE sites (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	slug citext NOT NULL UNIQUE,
	name text NOT NULL,
	base_url text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT sites_slug_shape CHECK (slug::text ~ '^[a-z0-9]$|^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$'),
	CONSTRAINT sites_base_url_shape CHECK (base_url = '' OR base_url ~ '^https?://')
);

CREATE TABLE evidence_imports (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	source_type text NOT NULL,
	source_uri text NOT NULL,
	status evidence_import_status NOT NULL DEFAULT 'pending',
	started_at timestamptz NOT NULL DEFAULT now(),
	finished_at timestamptz,
	tool_name text NOT NULL DEFAULT 'aegrail',
	tool_version text NOT NULL DEFAULT 'dev',
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence_objects (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	import_id uuid NOT NULL REFERENCES evidence_imports(id) ON DELETE CASCADE,
	uri text NOT NULL,
	sha256 text NOT NULL,
	content_type text NOT NULL DEFAULT '',
	size_bytes bigint NOT NULL DEFAULT 0,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (import_id, sha256, uri)
);

CREATE TABLE normalized_events (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	import_id uuid REFERENCES evidence_imports(id) ON DELETE SET NULL,
	occurred_at timestamptz NOT NULL,
	source_type text NOT NULL,
	source_ref text NOT NULL DEFAULT '',
	actor_type text NOT NULL DEFAULT '',
	actor_id text NOT NULL DEFAULT '',
	actor_email_redacted text NOT NULL DEFAULT '',
	ip inet,
	method text NOT NULL DEFAULT '',
	path text NOT NULL DEFAULT '',
	query_redacted text NOT NULL DEFAULT '',
	controller text NOT NULL DEFAULT '',
	action text NOT NULL DEFAULT '',
	status_code integer,
	bytes bigint,
	user_agent text NOT NULL DEFAULT '',
	object_type text NOT NULL DEFAULT '',
	object_id text NOT NULL DEFAULT '',
	event_name text NOT NULL,
	risk_tags text[] NOT NULL DEFAULT '{}',
	raw_ref text NOT NULL DEFAULT '',
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE detected_findings (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	rule_id text NOT NULL,
	rule_version text NOT NULL,
	dedupe_key text NOT NULL,
	severity text NOT NULL,
	confidence text NOT NULL,
	title text NOT NULL,
	description text NOT NULL,
	evidence_refs uuid[] NOT NULL DEFAULT '{}',
	recommended_next_check text NOT NULL DEFAULT '',
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (site_id, rule_id, dedupe_key),
	CONSTRAINT detected_findings_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT detected_findings_confidence CHECK (confidence IN ('low', 'medium', 'high'))
);

CREATE TABLE llm_reports (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	model text NOT NULL,
	prompt_version text NOT NULL,
	input_finding_ids uuid[] NOT NULL DEFAULT '{}',
	title text NOT NULL,
	body_md text NOT NULL,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE semantic_chunks (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	site_id uuid REFERENCES sites(id) ON DELETE CASCADE,
	source_type text NOT NULL,
	source_id uuid,
	content_hash text NOT NULL,
	content_redacted text NOT NULL,
	embedding vector,
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE (source_type, source_id, content_hash)
);

CREATE INDEX sites_slug_trgm_idx ON sites USING gin (slug gin_trgm_ops);
CREATE INDEX evidence_imports_site_started_idx ON evidence_imports (site_id, started_at DESC);
CREATE INDEX evidence_imports_status_idx ON evidence_imports (status);
CREATE INDEX evidence_objects_sha256_idx ON evidence_objects (sha256);
CREATE INDEX normalized_events_site_time_idx ON normalized_events (site_id, occurred_at DESC);
CREATE INDEX normalized_events_event_name_idx ON normalized_events (event_name);
CREATE INDEX normalized_events_source_type_idx ON normalized_events (source_type);
CREATE INDEX normalized_events_risk_tags_gin_idx ON normalized_events USING gin (risk_tags);
CREATE INDEX normalized_events_metadata_gin_idx ON normalized_events USING gin (metadata);
CREATE INDEX normalized_events_path_trgm_idx ON normalized_events USING gin (path gin_trgm_ops);
CREATE INDEX normalized_events_controller_trgm_idx ON normalized_events USING gin (controller gin_trgm_ops);
CREATE INDEX normalized_events_user_agent_trgm_idx ON normalized_events USING gin (user_agent gin_trgm_ops);
CREATE INDEX normalized_events_source_ref_trgm_idx ON normalized_events USING gin (source_ref gin_trgm_ops);
CREATE INDEX detected_findings_site_created_idx ON detected_findings (site_id, created_at DESC);
CREATE INDEX detected_findings_severity_idx ON detected_findings (severity);
CREATE INDEX llm_reports_site_created_idx ON llm_reports (site_id, created_at DESC);
CREATE INDEX semantic_chunks_site_idx ON semantic_chunks (site_id);
CREATE INDEX semantic_chunks_metadata_gin_idx ON semantic_chunks USING gin (metadata);

-- +goose Down
DROP TABLE IF EXISTS semantic_chunks;
DROP TABLE IF EXISTS llm_reports;
DROP TABLE IF EXISTS detected_findings;
DROP TABLE IF EXISTS normalized_events;
DROP TABLE IF EXISTS evidence_objects;
DROP TABLE IF EXISTS evidence_imports;
DROP TABLE IF EXISTS sites;
DROP TYPE IF EXISTS evidence_import_status;
