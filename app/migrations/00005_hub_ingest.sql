-- +goose Up
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

CREATE INDEX hub_ingest_batches_environment_received_idx ON hub_ingest_batches (environment_id, received_at DESC);
CREATE INDEX hub_ingest_batches_agent_received_idx ON hub_ingest_batches (agent_id, received_at DESC);
CREATE INDEX hub_ingest_events_environment_time_idx ON hub_ingest_events (environment_id, event_time DESC);
CREATE INDEX hub_ingest_events_host_time_idx ON hub_ingest_events (host_id, event_time DESC);
CREATE INDEX hub_ingest_events_agent_time_idx ON hub_ingest_events (agent_id, event_time DESC);
CREATE INDEX hub_ingest_events_type_idx ON hub_ingest_events (event_type);
CREATE INDEX hub_ingest_events_severity_idx ON hub_ingest_events (severity);
CREATE INDEX hub_ingest_events_labels_gin_idx ON hub_ingest_events USING gin (labels);
CREATE INDEX hub_ingest_events_payload_gin_idx ON hub_ingest_events USING gin (payload);

-- +goose Down
DROP INDEX IF EXISTS hub_ingest_events_payload_gin_idx;
DROP INDEX IF EXISTS hub_ingest_events_labels_gin_idx;
DROP INDEX IF EXISTS hub_ingest_events_severity_idx;
DROP INDEX IF EXISTS hub_ingest_events_type_idx;
DROP INDEX IF EXISTS hub_ingest_events_agent_time_idx;
DROP INDEX IF EXISTS hub_ingest_events_host_time_idx;
DROP INDEX IF EXISTS hub_ingest_events_environment_time_idx;
DROP INDEX IF EXISTS hub_ingest_batches_agent_received_idx;
DROP INDEX IF EXISTS hub_ingest_batches_environment_received_idx;
DROP TABLE IF EXISTS hub_ingest_events;
DROP TABLE IF EXISTS hub_ingest_batches;
