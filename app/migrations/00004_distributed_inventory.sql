-- +goose Up
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

ALTER TABLE normalized_events
	ADD COLUMN organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
	ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE SET NULL,
	ADD COLUMN environment_id uuid REFERENCES environments(id) ON DELETE SET NULL,
	ADD COLUMN app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	ADD COLUMN service_id uuid REFERENCES services(id) ON DELETE SET NULL,
	ADD COLUMN host_id uuid REFERENCES hosts(id) ON DELETE SET NULL,
	ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE SET NULL,
	ADD COLUMN region text NOT NULL DEFAULT '',
	ADD COLUMN received_at timestamptz NOT NULL DEFAULT now();

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
CREATE INDEX deployment_markers_environment_started_idx ON deployment_markers (environment_id, started_at DESC);
CREATE INDEX deployment_markers_app_started_idx ON deployment_markers (app_id, started_at DESC);
CREATE INDEX normalized_events_distributed_time_idx
	ON normalized_events (organization_id, project_id, environment_id, app_id, service_id, host_id, occurred_at DESC);
CREATE INDEX normalized_events_received_at_idx ON normalized_events (received_at DESC);

-- +goose Down
DROP INDEX IF EXISTS normalized_events_received_at_idx;
DROP INDEX IF EXISTS normalized_events_distributed_time_idx;
DROP INDEX IF EXISTS deployment_markers_app_started_idx;
DROP INDEX IF EXISTS deployment_markers_environment_started_idx;
DROP INDEX IF EXISTS agents_last_seen_idx;
DROP INDEX IF EXISTS agents_host_idx;
DROP INDEX IF EXISTS hosts_labels_gin_idx;
DROP INDEX IF EXISTS hosts_environment_idx;
DROP INDEX IF EXISTS services_role_idx;
DROP INDEX IF EXISTS services_app_idx;
DROP INDEX IF EXISTS monitored_apps_kind_idx;
DROP INDEX IF EXISTS monitored_apps_environment_idx;
DROP INDEX IF EXISTS environments_project_idx;
DROP INDEX IF EXISTS projects_org_idx;

ALTER TABLE normalized_events
	DROP COLUMN IF EXISTS received_at,
	DROP COLUMN IF EXISTS region,
	DROP COLUMN IF EXISTS agent_id,
	DROP COLUMN IF EXISTS host_id,
	DROP COLUMN IF EXISTS service_id,
	DROP COLUMN IF EXISTS app_id,
	DROP COLUMN IF EXISTS environment_id,
	DROP COLUMN IF EXISTS project_id,
	DROP COLUMN IF EXISTS organization_id;

DROP TABLE IF EXISTS deployment_markers;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS hosts;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS monitored_apps;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS organizations;
