-- +goose Up
CREATE TABLE hub_access_requests (
	event_id uuid PRIMARY KEY REFERENCES hub_ingest_events(id) ON DELETE CASCADE,
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	app_id uuid REFERENCES monitored_apps(id) ON DELETE SET NULL,
	service_id uuid REFERENCES services(id) ON DELETE SET NULL,
	host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	event_time timestamptz NOT NULL,
	event_type text NOT NULL,
	client_ip inet,
	method text NOT NULL DEFAULT '',
	scheme text NOT NULL DEFAULT '',
	request_host text NOT NULL DEFAULT '',
	path text NOT NULL DEFAULT '',
	query_redacted text NOT NULL DEFAULT '',
	request_target_redacted text NOT NULL DEFAULT '',
	protocol text NOT NULL DEFAULT '',
	status_code integer,
	response_bytes bigint,
	request_duration_ms double precision,
	upstream_duration_ms double precision,
	referer_redacted text NOT NULL DEFAULT '',
	user_agent text NOT NULL DEFAULT '',
	user_agent_hash text NOT NULL DEFAULT '',
	ua_family text NOT NULL DEFAULT '',
	ua_browser_family text NOT NULL DEFAULT '',
	ua_browser_version text NOT NULL DEFAULT '',
	ua_os_family text NOT NULL DEFAULT '',
	ua_os_version text NOT NULL DEFAULT '',
	ua_device_family text NOT NULL DEFAULT '',
	ua_actor_type text NOT NULL DEFAULT '',
	ua_known_actor text NOT NULL DEFAULT '',
	ua_is_bot boolean NOT NULL DEFAULT false,
	ua_is_tool boolean NOT NULL DEFAULT false,
	ua_risk_score integer NOT NULL DEFAULT 0,
	remote_network text NOT NULL DEFAULT '',
	remote_is_tor boolean NOT NULL DEFAULT false,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_access_requests_event_type_shape CHECK (event_type IN ('log.access', 'traffic.request')),
	CONSTRAINT hub_access_requests_status_shape CHECK (status_code IS NULL OR status_code BETWEEN 100 AND 599),
	CONSTRAINT hub_access_requests_response_bytes_shape CHECK (response_bytes IS NULL OR response_bytes >= 0),
	CONSTRAINT hub_access_requests_request_duration_shape CHECK (request_duration_ms IS NULL OR request_duration_ms >= 0),
	CONSTRAINT hub_access_requests_upstream_duration_shape CHECK (upstream_duration_ms IS NULL OR upstream_duration_ms >= 0),
	CONSTRAINT hub_access_requests_user_agent_hash_shape CHECK (user_agent_hash = '' OR user_agent_hash ~ '^[0-9a-f]{64}$'),
	CONSTRAINT hub_access_requests_ua_risk_shape CHECK (ua_risk_score BETWEEN 0 AND 100)
);

-- Existing log.access rows are intentionally not copied in SQL: the Go Hub
-- startup worker backfills only the most recent 30 days in batches of at most
-- 1,000 so every row passes through the same typed projection and user-agent
-- classifier as live ingest without an unbounded migration transaction.

CREATE INDEX hub_access_requests_scope_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, event_time DESC);
CREATE INDEX hub_access_requests_scope_app_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, app_id, event_time DESC)
	WHERE app_id IS NOT NULL;
CREATE INDEX hub_access_requests_scope_ip_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, client_ip, event_time DESC)
	WHERE client_ip IS NOT NULL;
CREATE INDEX hub_access_requests_scope_ua_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, user_agent_hash, event_time DESC)
	WHERE user_agent_hash <> '';
CREATE INDEX hub_access_requests_scope_path_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, md5(path), event_time DESC)
	WHERE path <> '';
CREATE INDEX hub_access_requests_scope_status_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, status_code, event_time DESC)
	WHERE status_code IS NOT NULL;
CREATE INDEX hub_access_requests_scope_bot_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, event_time DESC)
	WHERE ua_is_bot OR ua_is_tool OR ua_actor_type = 'malicious';

-- Routine traffic has a typed projection and must not multiply write/storage
-- cost through the generic JSONB search index. Signal event payloads retain
-- the existing GIN lookup behavior.
DROP INDEX IF EXISTS hub_ingest_events_payload_gin_idx;
CREATE INDEX hub_ingest_events_payload_gin_idx
	ON hub_ingest_events USING gin (payload)
	WHERE event_type <> 'traffic.request';

-- Technical lookup data is cached per organization so one tenant cannot infer
-- which IPs another tenant has investigated. Recognition is evidence only; it
-- is deliberately separate from the manual trust policy below.
CREATE TABLE hub_ip_intel (
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	ip inet NOT NULL,
	network_class text NOT NULL DEFAULT '',
	reverse_dns text[] NOT NULL DEFAULT '{}',
	dns_verified boolean NOT NULL DEFAULT false,
	provider_family text NOT NULL DEFAULT '',
	recognized_provider text NOT NULL DEFAULT '',
	provider_actor_type text NOT NULL DEFAULT '',
	provider_verified boolean NOT NULL DEFAULT false,
	lookup_status text NOT NULL DEFAULT 'unknown',
	last_lookup_at timestamptz NOT NULL,
	expires_at timestamptz NOT NULL,
	last_error text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (organization_id, ip),
	CONSTRAINT hub_ip_intel_lookup_status_shape CHECK (lookup_status IN ('fresh', 'error', 'not_applicable', 'unknown')),
	CONSTRAINT hub_ip_intel_expiry_order CHECK (expires_at >= last_lookup_at),
	CONSTRAINT hub_ip_intel_provider_verification_shape CHECK (NOT provider_verified OR dns_verified)
);

CREATE INDEX hub_ip_intel_expiry_idx ON hub_ip_intel (organization_id, expires_at);
CREATE INDEX hub_ip_intel_provider_idx
	ON hub_ip_intel (organization_id, provider_family, provider_verified)
	WHERE provider_family <> '';

CREATE TABLE hub_ip_manual_policies (
	organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	ip inet NOT NULL,
	policy text NOT NULL DEFAULT 'neutral',
	reason text NOT NULL DEFAULT '',
	updated_by text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (organization_id, ip),
	CONSTRAINT hub_ip_manual_policies_policy_shape CHECK (policy IN ('neutral', 'trusted', 'blocked'))
);

CREATE INDEX hub_ip_manual_policies_policy_idx
	ON hub_ip_manual_policies (organization_id, policy, updated_at DESC);

-- +goose Down
DROP TABLE IF EXISTS hub_ip_manual_policies;
DROP TABLE IF EXISTS hub_ip_intel;
DROP TABLE IF EXISTS hub_access_requests;
DROP INDEX IF EXISTS hub_ingest_events_payload_gin_idx;
CREATE INDEX hub_ingest_events_payload_gin_idx ON hub_ingest_events USING gin (payload);
