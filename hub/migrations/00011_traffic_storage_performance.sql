-- +goose Up
-- +goose NO TRANSACTION
-- The upgrade backfill reads only legacy log.access events, newest first, in
-- bounded batches. Keep that one-time path off the much larger mixed event
-- indexes and avoid indexing routine traffic.request rows for this purpose.
CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_ingest_events_traffic_backfill_idx
	ON hub_ingest_events (event_time DESC, created_at DESC, id DESC)
	WHERE event_type = 'log.access';

-- Current traffic queries group by the original path and never constrain its
-- MD5. With the hash between scope and time, this index cannot bound the query
-- window and only adds write/storage cost.
DROP INDEX CONCURRENTLY IF EXISTS hub_access_requests_scope_path_time_idx;

-- +goose Down
CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_access_requests_scope_path_time_idx
	ON hub_access_requests (organization_id, project_id, environment_id, md5(path), event_time DESC)
	WHERE path <> '';

DROP INDEX CONCURRENTLY IF EXISTS hub_ingest_events_traffic_backfill_idx;
