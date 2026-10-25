-- +goose Up
-- +goose NO TRANSACTION
-- The dashboard's default issue queue filters to status=open while retaining
-- the immutable created_at/id cursor order. Keep status before the cursor
-- columns so PostgreSQL can satisfy that filter and ordering from one index.
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_status_created_page_idx;
CREATE INDEX CONCURRENTLY hub_findings_environment_status_created_page_idx
	ON hub_findings (environment_id, status, created_at DESC, id DESC);

DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_app_status_created_page_idx;
CREATE INDEX CONCURRENTLY hub_findings_environment_app_status_created_page_idx
	ON hub_findings (environment_id, app_id, status, created_at DESC, id DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_app_status_created_page_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_status_created_page_idx;
