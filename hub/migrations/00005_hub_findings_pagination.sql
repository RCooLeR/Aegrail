-- +goose Up
-- +goose NO TRANSACTION
-- Always remove a same-named index first. PostgreSQL can leave an invalid
-- index behind when CREATE INDEX CONCURRENTLY is interrupted; IF NOT EXISTS
-- would silently accept that broken index on the next migration attempt.
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_created_page_idx;
CREATE INDEX CONCURRENTLY hub_findings_environment_created_page_idx
	ON hub_findings (environment_id, created_at DESC, id DESC);

DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_app_created_page_idx;
CREATE INDEX CONCURRENTLY hub_findings_environment_app_created_page_idx
	ON hub_findings (environment_id, app_id, created_at DESC, id DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_app_created_page_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_created_page_idx;
