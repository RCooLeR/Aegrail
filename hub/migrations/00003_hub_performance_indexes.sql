-- +goose Up
-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_ingest_events_environment_app_time_idx
	ON hub_ingest_events (environment_id, app_id, event_time DESC, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_ingest_events_environment_type_time_idx
	ON hub_ingest_events (environment_id, event_type, event_time DESC, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_ingest_events_environment_app_type_time_idx
	ON hub_ingest_events (environment_id, app_id, event_type, event_time DESC, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_findings_environment_app_event_idx
	ON hub_findings (environment_id, app_id, first_event_at DESC, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_findings_environment_app_status_event_idx
	ON hub_findings (environment_id, app_id, status, last_event_at DESC, updated_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_model_analysis_reports_scope_status_idx
	ON hub_model_analysis_reports (environment_id, app_id, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_model_analysis_reports_environment_app_generated_idx
	ON hub_model_analysis_reports (environment_id, app_id, generated_at DESC, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS hub_push_subscriptions_status_updated_idx
	ON hub_push_subscriptions (status, updated_at DESC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS hub_push_subscriptions_status_updated_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_model_analysis_reports_environment_app_generated_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_model_analysis_reports_scope_status_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_app_status_event_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_environment_app_event_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_ingest_events_environment_app_type_time_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_ingest_events_environment_type_time_idx;
DROP INDEX CONCURRENTLY IF EXISTS hub_ingest_events_environment_app_time_idx;
