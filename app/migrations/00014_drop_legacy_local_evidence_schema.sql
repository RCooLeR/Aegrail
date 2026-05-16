-- +goose Up
DROP INDEX IF EXISTS normalized_events_received_at_idx;
DROP INDEX IF EXISTS normalized_events_distributed_time_idx;
DROP INDEX IF EXISTS llm_reports_site_created_idx;
DROP INDEX IF EXISTS detected_findings_severity_idx;
DROP INDEX IF EXISTS detected_findings_site_created_idx;
DROP INDEX IF EXISTS normalized_events_source_ref_trgm_idx;
DROP INDEX IF EXISTS normalized_events_user_agent_trgm_idx;
DROP INDEX IF EXISTS normalized_events_controller_trgm_idx;
DROP INDEX IF EXISTS normalized_events_path_trgm_idx;
DROP INDEX IF EXISTS normalized_events_metadata_gin_idx;
DROP INDEX IF EXISTS normalized_events_risk_tags_gin_idx;
DROP INDEX IF EXISTS normalized_events_source_type_idx;
DROP INDEX IF EXISTS normalized_events_event_name_idx;
DROP INDEX IF EXISTS normalized_events_site_time_idx;
DROP INDEX IF EXISTS evidence_objects_sha256_idx;
DROP INDEX IF EXISTS evidence_imports_status_idx;
DROP INDEX IF EXISTS evidence_imports_site_started_idx;
DROP INDEX IF EXISTS sites_slug_trgm_idx;
DROP INDEX IF EXISTS semantic_chunks_metadata_gin_idx;
DROP INDEX IF EXISTS semantic_chunks_site_idx;

DROP TABLE IF EXISTS semantic_chunks;
DROP TABLE IF EXISTS llm_reports;
DROP TABLE IF EXISTS detected_findings;
DROP TABLE IF EXISTS normalized_events;
DROP TABLE IF EXISTS evidence_objects;
DROP TABLE IF EXISTS evidence_imports;
DROP TABLE IF EXISTS sites;
DROP TYPE IF EXISTS evidence_import_status;

-- +goose Down
SELECT 1;
