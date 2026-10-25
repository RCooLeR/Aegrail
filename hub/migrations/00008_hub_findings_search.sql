-- +goose Up
-- +goose NO TRANSACTION
-- Exact issue-queue search uses a case-insensitive literal substring over the
-- five operator-visible finding text fields. A trigram expression index keeps
-- both the first result page and its exact matched_total bounded as history
-- grows, while the scope/status B-trees can be combined by PostgreSQL.
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_search_trgm_idx;
CREATE INDEX CONCURRENTLY hub_findings_search_trgm_idx
	ON hub_findings USING gin ((lower(
		coalesce(title, '') || E'\x1f' ||
		coalesce(summary, '') || E'\x1f' ||
		coalesce(description, '') || E'\x1f' ||
		coalesce(rule_id, '') || E'\x1f' ||
		coalesce(dedupe_key, '')
	)) gin_trgm_ops);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS hub_findings_search_trgm_idx;
