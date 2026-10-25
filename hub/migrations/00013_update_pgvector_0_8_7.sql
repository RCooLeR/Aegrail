-- +goose Up
-- Upgrade existing pgvector installations, including the previously supported
-- 0.8.2 release, to the 0.8.7 extension SQL.
-- Deploy the 0.8.7 server image before running this migration. PostgreSQL takes
-- brief locks on the extension objects, but no Aegrail table is rewritten.
-- Fresh databases create vector at 0.8.7 when migration 00001 runs against the
-- current image, so this migration deliberately succeeds without changing them.
-- The extension update is not safely reversible; the down migration is a no-op.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '120s';

-- +goose StatementBegin
DO $migration$
DECLARE
	installed_version text;
BEGIN
	SELECT extversion
	INTO installed_version
	FROM pg_extension
	WHERE extname = 'vector';

	IF installed_version = '0.8.7' THEN
		RETURN;
	END IF;

	IF installed_version IS NULL THEN
		RAISE EXCEPTION
			'pgvector 0.8.7 migration requires the vector extension to be installed';
	END IF;

	-- PostgreSQL resolves the packaged extension update chain. This deliberately
	-- avoids an allow-list so every older version supported by the 0.8.7 image
	-- can advance, while a missing or unsupported path still fails explicitly.
	ALTER EXTENSION vector UPDATE TO '0.8.7';
END
$migration$;
-- +goose StatementEnd

-- +goose Down
-- Intentionally a no-op. PostgreSQL extensions do not provide a safe generic
-- downgrade path, and reverting package code without matching server binaries
-- can leave database objects unusable.
SELECT 1;
