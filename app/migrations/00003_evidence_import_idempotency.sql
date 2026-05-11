-- +goose Up
ALTER TABLE evidence_imports
	ADD COLUMN source_fingerprint text NOT NULL DEFAULT '',
	ADD COLUMN object_count integer NOT NULL DEFAULT 0;

ALTER TABLE evidence_objects
	ADD COLUMN original_uri text NOT NULL DEFAULT '',
	ADD COLUMN relative_path text NOT NULL DEFAULT '';

UPDATE evidence_objects
SET relative_path = uri
WHERE relative_path = '';

CREATE UNIQUE INDEX evidence_imports_site_source_fingerprint_idx
	ON evidence_imports (site_id, source_type, source_fingerprint)
	WHERE source_fingerprint <> '';

CREATE UNIQUE INDEX evidence_objects_import_relative_path_idx
	ON evidence_objects (import_id, relative_path);

CREATE INDEX evidence_objects_import_idx ON evidence_objects (import_id);
CREATE INDEX evidence_objects_relative_path_trgm_idx ON evidence_objects USING gin (relative_path gin_trgm_ops);

-- +goose Down
DROP INDEX IF EXISTS evidence_objects_relative_path_trgm_idx;
DROP INDEX IF EXISTS evidence_objects_import_idx;
DROP INDEX IF EXISTS evidence_objects_import_relative_path_idx;
DROP INDEX IF EXISTS evidence_imports_site_source_fingerprint_idx;

ALTER TABLE evidence_objects
	DROP COLUMN IF EXISTS relative_path,
	DROP COLUMN IF EXISTS original_uri;

ALTER TABLE evidence_imports
	DROP COLUMN IF EXISTS object_count,
	DROP COLUMN IF EXISTS source_fingerprint;
