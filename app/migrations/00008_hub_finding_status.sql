-- +goose Up
ALTER TABLE hub_findings
	ADD COLUMN status text NOT NULL DEFAULT 'open',
	ADD COLUMN status_reason text NOT NULL DEFAULT '',
	ADD COLUMN status_note text NOT NULL DEFAULT '',
	ADD COLUMN status_actor text NOT NULL DEFAULT '',
	ADD COLUMN status_updated_at timestamptz NOT NULL DEFAULT now(),
	ADD CONSTRAINT hub_findings_status_shape CHECK (status IN ('open', 'acknowledged', 'false_positive', 'resolved'));

CREATE INDEX hub_findings_status_idx ON hub_findings (status);

-- +goose Down
DROP INDEX IF EXISTS hub_findings_status_idx;
ALTER TABLE hub_findings
	DROP CONSTRAINT IF EXISTS hub_findings_status_shape,
	DROP COLUMN IF EXISTS status_updated_at,
	DROP COLUMN IF EXISTS status_actor,
	DROP COLUMN IF EXISTS status_note,
	DROP COLUMN IF EXISTS status_reason,
	DROP COLUMN IF EXISTS status;
