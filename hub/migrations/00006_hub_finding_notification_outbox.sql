-- +goose Up
CREATE TABLE IF NOT EXISTS hub_finding_notification_outbox (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	finding_id uuid NOT NULL REFERENCES hub_findings(id) ON DELETE CASCADE,
	event_type text NOT NULL,
	transport text NOT NULL,
	payload jsonb NOT NULL,
	attempt_count integer NOT NULL DEFAULT 0,
	next_attempt_at timestamptz NOT NULL DEFAULT now(),
	leased_until timestamptz,
	lease_token uuid,
	last_error text NOT NULL DEFAULT '',
	delivered_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT hub_finding_notification_outbox_event_present CHECK (length(trim(event_type)) > 0),
	CONSTRAINT hub_finding_notification_outbox_transport_present CHECK (length(trim(transport)) > 0),
	CONSTRAINT hub_finding_notification_outbox_attempt_count_nonnegative CHECK (attempt_count >= 0),
	CONSTRAINT hub_finding_notification_outbox_lease_shape CHECK (
		(leased_until IS NULL AND lease_token IS NULL)
		OR (leased_until IS NOT NULL AND lease_token IS NOT NULL)
	),
	UNIQUE (event_type, finding_id, transport)
);

CREATE INDEX IF NOT EXISTS hub_finding_notification_outbox_due_idx
	ON hub_finding_notification_outbox (next_attempt_at, created_at, id)
	WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS hub_finding_notification_outbox_lease_idx
	ON hub_finding_notification_outbox (leased_until)
	WHERE delivered_at IS NULL AND leased_until IS NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS hub_finding_notification_outbox;
