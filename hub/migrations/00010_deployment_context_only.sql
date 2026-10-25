-- +goose Up
-- Deployment markers used to make two automatic triage decisions. Restore only
-- rows whose current state still carries those machine-written markers; a later
-- operator action overwrites status_reason and is therefore left untouched.
UPDATE hub_findings
SET status = 'open',
	status_reason = 'deployment_context_only_migration',
	status_note = 'Reopened automatically because deployment markers are now context only.',
	status_actor = 'hub:migration:00010',
	status_updated_at = now(),
	updated_at = now()
WHERE status = 'acknowledged'
	AND status_reason = 'deployment_window';

WITH deployment_adjusted AS (
	SELECT id,
		severity AS adjusted_severity,
		metadata,
		metadata #>> '{deployment_context,original_severity}' AS original_severity,
		CASE metadata #>> '{deployment_context,original_severity}'
			WHEN 'critical' THEN 90
			WHEN 'high' THEN 72
			WHEN 'medium' THEN 46
			WHEN 'low' THEN 22
			ELSE 8
		END AS original_severity_points,
		jsonb_typeof(metadata -> 'risk') = 'object'
			AND jsonb_typeof(metadata #> '{risk,factors}') = 'array' AS has_repairable_risk
	FROM hub_findings
	WHERE metadata #>> '{deployment_context,severity_adjusted}' = 'true'
		AND metadata #>> '{deployment_context,original_severity}' IN ('info', 'low', 'medium', 'high', 'critical')
		-- Do not restore a severity while leaving an unrecognized persisted risk
		-- record inconsistent. Legacy scorer output always has an object and array.
		AND (
			metadata -> 'risk' IS NULL
			OR (
				jsonb_typeof(metadata -> 'risk') = 'object'
				AND jsonb_typeof(metadata #> '{risk,factors}') = 'array'
			)
		)
		-- A later operator severity change must win over the old automatic adjustment.
		AND severity = metadata #>> '{deployment_context,adjusted_severity}'
), normalized_risk_factors AS (
	SELECT adjusted.id, normalized.ordinality, normalized.factor
	FROM deployment_adjusted AS adjusted
	CROSS JOIN LATERAL (
		-- The current scorer always emits the severity factor first.
		SELECT 0::bigint AS ordinality,
			jsonb_build_object(
				'id', 'severity:' || adjusted.original_severity,
				'points', adjusted.original_severity_points,
				'reason', 'finding severity'
			) AS factor
		UNION ALL
		SELECT legacy.ordinality, legacy.factor
		FROM jsonb_array_elements(
			CASE
				WHEN adjusted.has_repairable_risk THEN adjusted.metadata #> '{risk,factors}'
				ELSE '[]'::jsonb
			END
		)
			WITH ORDINALITY AS legacy(factor, ordinality)
		WHERE coalesce(legacy.factor ->> 'id', '') NOT LIKE 'severity:%'
			AND coalesce(legacy.factor ->> 'id', '') <> 'context:deployment_adjusted'
	) AS normalized
	WHERE adjusted.has_repairable_risk
), repaired_risk AS (
	SELECT id,
		jsonb_agg(factor ORDER BY ordinality) AS factors,
		least(100, greatest(0, sum(
			CASE
				WHEN jsonb_typeof(factor -> 'points') = 'number'
					AND factor ->> 'points' ~ '^-?[0-9]+$'
				THEN (factor ->> 'points')::integer
				ELSE 0
			END
		)))::integer AS score
	FROM normalized_risk_factors
	GROUP BY id
), repaired AS (
	SELECT adjusted.id,
		adjusted.original_severity,
		repaired_risk.factors,
		repaired_risk.score,
		CASE
			WHEN repaired_risk.score >= 85 THEN 'critical'
			WHEN repaired_risk.score >= 65 THEN 'high'
			WHEN repaired_risk.score >= 40 THEN 'medium'
			WHEN repaired_risk.score >= 20 THEN 'low'
			ELSE 'informational'
		END AS band
	FROM deployment_adjusted AS adjusted
	LEFT JOIN repaired_risk ON repaired_risk.id = adjusted.id
)
UPDATE hub_findings AS finding
SET severity = repaired.original_severity,
	metadata = CASE
		WHEN repaired.factors IS NULL THEN jsonb_set(
			jsonb_set(finding.metadata, '{deployment_context,severity_adjusted}', 'false'::jsonb),
			'{deployment_context,adjusted_severity}',
			to_jsonb(repaired.original_severity)
		)
		ELSE jsonb_set(
			jsonb_set(
				jsonb_set(
					jsonb_set(
						jsonb_set(
							jsonb_set(
								jsonb_set(finding.metadata, '{deployment_context,severity_adjusted}', 'false'::jsonb),
								'{deployment_context,adjusted_severity}',
								to_jsonb(repaired.original_severity)
							),
							'{risk,version}',
							to_jsonb('2026-08-04.1'::text)
						),
						'{risk,severity}',
						to_jsonb(repaired.original_severity)
					),
					'{risk,factors}',
					repaired.factors
				),
				'{risk,score}',
				to_jsonb(repaired.score)
			),
			'{risk,band}',
			to_jsonb(repaired.band)
		)
	END,
	updated_at = now()
FROM repaired
WHERE finding.id = repaired.id;

-- +goose Down
-- Corrective data recovery is intentionally irreversible. Reintroducing the old
-- automatic acknowledgement and severity reduction would lose operator signal.
