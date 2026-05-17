package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

type ModelAnalysisReportRepository struct {
	pool *pgxpool.Pool
}

func NewModelAnalysisReportRepository(pool *pgxpool.Pool) *ModelAnalysisReportRepository {
	return &ModelAnalysisReportRepository{pool: pool}
}

func (r *ModelAnalysisReportRepository) SaveModelAnalysisReport(ctx context.Context, report domain.ModelAnalysisReport) (domain.ModelAnalysisReport, error) {
	const query = `
		INSERT INTO hub_model_analysis_reports (
			organization_id,
			project_id,
			environment_id,
			app_id,
			report_schema,
			status,
			model_provider,
			model_name,
			prompt_template_id,
			prompt_template_version,
			prompt_template_sha256,
			prompt_sha256,
			evidence_bundle_schema,
			evidence_bundle_sha256,
			evidence_bundle_redaction_version,
			evidence_bundle_generated_at,
			source_finding_ids,
			analysis,
			error,
			total_duration_millis,
			prompt_eval_count,
			eval_count,
			generated_at,
			metadata
		)
		VALUES (
			$1, $2, $3, nullif($4::text, '')::uuid,
			$5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24
		)
		RETURNING id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), report_schema, status, model_provider, model_name,
			prompt_template_id, prompt_template_version, prompt_template_sha256, prompt_sha256,
			evidence_bundle_schema, evidence_bundle_sha256, evidence_bundle_redaction_version,
			evidence_bundle_generated_at, source_finding_ids, analysis, error, total_duration_millis,
			prompt_eval_count, eval_count, generated_at, metadata, created_at
	`
	return r.scanModelAnalysisReport(r.pool.QueryRow(
		ctx,
		query,
		report.OrganizationID,
		report.ProjectID,
		report.EnvironmentID,
		string(report.AppID),
		report.ReportSchema,
		report.Status,
		report.ModelProvider,
		report.ModelName,
		report.PromptTemplateID,
		report.PromptTemplateVersion,
		report.PromptTemplateSHA256,
		report.PromptSHA256,
		report.EvidenceBundleSchema,
		report.EvidenceBundleSHA256,
		report.EvidenceBundleRedactionVersion,
		report.EvidenceBundleGeneratedAt,
		stringIDs(report.SourceFindingIDs),
		report.Analysis,
		report.Error,
		report.TotalDurationMillis,
		report.PromptEvalCount,
		report.EvalCount,
		report.GeneratedAt,
		nonNilAnyMap(report.Metadata),
	))
}

func (r *ModelAnalysisReportRepository) ListModelAnalysisReports(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.ModelAnalysisReport, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), report_schema, status, model_provider, model_name,
			prompt_template_id, prompt_template_version, prompt_template_sha256, prompt_sha256,
			evidence_bundle_schema, evidence_bundle_sha256, evidence_bundle_redaction_version,
			evidence_bundle_generated_at, source_finding_ids, analysis, error, total_duration_millis,
			prompt_eval_count, eval_count, generated_at, metadata, created_at
		FROM hub_model_analysis_reports
		WHERE environment_id = $1
			AND ($2::text = '' OR app_id = nullif($2::text, '')::uuid)
		ORDER BY generated_at DESC, created_at DESC
		LIMIT $3
	`
	rows, err := r.pool.Query(ctx, query, environmentID, string(appID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []domain.ModelAnalysisReport
	for rows.Next() {
		report, err := r.scanModelAnalysisReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (r *ModelAnalysisReportRepository) ListModelAnalysisReportsForFinding(ctx context.Context, environmentID domain.ID, appID domain.ID, findingID domain.ID, limit int) ([]domain.ModelAnalysisReport, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), report_schema, status, model_provider, model_name,
			prompt_template_id, prompt_template_version, prompt_template_sha256, prompt_sha256,
			evidence_bundle_schema, evidence_bundle_sha256, evidence_bundle_redaction_version,
			evidence_bundle_generated_at, source_finding_ids, analysis, error, total_duration_millis,
			prompt_eval_count, eval_count, generated_at, metadata, created_at
		FROM hub_model_analysis_reports
		WHERE environment_id = $1
			AND ($2::text = '' OR app_id = nullif($2::text, '')::uuid)
			AND source_finding_ids @> ARRAY[$3]::text[]
		ORDER BY generated_at DESC, created_at DESC
		LIMIT $4
	`
	rows, err := r.pool.Query(ctx, query, environmentID, string(appID), string(findingID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reports []domain.ModelAnalysisReport
	for rows.Next() {
		report, err := r.scanModelAnalysisReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (r *ModelAnalysisReportRepository) GetModelAnalysisReport(ctx context.Context, reportID domain.ID, environmentID domain.ID, appID domain.ID) (domain.ModelAnalysisReport, error) {
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), report_schema, status, model_provider, model_name,
			prompt_template_id, prompt_template_version, prompt_template_sha256, prompt_sha256,
			evidence_bundle_schema, evidence_bundle_sha256, evidence_bundle_redaction_version,
			evidence_bundle_generated_at, source_finding_ids, analysis, error, total_duration_millis,
			prompt_eval_count, eval_count, generated_at, metadata, created_at
		FROM hub_model_analysis_reports
		WHERE id = $1
			AND environment_id = $2
			AND ($3::text = '' OR app_id = nullif($3::text, '')::uuid)
	`
	return r.scanModelAnalysisReport(r.pool.QueryRow(ctx, query, reportID, environmentID, string(appID)))
}

func (r *ModelAnalysisReportRepository) FindModelAnalysisReportByEvidence(ctx context.Context, environmentID domain.ID, appID domain.ID, findingID domain.ID, evidenceBundleSHA256 string) (domain.ModelAnalysisReport, bool, error) {
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), report_schema, status, model_provider, model_name,
			prompt_template_id, prompt_template_version, prompt_template_sha256, prompt_sha256,
			evidence_bundle_schema, evidence_bundle_sha256, evidence_bundle_redaction_version,
			evidence_bundle_generated_at, source_finding_ids, analysis, error, total_duration_millis,
			prompt_eval_count, eval_count, generated_at, metadata, created_at
		FROM hub_model_analysis_reports
		WHERE environment_id = $1
			AND ($2::text = '' OR app_id = nullif($2::text, '')::uuid)
			AND source_finding_ids @> ARRAY[$3]::text[]
			AND evidence_bundle_sha256 = $4
		ORDER BY generated_at DESC, created_at DESC
		LIMIT 1
	`
	report, err := r.scanModelAnalysisReport(r.pool.QueryRow(ctx, query, environmentID, string(appID), string(findingID), evidenceBundleSHA256))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ModelAnalysisReport{}, false, nil
		}
		return domain.ModelAnalysisReport{}, false, err
	}
	return report, true, nil
}

func (r *ModelAnalysisReportRepository) FindLatestModelAnalysisReportByFinding(ctx context.Context, environmentID domain.ID, appID domain.ID, findingID domain.ID, promptTemplateID string, promptTemplateVersion string, modelName string) (domain.ModelAnalysisReport, bool, error) {
	const query = `
		SELECT id::text, organization_id::text, project_id::text, environment_id::text,
			coalesce(app_id::text, ''), report_schema, status, model_provider, model_name,
			prompt_template_id, prompt_template_version, prompt_template_sha256, prompt_sha256,
			evidence_bundle_schema, evidence_bundle_sha256, evidence_bundle_redaction_version,
			evidence_bundle_generated_at, source_finding_ids, analysis, error, total_duration_millis,
			prompt_eval_count, eval_count, generated_at, metadata, created_at
		FROM hub_model_analysis_reports
		WHERE environment_id = $1
			AND ($2::text = '' OR app_id = nullif($2::text, '')::uuid)
			AND source_finding_ids @> ARRAY[$3]::text[]
			AND prompt_template_id = $4
			AND prompt_template_version = $5
			AND ($6::text = '' OR model_name = $6)
		ORDER BY generated_at DESC, created_at DESC
		LIMIT 1
	`
	report, err := r.scanModelAnalysisReport(r.pool.QueryRow(ctx, query, environmentID, string(appID), string(findingID), promptTemplateID, promptTemplateVersion, modelName))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ModelAnalysisReport{}, false, nil
		}
		return domain.ModelAnalysisReport{}, false, err
	}
	return report, true, nil
}

type modelAnalysisReportRow interface {
	Scan(dest ...any) error
}

func (r *ModelAnalysisReportRepository) scanModelAnalysisReport(row modelAnalysisReportRow) (domain.ModelAnalysisReport, error) {
	var report domain.ModelAnalysisReport
	var sourceFindingIDs []string
	if err := row.Scan(
		&report.ID,
		&report.OrganizationID,
		&report.ProjectID,
		&report.EnvironmentID,
		&report.AppID,
		&report.ReportSchema,
		&report.Status,
		&report.ModelProvider,
		&report.ModelName,
		&report.PromptTemplateID,
		&report.PromptTemplateVersion,
		&report.PromptTemplateSHA256,
		&report.PromptSHA256,
		&report.EvidenceBundleSchema,
		&report.EvidenceBundleSHA256,
		&report.EvidenceBundleRedactionVersion,
		&report.EvidenceBundleGeneratedAt,
		&sourceFindingIDs,
		&report.Analysis,
		&report.Error,
		&report.TotalDurationMillis,
		&report.PromptEvalCount,
		&report.EvalCount,
		&report.GeneratedAt,
		&report.Metadata,
		&report.CreatedAt,
	); err != nil {
		return domain.ModelAnalysisReport{}, err
	}
	report.SourceFindingIDs = domainIDs(sourceFindingIDs)
	if report.Metadata == nil {
		report.Metadata = map[string]any{}
	}
	return report, nil
}
