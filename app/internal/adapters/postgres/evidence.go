package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
)

type EvidenceRepository struct {
	pool *pgxpool.Pool
}

func NewEvidenceRepository(pool *pgxpool.Pool) *EvidenceRepository {
	return &EvidenceRepository{pool: pool}
}

func (r *EvidenceRepository) FindImportByFingerprint(ctx context.Context, siteID domain.ID, sourceType string, fingerprint string) (domain.EvidenceImport, []domain.EvidenceRef, bool, error) {
	evidenceImport, ok, err := r.findImport(ctx, siteID, sourceType, fingerprint)
	if err != nil || !ok {
		return domain.EvidenceImport{}, nil, ok, err
	}

	refs, err := r.ListEvidenceRefs(ctx, evidenceImport.ID)
	if err != nil {
		return domain.EvidenceImport{}, nil, false, err
	}
	return evidenceImport, refs, true, nil
}

func (r *EvidenceRepository) CreateImport(ctx context.Context, evidenceImport domain.EvidenceImport) (domain.EvidenceImport, bool, error) {
	const insertQuery = `
		INSERT INTO evidence_imports (
			site_id,
			source_type,
			source_uri,
			source_fingerprint,
			status,
			tool_name,
			tool_version
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT DO NOTHING
		RETURNING id::text, site_id::text, source_type, source_uri, source_fingerprint,
			status, started_at, finished_at, tool_name, tool_version, object_count
	`

	var saved domain.EvidenceImport
	err := r.pool.QueryRow(
		ctx,
		insertQuery,
		evidenceImport.SiteID,
		evidenceImport.SourceType,
		evidenceImport.SourceURI,
		evidenceImport.SourceFingerprint,
		evidenceImport.Status,
		evidenceImport.ToolName,
		evidenceImport.ToolVersion,
	).Scan(
		&saved.ID,
		&saved.SiteID,
		&saved.SourceType,
		&saved.SourceURI,
		&saved.SourceFingerprint,
		&saved.Status,
		&saved.StartedAt,
		&saved.FinishedAt,
		&saved.ToolName,
		&saved.ToolVersion,
		&saved.ObjectCount,
	)
	if err == nil {
		return saved, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.EvidenceImport{}, false, err
	}

	existing, ok, err := r.findImport(ctx, evidenceImport.SiteID, evidenceImport.SourceType, evidenceImport.SourceFingerprint)
	return existing, false, errIfNotFound(ok, err)
}

func (r *EvidenceRepository) CompleteImport(ctx context.Context, importID domain.ID, refs []domain.EvidenceRef) ([]domain.EvidenceRef, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	saved := make([]domain.EvidenceRef, 0, len(refs))
	for _, ref := range refs {
		const insertObjectQuery = `
			INSERT INTO evidence_objects (
				import_id,
				uri,
				original_uri,
				relative_path,
				sha256,
				content_type,
				size_bytes
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (import_id, relative_path) DO UPDATE
			SET uri = EXCLUDED.uri,
				original_uri = EXCLUDED.original_uri,
				sha256 = EXCLUDED.sha256,
				content_type = EXCLUDED.content_type,
				size_bytes = EXCLUDED.size_bytes
			RETURNING id::text, import_id::text, uri, original_uri, relative_path, sha256,
				content_type, size_bytes, created_at
		`

		var object domain.EvidenceRef
		if err := tx.QueryRow(
			ctx,
			insertObjectQuery,
			importID,
			ref.URI,
			ref.OriginalURI,
			ref.RelativePath,
			ref.SHA256,
			ref.ContentType,
			ref.SizeBytes,
		).Scan(
			&object.ID,
			&object.ImportID,
			&object.URI,
			&object.OriginalURI,
			&object.RelativePath,
			&object.SHA256,
			&object.ContentType,
			&object.SizeBytes,
			&object.CreatedAt,
		); err != nil {
			return nil, err
		}
		saved = append(saved, object)
	}

	const updateImportQuery = `
		UPDATE evidence_imports
		SET status = 'completed',
			finished_at = now(),
			object_count = $2,
			updated_at = now()
		WHERE id = $1
	`
	if _, err := tx.Exec(ctx, updateImportQuery, importID, len(saved)); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return saved, nil
}

func (r *EvidenceRepository) MarkImportFailed(ctx context.Context, importID domain.ID) error {
	const query = `
		UPDATE evidence_imports
		SET status = 'failed',
			finished_at = now(),
			updated_at = now()
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, importID)
	return err
}

func (r *EvidenceRepository) ListEvidenceRefs(ctx context.Context, importID domain.ID) ([]domain.EvidenceRef, error) {
	const query = `
		SELECT id::text, import_id::text, uri, original_uri, relative_path, sha256,
			content_type, size_bytes, created_at
		FROM evidence_objects
		WHERE import_id = $1
		ORDER BY relative_path ASC
	`

	rows, err := r.pool.Query(ctx, query, importID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	refs := make([]domain.EvidenceRef, 0)
	for rows.Next() {
		var ref domain.EvidenceRef
		if err := rows.Scan(
			&ref.ID,
			&ref.ImportID,
			&ref.URI,
			&ref.OriginalURI,
			&ref.RelativePath,
			&ref.SHA256,
			&ref.ContentType,
			&ref.SizeBytes,
			&ref.CreatedAt,
		); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func (r *EvidenceRepository) findImport(ctx context.Context, siteID domain.ID, sourceType string, fingerprint string) (domain.EvidenceImport, bool, error) {
	const query = `
		SELECT id::text, site_id::text, source_type, source_uri, source_fingerprint,
			status, started_at, finished_at, tool_name, tool_version, object_count
		FROM evidence_imports
		WHERE site_id = $1
			AND source_type = $2
			AND source_fingerprint = $3
	`

	var evidenceImport domain.EvidenceImport
	err := r.pool.QueryRow(ctx, query, siteID, sourceType, fingerprint).Scan(
		&evidenceImport.ID,
		&evidenceImport.SiteID,
		&evidenceImport.SourceType,
		&evidenceImport.SourceURI,
		&evidenceImport.SourceFingerprint,
		&evidenceImport.Status,
		&evidenceImport.StartedAt,
		&evidenceImport.FinishedAt,
		&evidenceImport.ToolName,
		&evidenceImport.ToolVersion,
		&evidenceImport.ObjectCount,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.EvidenceImport{}, false, nil
		}
		return domain.EvidenceImport{}, false, err
	}
	return evidenceImport, true, nil
}

func errIfNotFound(ok bool, err error) error {
	if err != nil {
		return err
	}
	if !ok {
		return pgx.ErrNoRows
	}
	return nil
}
