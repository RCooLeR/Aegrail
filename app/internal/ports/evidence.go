package ports

import (
	"context"

	"github.com/rcooler/aegrail/internal/domain"
)

type EvidenceRepository interface {
	FindImportByFingerprint(ctx context.Context, siteID domain.ID, sourceType string, fingerprint string) (domain.EvidenceImport, []domain.EvidenceRef, bool, error)
	CreateImport(ctx context.Context, evidenceImport domain.EvidenceImport) (domain.EvidenceImport, bool, error)
	CompleteImport(ctx context.Context, importID domain.ID, refs []domain.EvidenceRef) ([]domain.EvidenceRef, error)
	MarkImportFailed(ctx context.Context, importID domain.ID) error
	ListEvidenceRefs(ctx context.Context, importID domain.ID) ([]domain.EvidenceRef, error)
}

type LocalEvidenceScanner interface {
	ScanLocalEvidence(ctx context.Context, path string) (domain.EvidenceManifest, error)
}

type EvidenceArchive interface {
	StoreLocalEvidence(ctx context.Context, siteSlug string, importID domain.ID, manifest domain.EvidenceManifest) ([]domain.EvidenceRef, error)
	EvidenceRefsExist(ctx context.Context, refs []domain.EvidenceRef) (bool, error)
}
