package local

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/ports"
)

type Application struct {
	meta      domain.AppMeta
	workspace ports.ProjectWorkspace
	sites     ports.SiteRepository
	migrator  ports.DatabaseMigrator
	evidence  ports.EvidenceRepository
	scanner   ports.LocalEvidenceScanner
	archive   ports.EvidenceArchive
}

type Dependencies struct {
	Workspace ports.ProjectWorkspace
	Sites     ports.SiteRepository
	Migrator  ports.DatabaseMigrator
	Evidence  ports.EvidenceRepository
	Scanner   ports.LocalEvidenceScanner
	Archive   ports.EvidenceArchive
}

func New(meta domain.AppMeta, deps Dependencies) *Application {
	return &Application{
		meta:      meta,
		workspace: deps.Workspace,
		sites:     deps.Sites,
		migrator:  deps.Migrator,
		evidence:  deps.Evidence,
		scanner:   deps.Scanner,
		archive:   deps.Archive,
	}
}

func (a *Application) Meta() domain.AppMeta {
	return a.meta
}

type InitProjectInput struct {
	DataDir string
}

type InitProjectResult struct {
	DataDir     string
	CreatedDirs []string
}

func (a *Application) InitProject(ctx context.Context, input InitProjectInput) (InitProjectResult, error) {
	dataDir := strings.TrimSpace(input.DataDir)
	if dataDir == "" {
		return InitProjectResult{}, errors.New("data directory is required")
	}
	if a.workspace == nil {
		return InitProjectResult{}, errors.New("project workspace adapter is not configured")
	}

	createdDirs, err := a.workspace.EnsureProjectDirs(ctx, dataDir)
	if err != nil {
		return InitProjectResult{}, err
	}

	return InitProjectResult{
		DataDir:     dataDir,
		CreatedDirs: createdDirs,
	}, nil
}

type CreateSiteInput struct {
	Slug    string
	Name    string
	BaseURL string
}

func (a *Application) CreateSite(ctx context.Context, input CreateSiteInput) (domain.Site, error) {
	if a.sites == nil {
		return domain.Site{}, errors.New("site repository is not configured")
	}

	slug, err := domain.NormalizeSlug("site", input.Slug)
	if err != nil {
		return domain.Site{}, err
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = slug
	}

	baseURL, err := domain.NormalizeBaseURL(input.BaseURL)
	if err != nil {
		return domain.Site{}, err
	}

	return a.sites.Save(ctx, domain.Site{
		Slug:    slug,
		Name:    name,
		BaseURL: baseURL,
	})
}

func (a *Application) ListSites(ctx context.Context) ([]domain.Site, error) {
	if a.sites == nil {
		return nil, errors.New("site repository is not configured")
	}
	return a.sites.List(ctx)
}

func (a *Application) MigrateDatabase(ctx context.Context) error {
	if a.migrator == nil {
		return errors.New("database migrator is not configured")
	}
	return a.migrator.Up(ctx)
}

func (a *Application) DatabaseStatus(ctx context.Context) error {
	if a.migrator == nil {
		return errors.New("database migrator is not configured")
	}
	return a.migrator.Status(ctx)
}

type ImportLocalEvidenceInput struct {
	SiteSlug   string
	SourceType string
	Path       string
}

type ImportLocalEvidenceResult struct {
	Import domain.EvidenceImport
	Refs   []domain.EvidenceRef
	Reused bool
}

func (a *Application) ImportLocalEvidence(ctx context.Context, input ImportLocalEvidenceInput) (ImportLocalEvidenceResult, error) {
	if a.sites == nil {
		return ImportLocalEvidenceResult{}, errors.New("site repository is not configured")
	}
	if a.evidence == nil {
		return ImportLocalEvidenceResult{}, errors.New("evidence repository is not configured")
	}
	if a.scanner == nil {
		return ImportLocalEvidenceResult{}, errors.New("local evidence scanner is not configured")
	}
	if a.archive == nil {
		return ImportLocalEvidenceResult{}, errors.New("evidence archive is not configured")
	}

	siteSlug, err := domain.NormalizeSlug("site", input.SiteSlug)
	if err != nil {
		return ImportLocalEvidenceResult{}, err
	}
	sourceType, err := domain.NormalizeSourceType(input.SourceType)
	if err != nil {
		return ImportLocalEvidenceResult{}, err
	}
	path := strings.TrimSpace(input.Path)
	if path == "" {
		return ImportLocalEvidenceResult{}, errors.New("import path is required")
	}

	site, ok, err := a.sites.FindBySlug(ctx, siteSlug)
	if err != nil {
		return ImportLocalEvidenceResult{}, err
	}
	if !ok {
		return ImportLocalEvidenceResult{}, fmt.Errorf("site %q does not exist", siteSlug)
	}

	manifest, err := a.scanner.ScanLocalEvidence(ctx, path)
	if err != nil {
		return ImportLocalEvidenceResult{}, err
	}
	if len(manifest.Files) == 0 {
		return ImportLocalEvidenceResult{}, fmt.Errorf("no files found under %q", path)
	}

	existingImport, refs, ok, err := a.evidence.FindImportByFingerprint(ctx, site.ID, sourceType, manifest.SourceFingerprint)
	if err != nil {
		return ImportLocalEvidenceResult{}, err
	}
	var evidenceImport domain.EvidenceImport
	if ok {
		if existingImport.Status == domain.EvidenceImportCompleted && len(refs) > 0 {
			refsExist, err := a.archive.EvidenceRefsExist(ctx, refs)
			if err != nil {
				return ImportLocalEvidenceResult{}, err
			}
			if refsExist {
				return ImportLocalEvidenceResult{
					Import: existingImport,
					Refs:   refs,
					Reused: true,
				}, nil
			}
		}
		evidenceImport = existingImport
	} else {
		var created bool
		evidenceImport, created, err = a.evidence.CreateImport(ctx, domain.EvidenceImport{
			SiteID:            site.ID,
			SourceType:        sourceType,
			SourceURI:         manifest.SourceURI,
			SourceFingerprint: manifest.SourceFingerprint,
			Status:            domain.EvidenceImportProcessing,
			ToolName:          a.meta.Binary,
			ToolVersion:       a.meta.Version,
		})
		if err != nil {
			return ImportLocalEvidenceResult{}, err
		}
		if !created {
			refs, err := a.evidence.ListEvidenceRefs(ctx, evidenceImport.ID)
			if err != nil {
				return ImportLocalEvidenceResult{}, err
			}
			if evidenceImport.Status == domain.EvidenceImportCompleted && len(refs) > 0 {
				refsExist, err := a.archive.EvidenceRefsExist(ctx, refs)
				if err != nil {
					return ImportLocalEvidenceResult{}, err
				}
				if refsExist {
					return ImportLocalEvidenceResult{
						Import: evidenceImport,
						Refs:   refs,
						Reused: true,
					}, nil
				}
			}
		}
	}

	archivedRefs, err := a.archive.StoreLocalEvidence(ctx, site.Slug, evidenceImport.ID, manifest)
	if err != nil {
		_ = a.evidence.MarkImportFailed(ctx, evidenceImport.ID)
		return ImportLocalEvidenceResult{}, err
	}

	savedRefs, err := a.evidence.CompleteImport(ctx, evidenceImport.ID, archivedRefs)
	if err != nil {
		_ = a.evidence.MarkImportFailed(ctx, evidenceImport.ID)
		return ImportLocalEvidenceResult{}, err
	}
	evidenceImport.Status = domain.EvidenceImportCompleted
	evidenceImport.ObjectCount = len(savedRefs)

	return ImportLocalEvidenceResult{
		Import: evidenceImport,
		Refs:   savedRefs,
		Reused: false,
	}, nil
}
