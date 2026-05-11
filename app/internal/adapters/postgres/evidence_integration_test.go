package postgres

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rcooler/aegrail/internal/adapters/filesystem"
	"github.com/rcooler/aegrail/internal/domain"
	localapp "github.com/rcooler/aegrail/internal/local"
)

func TestEvidenceRepositoryCreateImportIntegration(t *testing.T) {
	databaseURL := os.Getenv("AEGRAIL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AEGRAIL_TEST_DATABASE_URL is not set")
	}

	pool, err := OpenPool(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var siteID domain.ID
	if err := pool.QueryRow(context.Background(), `select id::text from sites where slug = 'petlink'`).Scan(&siteID); err != nil {
		t.Fatal(err)
	}

	repo := NewEvidenceRepository(pool)
	created, wasCreated, err := repo.CreateImport(context.Background(), domain.EvidenceImport{
		SiteID:            siteID,
		SourceType:        "integration",
		SourceURI:         "integration",
		SourceFingerprint: "integration-fingerprint",
		Status:            domain.EvidenceImportProcessing,
		ToolName:          "aegrail",
		ToolVersion:       "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("created import ID is empty")
	}
	if !wasCreated {
		t.Fatal("first CreateImport returned wasCreated=false")
	}
}

func TestImportLocalEvidenceIntegration(t *testing.T) {
	databaseURL := os.Getenv("AEGRAIL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AEGRAIL_TEST_DATABASE_URL is not set")
	}

	pool, err := OpenPool(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	source := t.TempDir()
	sourceFile := filepath.Join(source, "access.log")
	if err := os.WriteFile(sourceFile, []byte("GET /admin?token=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	application := localapp.New(domain.AppMeta{Binary: "aegrail", Version: "test"}, localapp.Dependencies{
		Sites:    NewSiteRepository(pool),
		Evidence: NewEvidenceRepository(pool),
		Scanner:  filesystem.NewEvidenceScanner(),
		Archive:  filesystem.NewEvidenceArchive(dataDir),
	})

	result, err := application.ImportLocalEvidence(context.Background(), localapp.ImportLocalEvidenceInput{
		SiteSlug:   "petlink",
		SourceType: "integration_import",
		Path:       source,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Refs) != 1 {
		t.Fatalf("ref count = %d, want 1", len(result.Refs))
	}
	if _, err := os.Stat(filepath.FromSlash(result.Refs[0].URI)); err != nil {
		t.Fatalf("archived evidence missing: %v", err)
	}
}
