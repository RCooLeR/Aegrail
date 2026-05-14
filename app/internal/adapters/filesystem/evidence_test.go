package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestEvidenceScannerBuildsStableManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "b.log"), []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.log"), []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner := NewEvidenceScanner()
	first, err := scanner.ScanLocalEvidence(context.Background(), root)
	if err != nil {
		t.Fatalf("first scan returned error: %v", err)
	}
	second, err := scanner.ScanLocalEvidence(context.Background(), root)
	if err != nil {
		t.Fatalf("second scan returned error: %v", err)
	}

	if first.SourceFingerprint == "" {
		t.Fatal("source fingerprint is empty")
	}
	if first.SourceFingerprint != second.SourceFingerprint {
		t.Fatalf("fingerprint changed across scans: %s != %s", first.SourceFingerprint, second.SourceFingerprint)
	}
	if len(first.Files) != 2 {
		t.Fatalf("file count = %d, want 2", len(first.Files))
	}
	if first.Files[0].RelativePath != "a.log" {
		t.Fatalf("first file = %q, want sorted a.log", first.Files[0].RelativePath)
	}
}

func TestEvidenceArchiveCopiesFiles(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.log")
	if err := os.WriteFile(src, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := NewEvidenceArchive(filepath.Join(root, "data"))
	refs, err := archive.StoreLocalEvidence(context.Background(), "demo-site", "import-1", domain.EvidenceManifest{
		Files: []domain.EvidenceFile{
			{
				SourcePath:   src,
				RelativePath: "source.log",
				SHA256:       "hash",
				ContentType:  "text/plain",
				SizeBytes:    6,
			},
		},
	})
	if err != nil {
		t.Fatalf("StoreLocalEvidence returned error: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("ref count = %d, want 1", len(refs))
	}
	if _, err := os.Stat(filepath.FromSlash(refs[0].URI)); err != nil {
		t.Fatalf("archived file does not exist: %v", err)
	}
}
