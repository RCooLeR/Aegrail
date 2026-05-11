package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type EvidenceScanner struct{}

func NewEvidenceScanner() *EvidenceScanner {
	return &EvidenceScanner{}
}

func (s *EvidenceScanner) ScanLocalEvidence(ctx context.Context, path string) (domain.EvidenceManifest, error) {
	root, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return domain.EvidenceManifest{}, err
	}

	info, err := os.Stat(root)
	if err != nil {
		return domain.EvidenceManifest{}, err
	}

	files := make([]domain.EvidenceFile, 0)
	if !info.IsDir() {
		file, err := hashEvidenceFile(ctx, root, filepath.Base(root))
		if err != nil {
			return domain.EvidenceManifest{}, err
		}
		files = append(files, file)
	} else {
		err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(root, current)
			if err != nil {
				return err
			}
			file, err := hashEvidenceFile(ctx, current, filepath.ToSlash(rel))
			if err != nil {
				return err
			}
			files = append(files, file)
			return nil
		})
		if err != nil {
			return domain.EvidenceManifest{}, err
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].RelativePath < files[j].RelativePath
	})

	return domain.EvidenceManifest{
		SourceURI:         root,
		SourceFingerprint: evidenceFingerprint(files),
		Files:             files,
	}, nil
}

type EvidenceArchive struct {
	dataDir string
}

func NewEvidenceArchive(dataDir string) *EvidenceArchive {
	return &EvidenceArchive{dataDir: dataDir}
}

func (a *EvidenceArchive) StoreLocalEvidence(ctx context.Context, siteSlug string, importID domain.ID, manifest domain.EvidenceManifest) ([]domain.EvidenceRef, error) {
	if strings.TrimSpace(a.dataDir) == "" {
		return nil, errors.New("data directory is required")
	}

	root := filepath.Join(filepath.Clean(a.dataDir), "evidence", siteSlug, string(importID))
	refs := make([]domain.EvidenceRef, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rel, err := safeRelativePath(file.RelativePath)
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		if err := copyFile(file.SourcePath, dst); err != nil {
			return nil, err
		}
		if _, err := os.Stat(dst); err != nil {
			return nil, fmt.Errorf("archived evidence was not written to %s: %w", dst, err)
		}

		absDst, err := filepath.Abs(dst)
		if err != nil {
			return nil, err
		}
		refs = append(refs, domain.EvidenceRef{
			ImportID:     importID,
			URI:          filepath.ToSlash(absDst),
			OriginalURI:  filepath.ToSlash(file.SourcePath),
			RelativePath: file.RelativePath,
			SHA256:       file.SHA256,
			ContentType:  file.ContentType,
			SizeBytes:    file.SizeBytes,
		})
	}
	return refs, nil
}

func (a *EvidenceArchive) EvidenceRefsExist(ctx context.Context, refs []domain.EvidenceRef) (bool, error) {
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, err := os.Stat(filepath.FromSlash(ref.URI)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

func hashEvidenceFile(ctx context.Context, path string, relativePath string) (domain.EvidenceFile, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceFile{}, err
	}

	file, err := os.Open(path)
	if err != nil {
		return domain.EvidenceFile{}, err
	}
	defer file.Close()

	hasher := sha256.New()
	header := make([]byte, 0, 512)
	buf := make([]byte, 32*1024)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return domain.EvidenceFile{}, err
		}

		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, err := hasher.Write(chunk); err != nil {
				return domain.EvidenceFile{}, err
			}
			size += int64(n)
			if len(header) < 512 {
				remaining := 512 - len(header)
				if n < remaining {
					remaining = n
				}
				header = append(header, chunk[:remaining]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return domain.EvidenceFile{}, readErr
		}
	}

	contentType := http.DetectContentType(header)
	if len(header) == 0 {
		contentType = "application/octet-stream"
	}

	return domain.EvidenceFile{
		SourcePath:   path,
		RelativePath: filepath.ToSlash(relativePath),
		SHA256:       hex.EncodeToString(hasher.Sum(nil)),
		ContentType:  contentType,
		SizeBytes:    size,
	}, nil
}

func evidenceFingerprint(files []domain.EvidenceFile) string {
	hasher := sha256.New()
	for _, file := range files {
		fmt.Fprintf(hasher, "%s\x00%d\x00%s\n", file.RelativePath, file.SizeBytes, file.SHA256)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func safeRelativePath(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", errors.New("relative path is required")
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe relative path %q", value)
	}
	return clean, nil
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
