package filesystem

import (
	"context"
	"os"
	"path/filepath"
)

type Workspace struct{}

func NewWorkspace() *Workspace {
	return &Workspace{}
}

func (w *Workspace) EnsureProjectDirs(ctx context.Context, dataDir string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root := filepath.Clean(dataDir)
	dirs := []string{
		root,
		filepath.Join(root, "evidence"),
		filepath.Join(root, "reports"),
		filepath.Join(root, "snapshots"),
		filepath.Join(root, "tmp"),
	}

	created := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		created = append(created, dir)
	}

	return created, nil
}
