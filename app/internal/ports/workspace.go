package ports

import (
	"context"
)

type ProjectWorkspace interface {
	EnsureProjectDirs(ctx context.Context, dataDir string) ([]string, error)
}
