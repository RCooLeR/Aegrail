package ports

import "context"

type DatabaseMigrator interface {
	Up(ctx context.Context) error
	Status(ctx context.Context) error
}
