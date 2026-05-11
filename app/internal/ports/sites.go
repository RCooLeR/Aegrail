package ports

import (
	"context"

	"github.com/rcooler/aegrail/internal/domain"
)

type SiteRepository interface {
	Save(ctx context.Context, site domain.Site) (domain.Site, error)
	List(ctx context.Context) ([]domain.Site, error)
	FindBySlug(ctx context.Context, slug string) (domain.Site, bool, error)
}
