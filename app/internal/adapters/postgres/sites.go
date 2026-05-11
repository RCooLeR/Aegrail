package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
)

type SiteRepository struct {
	pool *pgxpool.Pool
}

func NewSiteRepository(pool *pgxpool.Pool) *SiteRepository {
	return &SiteRepository{pool: pool}
}

func (r *SiteRepository) Save(ctx context.Context, site domain.Site) (domain.Site, error) {
	const query = `
		INSERT INTO sites (slug, name, base_url)
		VALUES ($1, $2, $3)
		ON CONFLICT (slug) DO UPDATE
		SET name = EXCLUDED.name,
			base_url = EXCLUDED.base_url,
			updated_at = now()
		RETURNING id::text, slug::text, name, base_url, created_at, updated_at
	`

	var saved domain.Site
	err := r.pool.QueryRow(ctx, query, site.Slug, site.Name, site.BaseURL).Scan(
		&saved.ID,
		&saved.Slug,
		&saved.Name,
		&saved.BaseURL,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	)
	if err != nil {
		return domain.Site{}, err
	}
	return saved, nil
}

func (r *SiteRepository) List(ctx context.Context) ([]domain.Site, error) {
	const query = `
		SELECT id::text, slug::text, name, base_url, created_at, updated_at
		FROM sites
		ORDER BY slug ASC
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sites := make([]domain.Site, 0)
	for rows.Next() {
		var site domain.Site
		if err := rows.Scan(
			&site.ID,
			&site.Slug,
			&site.Name,
			&site.BaseURL,
			&site.CreatedAt,
			&site.UpdatedAt,
		); err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

func (r *SiteRepository) FindBySlug(ctx context.Context, slug string) (domain.Site, bool, error) {
	const query = `
		SELECT id::text, slug::text, name, base_url, created_at, updated_at
		FROM sites
		WHERE slug = $1
	`

	var site domain.Site
	err := r.pool.QueryRow(ctx, query, slug).Scan(
		&site.ID,
		&site.Slug,
		&site.Name,
		&site.BaseURL,
		&site.CreatedAt,
		&site.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Site{}, false, nil
		}
		return domain.Site{}, false, err
	}
	return site, true, nil
}
