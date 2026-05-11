package local

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestCreateSiteNormalizesAndSaves(t *testing.T) {
	repo := &fakeSiteRepository{}
	application := New(domain.AppMeta{Binary: "aegrail"}, Dependencies{Sites: repo})

	site, err := application.CreateSite(context.Background(), CreateSiteInput{
		Slug:    "PetLink",
		Name:    "Petlink Demo",
		BaseURL: "https://petlink.example",
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if site.Slug != "petlink" {
		t.Fatalf("slug = %q, want petlink", site.Slug)
	}
	if site.Name != "Petlink Demo" {
		t.Fatalf("name = %q, want Petlink Demo", site.Name)
	}
	if site.BaseURL != "https://petlink.example" {
		t.Fatalf("baseURL = %q, want https://petlink.example", site.BaseURL)
	}
}

func TestCreateSiteRejectsInvalidSlug(t *testing.T) {
	application := New(domain.AppMeta{Binary: "aegrail"}, Dependencies{Sites: &fakeSiteRepository{}})

	_, err := application.CreateSite(context.Background(), CreateSiteInput{
		Slug: "bad slug",
	})
	if err == nil {
		t.Fatal("CreateSite returned nil error for invalid slug")
	}
}

func TestCreateSiteRejectsInvalidURL(t *testing.T) {
	application := New(domain.AppMeta{Binary: "aegrail"}, Dependencies{Sites: &fakeSiteRepository{}})

	_, err := application.CreateSite(context.Background(), CreateSiteInput{
		Slug:    "petlink",
		BaseURL: "ftp://petlink.example",
	})
	if err == nil {
		t.Fatal("CreateSite returned nil error for invalid URL")
	}
}

type fakeSiteRepository struct {
	sites []domain.Site
}

func (r *fakeSiteRepository) Save(_ context.Context, site domain.Site) (domain.Site, error) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	site.ID = "site-1"
	site.CreatedAt = now
	site.UpdatedAt = now
	r.sites = append(r.sites, site)
	return site, nil
}

func (r *fakeSiteRepository) List(_ context.Context) ([]domain.Site, error) {
	return r.sites, nil
}

func (r *fakeSiteRepository) FindBySlug(_ context.Context, slug string) (domain.Site, bool, error) {
	for _, site := range r.sites {
		if site.Slug == slug {
			return site, true, nil
		}
	}
	return domain.Site{}, false, nil
}
