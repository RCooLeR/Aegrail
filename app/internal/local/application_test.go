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
		Slug:    "DemoSite",
		Name:    "Demo Site",
		BaseURL: "https://demo-site.example",
	})
	if err != nil {
		t.Fatalf("CreateSite returned error: %v", err)
	}

	if site.Slug != "demosite" {
		t.Fatalf("slug = %q, want demosite", site.Slug)
	}
	if site.Name != "Demo Site" {
		t.Fatalf("name = %q, want Demo Site", site.Name)
	}
	if site.BaseURL != "https://demo-site.example" {
		t.Fatalf("baseURL = %q, want https://demo-site.example", site.BaseURL)
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
		Slug:    "demo-site",
		BaseURL: "ftp://demo-site.example",
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
