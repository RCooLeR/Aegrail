package hub

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestAnalyzeBrowserScriptDriftDetectsNewDomainsInlineHashesAndTagManagers(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings})
	ctx := context.Background()

	environment, app := bootstrapBrowserDriftInventory(t, ctx, hub)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	pageURL := "https://example.test"
	ingest.timelineEvents = []domain.TimelineEvent{
		browserScriptTimelineEvent("evt-base-domain", environment.ID, app.ID, now.Add(-48*time.Hour), pageURL, map[string]any{
			"source_type": "dom",
			"domain":      "static.example.test",
			"url":         "https://static.example.test/app.js",
		}),
		browserScriptTimelineEvent("evt-base-inline", environment.ID, app.ID, now.Add(-47*time.Hour), pageURL, map[string]any{
			"source_type": "inline",
			"sha256":      "old-inline",
		}),
		browserScriptTimelineEvent("evt-base-tag", environment.ID, app.ID, now.Add(-46*time.Hour), pageURL, map[string]any{
			"source_type":     "dom",
			"domain":          "www.googletagmanager.com",
			"tag_manager":     true,
			"tag_manager_ids": []string{"GTM-OLD"},
		}),
		browserScriptTimelineEvent("evt-new-domain", environment.ID, app.ID, now.Add(-20*time.Minute), pageURL, map[string]any{
			"source_type": "network",
			"domain":      "cdn.bad.example",
			"url":         "https://cdn.bad.example/payload.js",
		}),
		browserScriptTimelineEvent("evt-new-inline", environment.ID, app.ID, now.Add(-19*time.Minute), pageURL, map[string]any{
			"source_type": "inline",
			"sha256":      "new-inline",
		}),
		browserScriptTimelineEvent("evt-new-tag", environment.ID, app.ID, now.Add(-18*time.Minute), pageURL, map[string]any{
			"source_type":     "dom",
			"domain":          "www.googletagmanager.com",
			"tag_manager":     true,
			"tag_manager_ids": []string{"GTM-NEW"},
		}),
	}

	result, err := hub.AnalyzeBrowserScriptDrift(ctx, AnalyzeBrowserScriptDriftInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		BaselineSince:    now.Add(-30 * 24 * time.Hour),
		ObserveSince:     now.Add(-24 * time.Hour),
		SaveFindings:     true,
	})
	if err != nil {
		t.Fatalf("AnalyzeBrowserScriptDrift returned error: %v", err)
	}
	if result.BaselineEvents != 3 || result.ObservedEvents != 3 {
		t.Fatalf("event counts = baseline %d observed %d", result.BaselineEvents, result.ObservedEvents)
	}
	if len(result.Drifts) != 3 {
		t.Fatalf("drifts = %#v, want 3", result.Drifts)
	}
	byRule := map[string]BrowserScriptDrift{}
	for _, drift := range result.Drifts {
		byRule[drift.RuleID] = drift
	}
	if byRule["browser-script-domain-new"].Value != "cdn.bad.example" {
		t.Fatalf("domain drift = %#v", byRule["browser-script-domain-new"])
	}
	if byRule["browser-inline-script-changed"].Value != "new-inline" {
		t.Fatalf("inline drift = %#v", byRule["browser-inline-script-changed"])
	}
	if byRule["browser-tag-manager-id-new"].Value != "GTM-NEW" || byRule["browser-tag-manager-id-new"].Severity != domain.SeverityHigh {
		t.Fatalf("tag manager drift = %#v", byRule["browser-tag-manager-id-new"])
	}
	if len(result.Findings) != 3 {
		t.Fatalf("saved findings = %#v, want 3", result.Findings)
	}
}

func TestAnalyzeBrowserScriptDriftSkipsPagesWithoutBaseline(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

	environment, app := bootstrapBrowserDriftInventory(t, ctx, hub)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		browserScriptTimelineEvent("evt-new-domain", environment.ID, app.ID, now.Add(-20*time.Minute), "https://new.example.test", map[string]any{
			"source_type": "dom",
			"domain":      "cdn.example.test",
		}),
	}

	result, err := hub.AnalyzeBrowserScriptDrift(ctx, AnalyzeBrowserScriptDriftInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		BaselineSince:    now.Add(-30 * 24 * time.Hour),
		ObserveSince:     now.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AnalyzeBrowserScriptDrift returned error: %v", err)
	}
	if len(result.Drifts) != 0 {
		t.Fatalf("drifts = %#v, want none without page baseline", result.Drifts)
	}
}

func TestAnalyzeBrowserScriptDriftSuppressesAllowedValues(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	allowlist := newMemoryBrowserScriptAllowlistRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, BrowserAllowlist: allowlist})
	ctx := context.Background()

	environment, app := bootstrapBrowserDriftInventory(t, ctx, hub)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	pageURL := "https://example.test"
	ingest.timelineEvents = []domain.TimelineEvent{
		browserScriptTimelineEvent("evt-base-domain", environment.ID, app.ID, now.Add(-48*time.Hour), pageURL, map[string]any{
			"source_type": "dom",
			"domain":      "static.example.test",
		}),
		browserScriptTimelineEvent("evt-new-domain", environment.ID, app.ID, now.Add(-20*time.Minute), pageURL, map[string]any{
			"source_type": "network",
			"domain":      "cdn.approved.example",
		}),
	}

	entry, err := hub.AllowBrowserScript(ctx, AllowBrowserScriptInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		PageURL:          pageURL + "/",
		Kind:             "script-domain",
		Value:            "cdn.approved.example",
		Reason:           "approved vendor",
		ApprovedBy:       "security",
	})
	if err != nil {
		t.Fatalf("AllowBrowserScript returned error: %v", err)
	}
	if entry.Kind != "domain" || entry.PageURL != pageURL {
		t.Fatalf("allowlist entry = %#v", entry)
	}

	result, err := hub.AnalyzeBrowserScriptDrift(ctx, AnalyzeBrowserScriptDriftInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		BaselineSince:    now.Add(-30 * 24 * time.Hour),
		ObserveSince:     now.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AnalyzeBrowserScriptDrift returned error: %v", err)
	}
	if len(result.Drifts) != 0 {
		t.Fatalf("drifts = %#v, want approved domain suppressed", result.Drifts)
	}
}

func TestUpdateBrowserScriptAllowlistStatusDisablesSuppression(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	allowlist := newMemoryBrowserScriptAllowlistRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, BrowserAllowlist: allowlist})
	ctx := context.Background()

	environment, app := bootstrapBrowserDriftInventory(t, ctx, hub)
	now := time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC)
	pageURL := "https://example.test"
	ingest.timelineEvents = []domain.TimelineEvent{
		browserScriptTimelineEvent("evt-base-domain", environment.ID, app.ID, now.Add(-48*time.Hour), pageURL, map[string]any{
			"source_type": "dom",
			"domain":      "static.example.test",
		}),
		browserScriptTimelineEvent("evt-new-domain", environment.ID, app.ID, now.Add(-20*time.Minute), pageURL, map[string]any{
			"source_type": "network",
			"domain":      "cdn.reviewed.example",
		}),
	}

	entry, err := hub.AllowBrowserScript(ctx, AllowBrowserScriptInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		PageURL:          pageURL,
		Kind:             "domain",
		Value:            "cdn.reviewed.example",
		Reason:           "initial review",
		ApprovedBy:       "security",
	})
	if err != nil {
		t.Fatalf("AllowBrowserScript returned error: %v", err)
	}

	disabled, err := hub.UpdateBrowserScriptAllowlistStatus(ctx, UpdateBrowserScriptAllowlistStatusInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		EntryID:          string(entry.ID),
		Status:           "disable",
		Reason:           "vendor removed",
		ApprovedBy:       "roman",
	})
	if err != nil {
		t.Fatalf("UpdateBrowserScriptAllowlistStatus returned error: %v", err)
	}
	if disabled.Status != "disabled" || disabled.Reason != "vendor removed" || disabled.ApprovedBy != "roman" {
		t.Fatalf("disabled entry = %#v, want disabled metadata", disabled)
	}

	result, err := hub.AnalyzeBrowserScriptDrift(ctx, AnalyzeBrowserScriptDriftInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		BaselineSince:    now.Add(-30 * 24 * time.Hour),
		ObserveSince:     now.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AnalyzeBrowserScriptDrift returned error: %v", err)
	}
	if len(result.Drifts) != 1 || result.Drifts[0].Value != "cdn.reviewed.example" {
		t.Fatalf("drifts = %#v, want disabled allowlist entry to stop suppressing", result.Drifts)
	}
}

func bootstrapBrowserDriftInventory(t *testing.T, ctx context.Context, hub *Hub) (domain.Environment, domain.MonitoredApp) {
	t.Helper()
	if _, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme"}); err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	if _, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site"}); err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production"})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	return environment, app
}

func browserScriptTimelineEvent(id string, environmentID domain.ID, appID domain.ID, eventTime time.Time, pageURL string, payload map[string]any) domain.TimelineEvent {
	payload["page_url"] = pageURL
	payload["final_url"] = pageURL
	return domain.TimelineEvent{
		ID:            domain.ID(id),
		EnvironmentID: environmentID,
		AppID:         appID,
		HostSlug:      "web-01",
		EventTime:     eventTime,
		EventType:     "browser.script.observed",
		Target:        payloadStringAny(payload, "url", pageURL),
		Severity:      domain.SeverityInfo,
		Payload:       payload,
	}
}

type memoryBrowserScriptAllowlistRepository struct {
	entries map[string]domain.BrowserScriptAllowlistEntry
}

func newMemoryBrowserScriptAllowlistRepository() *memoryBrowserScriptAllowlistRepository {
	return &memoryBrowserScriptAllowlistRepository{entries: map[string]domain.BrowserScriptAllowlistEntry{}}
}

func (r *memoryBrowserScriptAllowlistRepository) SaveBrowserScriptAllowlistEntry(ctx context.Context, entry domain.BrowserScriptAllowlistEntry) (domain.BrowserScriptAllowlistEntry, error) {
	key := string(entry.EnvironmentID) + ":" + string(entry.AppID) + ":" + entry.PageURL + ":" + entry.Kind + ":" + entry.Value
	existing, ok := r.entries[key]
	now := time.Now().UTC()
	if ok {
		entry.ID = existing.ID
		entry.CreatedAt = existing.CreatedAt
	} else {
		entry.ID = domain.ID("allow-" + entry.Kind + "-" + entry.Value)
		entry.CreatedAt = now
	}
	entry.UpdatedAt = now
	r.entries[key] = entry
	return entry, nil
}

func (r *memoryBrowserScriptAllowlistRepository) ListBrowserScriptAllowlistEntries(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.BrowserScriptAllowlistEntry, error) {
	var entries []domain.BrowserScriptAllowlistEntry
	for _, entry := range r.entries {
		if entry.EnvironmentID == environmentID && entry.AppID == appID {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (r *memoryBrowserScriptAllowlistRepository) UpdateBrowserScriptAllowlistEntryStatus(ctx context.Context, entryID domain.ID, environmentID domain.ID, appID domain.ID, update domain.BrowserScriptAllowlistStatusUpdate) (domain.BrowserScriptAllowlistEntry, error) {
	now := time.Now().UTC()
	for key, entry := range r.entries {
		if entry.ID != entryID || entry.EnvironmentID != environmentID || entry.AppID != appID {
			continue
		}
		entry.Status = update.Status
		entry.Reason = update.Reason
		entry.ApprovedBy = update.ApprovedBy
		entry.UpdatedAt = now
		r.entries[key] = entry
		return entry, nil
	}
	return domain.BrowserScriptAllowlistEntry{}, fmt.Errorf("allowlist entry %q was not found", entryID)
}
