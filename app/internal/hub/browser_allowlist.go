package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type AllowBrowserScriptInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	PageURL          string
	Kind             string
	Value            string
	Reason           string
	ApprovedBy       string
}

type ListBrowserScriptAllowlistInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	PageURL          string
	Kind             string
	Status           string
}

type UpdateBrowserScriptAllowlistStatusInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	EntryID          string
	Status           string
	Reason           string
	ApprovedBy       string
}

func (h *Hub) AllowBrowserScript(ctx context.Context, input AllowBrowserScriptInput) (domain.BrowserScriptAllowlistEntry, error) {
	if h.browserAllowlist == nil {
		return domain.BrowserScriptAllowlistEntry{}, errors.New("browser script allowlist repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	kind, err := normalizeBrowserScriptAllowlistKind(input.Kind)
	if err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	value := strings.TrimSpace(input.Value)
	if value == "" {
		return domain.BrowserScriptAllowlistEntry{}, errors.New("allowlist value is required")
	}
	org, project, environment, err := h.resolveEnvironmentContext(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	return h.browserAllowlist.SaveBrowserScriptAllowlistEntry(ctx, domain.BrowserScriptAllowlistEntry{
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  environment.ID,
		AppID:          app.ID,
		PageURL:        normalizeBrowserPageURL(input.PageURL),
		Kind:           kind,
		Value:          value,
		Reason:         strings.TrimSpace(input.Reason),
		ApprovedBy:     strings.TrimSpace(input.ApprovedBy),
		Status:         "active",
	})
}

func (h *Hub) ListBrowserScriptAllowlist(ctx context.Context, input ListBrowserScriptAllowlistInput) ([]domain.BrowserScriptAllowlistEntry, error) {
	if h.browserAllowlist == nil {
		return nil, errors.New("browser script allowlist repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return nil, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return nil, err
	}
	app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return nil, err
	}
	entries, err := h.browserAllowlist.ListBrowserScriptAllowlistEntries(ctx, environment.ID, app.ID)
	if err != nil {
		return nil, err
	}
	return filterBrowserScriptAllowlistEntries(entries, input)
}

func (h *Hub) UpdateBrowserScriptAllowlistStatus(ctx context.Context, input UpdateBrowserScriptAllowlistStatusInput) (domain.BrowserScriptAllowlistEntry, error) {
	if h.browserAllowlist == nil {
		return domain.BrowserScriptAllowlistEntry{}, errors.New("browser script allowlist repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	entryID := domain.ID(strings.TrimSpace(input.EntryID))
	if entryID == "" {
		return domain.BrowserScriptAllowlistEntry{}, errors.New("allowlist entry id is required")
	}
	status, err := normalizeBrowserScriptAllowlistStatus(input.Status)
	if err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return domain.BrowserScriptAllowlistEntry{}, err
	}
	return h.browserAllowlist.UpdateBrowserScriptAllowlistEntryStatus(ctx, entryID, environment.ID, app.ID, domain.BrowserScriptAllowlistStatusUpdate{
		Status:     status,
		Reason:     strings.TrimSpace(input.Reason),
		ApprovedBy: strings.TrimSpace(input.ApprovedBy),
	})
}

func filterBrowserScriptAllowlistEntries(entries []domain.BrowserScriptAllowlistEntry, input ListBrowserScriptAllowlistInput) ([]domain.BrowserScriptAllowlistEntry, error) {
	page := normalizeBrowserPageURL(input.PageURL)
	kind := ""
	if strings.TrimSpace(input.Kind) != "" {
		normalized, err := normalizeBrowserScriptAllowlistKind(input.Kind)
		if err != nil {
			return nil, err
		}
		kind = normalized
	}
	status := strings.ToLower(strings.TrimSpace(input.Status))
	if status != "" {
		normalized, err := normalizeBrowserScriptAllowlistStatus(status)
		if err != nil {
			return nil, err
		}
		status = normalized
	}
	filtered := make([]domain.BrowserScriptAllowlistEntry, 0, len(entries))
	for _, entry := range entries {
		if page != "" && normalizeBrowserPageURL(entry.PageURL) != page {
			continue
		}
		if kind != "" && entry.Kind != kind {
			continue
		}
		entryStatus := entry.Status
		if entryStatus == "" {
			entryStatus = "active"
		}
		if status != "" && entryStatus != status {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, nil
}

func normalizeBrowserScriptAllowlistKind(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	switch value {
	case "domain", "script_domain":
		return "domain", nil
	case "inline", "inline_script", "inline_hash", "sha256":
		return "inline_hash", nil
	case "tag_manager", "tag_manager_id", "gtm", "container":
		return "tag_manager_id", nil
	default:
		return "", fmt.Errorf("browser script allowlist kind %q is not supported", value)
	}
}

func normalizeBrowserPageURL(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, "#")
	return strings.TrimRight(value, "/")
}

func normalizeBrowserScriptAllowlistStatus(value string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(value))
	status = strings.ReplaceAll(status, "-", "_")
	switch status {
	case "active", "enabled", "enable":
		return "active", nil
	case "disabled", "disable", "inactive":
		return "disabled", nil
	default:
		return "", fmt.Errorf("browser script allowlist status %q is not supported", value)
	}
}
