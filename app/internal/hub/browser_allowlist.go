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
	return h.browserAllowlist.ListBrowserScriptAllowlistEntries(ctx, environment.ID, app.ID)
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
