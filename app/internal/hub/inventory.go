package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/ports"
)

type Hub struct {
	inventory        ports.InventoryRepository
	ingest           ports.IngestRepository
	findings         ports.HubFindingRepository
	browserAllowlist ports.BrowserScriptAllowlistRepository
	modelReports     ports.ModelAnalysisReportRepository
	users            ports.HubUserRepository
	userSecretKey    string
}

type Dependencies struct {
	Inventory        ports.InventoryRepository
	Ingest           ports.IngestRepository
	Findings         ports.HubFindingRepository
	BrowserAllowlist ports.BrowserScriptAllowlistRepository
	ModelReports     ports.ModelAnalysisReportRepository
	Users            ports.HubUserRepository
	UserSecretKey    string
}

func New(deps Dependencies) *Hub {
	return &Hub{
		inventory:        deps.Inventory,
		ingest:           deps.Ingest,
		findings:         deps.Findings,
		browserAllowlist: deps.BrowserAllowlist,
		modelReports:     deps.ModelReports,
		users:            deps.Users,
		userSecretKey:    strings.TrimSpace(deps.UserSecretKey),
	}
}

type SaveOrganizationInput struct {
	Slug string
	Name string
}

type SaveProjectInput struct {
	OrganizationSlug string
	Slug             string
	Name             string
}

type SaveEnvironmentInput struct {
	OrganizationSlug string
	ProjectSlug      string
	Slug             string
	Name             string
}

type SaveMonitoredAppInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	Slug             string
	Name             string
	Kind             string
}

type SaveServiceInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Slug             string
	Name             string
	Role             string
}

type SaveHostInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	Slug             string
	Hostname         string
	Region           string
	Labels           map[string]string
}

type SaveAgentInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	HostSlug         string
	AgentID          string
	Fingerprint      string
	Version          string
}

type SaveDeploymentMarkerInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Version          string
	CommitSHA        string
	Actor            string
	StartedAt        time.Time
	FinishedAt       *time.Time
}

func (h *Hub) SaveOrganization(ctx context.Context, input SaveOrganizationInput) (domain.Organization, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Organization{}, err
	}
	slug, err := domain.NormalizeSlug("organization", input.Slug)
	if err != nil {
		return domain.Organization{}, err
	}
	return h.inventory.SaveOrganization(ctx, domain.Organization{
		Slug: slug,
		Name: defaultName(input.Name, slug),
	})
}

func (h *Hub) ListOrganizations(ctx context.Context) ([]domain.Organization, error) {
	if err := h.requireInventory(); err != nil {
		return nil, err
	}
	return h.inventory.ListOrganizations(ctx)
}

func (h *Hub) SaveProject(ctx context.Context, input SaveProjectInput) (domain.Project, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Project{}, err
	}
	org, err := h.resolveOrganization(ctx, input.OrganizationSlug)
	if err != nil {
		return domain.Project{}, err
	}
	slug, err := domain.NormalizeSlug("project", input.Slug)
	if err != nil {
		return domain.Project{}, err
	}
	return h.inventory.SaveProject(ctx, domain.Project{
		OrganizationID: org.ID,
		Slug:           slug,
		Name:           defaultName(input.Name, slug),
	})
}

func (h *Hub) ListProjects(ctx context.Context, organizationSlug string) ([]domain.Project, error) {
	if err := h.requireInventory(); err != nil {
		return nil, err
	}
	org, err := h.resolveOrganization(ctx, organizationSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListProjects(ctx, org.ID)
}

func (h *Hub) SaveEnvironment(ctx context.Context, input SaveEnvironmentInput) (domain.Environment, error) {
	project, err := h.resolveProjectPath(ctx, input.OrganizationSlug, input.ProjectSlug)
	if err != nil {
		return domain.Environment{}, err
	}
	slug, err := domain.NormalizeSlug("environment", input.Slug)
	if err != nil {
		return domain.Environment{}, err
	}
	return h.inventory.SaveEnvironment(ctx, domain.Environment{
		ProjectID: project.ID,
		Slug:      slug,
		Name:      defaultName(input.Name, slug),
	})
}

func (h *Hub) ListEnvironments(ctx context.Context, organizationSlug string, projectSlug string) ([]domain.Environment, error) {
	project, err := h.resolveProjectPath(ctx, organizationSlug, projectSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListEnvironments(ctx, project.ID)
}

func (h *Hub) SaveMonitoredApp(ctx context.Context, input SaveMonitoredAppInput) (domain.MonitoredApp, error) {
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.MonitoredApp{}, err
	}
	slug, err := domain.NormalizeSlug("app", input.Slug)
	if err != nil {
		return domain.MonitoredApp{}, err
	}
	return h.inventory.SaveMonitoredApp(ctx, domain.MonitoredApp{
		EnvironmentID: environment.ID,
		Slug:          slug,
		Name:          defaultName(input.Name, slug),
		Kind:          strings.TrimSpace(input.Kind),
	})
}

func (h *Hub) ListMonitoredApps(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) ([]domain.MonitoredApp, error) {
	environment, err := h.resolveEnvironmentPath(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListMonitoredApps(ctx, environment.ID)
}

func (h *Hub) SaveService(ctx context.Context, input SaveServiceInput) (domain.Service, error) {
	app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return domain.Service{}, err
	}
	slug, err := domain.NormalizeSlug("service", input.Slug)
	if err != nil {
		return domain.Service{}, err
	}
	return h.inventory.SaveService(ctx, domain.Service{
		AppID: app.ID,
		Slug:  slug,
		Name:  defaultName(input.Name, slug),
		Role:  strings.TrimSpace(input.Role),
	})
}

func (h *Hub) ListServices(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string) ([]domain.Service, error) {
	app, err := h.resolveAppPath(ctx, organizationSlug, projectSlug, environmentSlug, appSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListServices(ctx, app.ID)
}

func (h *Hub) SaveHost(ctx context.Context, input SaveHostInput) (domain.Host, error) {
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.Host{}, err
	}
	slug, err := domain.NormalizeSlug("host", input.Slug)
	if err != nil {
		return domain.Host{}, err
	}
	hostname := strings.TrimSpace(input.Hostname)
	if hostname == "" {
		hostname = slug
	}
	return h.inventory.SaveHost(ctx, domain.Host{
		EnvironmentID: environment.ID,
		Slug:          slug,
		Hostname:      hostname,
		Region:        strings.TrimSpace(input.Region),
		Labels:        input.Labels,
	})
}

func (h *Hub) ListHosts(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) ([]domain.Host, error) {
	environment, err := h.resolveEnvironmentPath(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListHosts(ctx, environment.ID)
}

func (h *Hub) SaveAgent(ctx context.Context, input SaveAgentInput) (domain.Agent, error) {
	host, err := h.resolveHostPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.HostSlug)
	if err != nil {
		return domain.Agent{}, err
	}
	agentID := strings.TrimSpace(input.AgentID)
	if agentID == "" {
		return domain.Agent{}, errors.New("agent id is required")
	}
	fingerprint := strings.TrimSpace(input.Fingerprint)
	if fingerprint == "" {
		return domain.Agent{}, errors.New("agent fingerprint is required")
	}
	now := time.Now().UTC()
	return h.inventory.SaveAgent(ctx, domain.Agent{
		HostID:      host.ID,
		AgentID:     agentID,
		Fingerprint: fingerprint,
		Version:     strings.TrimSpace(input.Version),
		LastSeenAt:  &now,
	})
}

func (h *Hub) ListAgents(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, hostSlug string) ([]domain.Agent, error) {
	host, err := h.resolveHostPath(ctx, organizationSlug, projectSlug, environmentSlug, hostSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListAgents(ctx, host.ID)
}

func (h *Hub) SaveDeploymentMarker(ctx context.Context, input SaveDeploymentMarkerInput) (domain.DeploymentMarker, error) {
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return domain.DeploymentMarker{}, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return domain.DeploymentMarker{}, err
		}
		appID = app.ID
	}
	version := strings.TrimSpace(input.Version)
	if version == "" {
		return domain.DeploymentMarker{}, errors.New("deployment version is required")
	}
	startedAt := input.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	return h.inventory.SaveDeploymentMarker(ctx, domain.DeploymentMarker{
		EnvironmentID: environment.ID,
		AppID:         appID,
		Version:       version,
		CommitSHA:     strings.TrimSpace(input.CommitSHA),
		Actor:         strings.TrimSpace(input.Actor),
		StartedAt:     startedAt.UTC(),
		FinishedAt:    input.FinishedAt,
	})
}

func (h *Hub) ListDeploymentMarkers(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string) ([]domain.DeploymentMarker, error) {
	environment, err := h.resolveEnvironmentPath(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return nil, err
	}
	var appID domain.ID
	if strings.TrimSpace(appSlug) != "" {
		app, err := h.resolveAppPath(ctx, organizationSlug, projectSlug, environmentSlug, appSlug)
		if err != nil {
			return nil, err
		}
		appID = app.ID
	}
	return h.inventory.ListDeploymentMarkers(ctx, environment.ID, appID)
}

func (h *Hub) requireInventory() error {
	if h.inventory == nil {
		return errors.New("inventory repository is not configured")
	}
	return nil
}

func (h *Hub) resolveOrganization(ctx context.Context, organizationSlug string) (domain.Organization, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Organization{}, err
	}
	slug, err := domain.NormalizeSlug("organization", organizationSlug)
	if err != nil {
		return domain.Organization{}, err
	}
	org, ok, err := h.inventory.FindOrganizationBySlug(ctx, slug)
	if err != nil {
		return domain.Organization{}, err
	}
	if !ok {
		return domain.Organization{}, fmt.Errorf("organization %q does not exist", slug)
	}
	return org, nil
}

func (h *Hub) resolveProjectPath(ctx context.Context, organizationSlug string, projectSlug string) (domain.Project, error) {
	org, err := h.resolveOrganization(ctx, organizationSlug)
	if err != nil {
		return domain.Project{}, err
	}
	slug, err := domain.NormalizeSlug("project", projectSlug)
	if err != nil {
		return domain.Project{}, err
	}
	project, ok, err := h.inventory.FindProjectBySlug(ctx, org.ID, slug)
	if err != nil {
		return domain.Project{}, err
	}
	if !ok {
		return domain.Project{}, fmt.Errorf("project %q does not exist in organization %q", slug, org.Slug)
	}
	return project, nil
}

func (h *Hub) resolveEnvironmentPath(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) (domain.Environment, error) {
	_, _, environment, err := h.resolveEnvironmentContext(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return domain.Environment{}, err
	}
	return environment, nil
}

func (h *Hub) resolveEnvironmentContext(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) (domain.Organization, domain.Project, domain.Environment, error) {
	org, err := h.resolveOrganization(ctx, organizationSlug)
	if err != nil {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, err
	}
	projectSlug, err = domain.NormalizeSlug("project", projectSlug)
	if err != nil {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, err
	}
	project, ok, err := h.inventory.FindProjectBySlug(ctx, org.ID, projectSlug)
	if err != nil {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, err
	}
	if !ok {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, fmt.Errorf("project %q does not exist in organization %q", projectSlug, org.Slug)
	}
	slug, err := domain.NormalizeSlug("environment", environmentSlug)
	if err != nil {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, err
	}
	environment, ok, err := h.inventory.FindEnvironmentBySlug(ctx, project.ID, slug)
	if err != nil {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, err
	}
	if !ok {
		return domain.Organization{}, domain.Project{}, domain.Environment{}, fmt.Errorf("environment %q does not exist in project %q", slug, project.Slug)
	}
	return org, project, environment, nil
}

func (h *Hub) resolveAppPath(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string) (domain.MonitoredApp, error) {
	environment, err := h.resolveEnvironmentPath(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return domain.MonitoredApp{}, err
	}
	slug, err := domain.NormalizeSlug("app", appSlug)
	if err != nil {
		return domain.MonitoredApp{}, err
	}
	app, ok, err := h.inventory.FindMonitoredAppBySlug(ctx, environment.ID, slug)
	if err != nil {
		return domain.MonitoredApp{}, err
	}
	if !ok {
		return domain.MonitoredApp{}, fmt.Errorf("app %q does not exist in environment %q", slug, environment.Slug)
	}
	return app, nil
}

func (h *Hub) resolveHostPath(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, hostSlug string) (domain.Host, error) {
	environment, err := h.resolveEnvironmentPath(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return domain.Host{}, err
	}
	slug, err := domain.NormalizeSlug("host", hostSlug)
	if err != nil {
		return domain.Host{}, err
	}
	host, ok, err := h.inventory.FindHostBySlug(ctx, environment.ID, slug)
	if err != nil {
		return domain.Host{}, err
	}
	if !ok {
		return domain.Host{}, fmt.Errorf("host %q does not exist in environment %q", slug, environment.Slug)
	}
	return host, nil
}

func defaultName(name string, slug string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return slug
	}
	return name
}
