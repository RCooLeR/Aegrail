package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
	"github.com/rcooler/aegrail/hub/internal/wire"
)

type Hub struct {
	meta                       domain.AppMeta
	inventory                  ports.InventoryRepository
	ingest                     ports.IngestRepository
	findings                   ports.HubFindingRepository
	fileIgnoreRules            ports.HubFileIgnoreRuleRepository
	browserAllowlist           ports.BrowserScriptAllowlistRepository
	modelReports               ports.ModelAnalysisReportRepository
	model                      ports.ModelGateway
	jobs                       ports.JobQueue
	locks                      ports.LockManager
	rateLimiter                ports.RateLimiter
	users                      ports.HubUserRepository
	notifications              ports.NotificationSink
	userSecretKey              string
	backgroundError            func(error)
	usersExistMu               sync.RWMutex
	usersExist                 bool
	totpReplayMu               sync.Mutex
	totpReplay                 map[totpReplayKey]time.Time
	workersWG                  sync.WaitGroup
	modelQueueFallbackWarnOnce sync.Once
}

type Dependencies struct {
	Meta             domain.AppMeta
	Inventory        ports.InventoryRepository
	Ingest           ports.IngestRepository
	Findings         ports.HubFindingRepository
	FileIgnoreRules  ports.HubFileIgnoreRuleRepository
	BrowserAllowlist ports.BrowserScriptAllowlistRepository
	ModelReports     ports.ModelAnalysisReportRepository
	Model            ports.ModelGateway
	Jobs             ports.JobQueue
	Locks            ports.LockManager
	RateLimiter      ports.RateLimiter
	Users            ports.HubUserRepository
	Notifications    ports.NotificationSink
	UserSecretKey    string
	BackgroundError  func(error)
}

func New(deps Dependencies) *Hub {
	return &Hub{
		meta:             deps.Meta,
		inventory:        deps.Inventory,
		ingest:           deps.Ingest,
		findings:         deps.Findings,
		fileIgnoreRules:  deps.FileIgnoreRules,
		browserAllowlist: deps.BrowserAllowlist,
		modelReports:     deps.ModelReports,
		model:            deps.Model,
		jobs:             deps.Jobs,
		locks:            deps.Locks,
		rateLimiter:      deps.RateLimiter,
		users:            deps.Users,
		notifications:    deps.Notifications,
		userSecretKey:    strings.TrimSpace(deps.UserSecretKey),
		backgroundError:  deps.BackgroundError,
		totpReplay:       map[totpReplayKey]time.Time{},
	}
}

type SaveOrganizationInput struct {
	Slug string
	Name string
}

type UpdateOrganizationInput struct {
	ID   string
	Slug string
	Name string
}

type SaveProjectInput struct {
	OrganizationSlug string
	Slug             string
	Name             string
}

type UpdateProjectInput struct {
	ID   string
	Slug string
	Name string
}

type SaveEnvironmentInput struct {
	OrganizationSlug string
	ProjectSlug      string
	Slug             string
	Name             string
}

type UpdateEnvironmentInput struct {
	ID   string
	Slug string
	Name string
}

type SaveMonitoredAppInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	Slug             string
	Name             string
	Kind             string
}

type UpdateMonitoredAppInput struct {
	ID   string
	Slug string
	Name string
	Kind string
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

type UpdateServiceInput struct {
	ID   string
	Slug string
	Name string
	Role string
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

type UpdateHostInput struct {
	ID       string
	Slug     string
	Hostname string
	Region   string
	Labels   map[string]string
}

type SaveAgentInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	HostSlug         string
	AgentID          string
	Fingerprint      string
	Version          string
	WireProtocol     string
	NodePublicKey    string
}

type UpdateAgentInput struct {
	ID      string
	AgentID string
	Version string
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

func (h *Hub) ListInventoryScopeTree(ctx context.Context) (ports.InventoryScopeTree, error) {
	if err := h.requireInventory(); err != nil {
		return ports.InventoryScopeTree{}, err
	}
	if treeRepository, ok := h.inventory.(ports.InventoryScopeTreeRepository); ok {
		return treeRepository.ListInventoryScopeTree(ctx)
	}
	return h.listInventoryScopeTreeFallback(ctx)
}

func (h *Hub) GetInventoryScopeForEnvironment(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) (ports.InventoryEnvironmentScopePath, bool, error) {
	if err := h.requireInventory(); err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	if scopeRepository, ok := h.inventory.(ports.InventoryEnvironmentScopeRepository); ok {
		return scopeRepository.GetInventoryScopeForEnvironment(ctx, organizationSlug, projectSlug, environmentSlug)
	}
	org, project, environment, err := h.resolveEnvironmentContext(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	apps, err := h.inventory.ListMonitoredApps(ctx, environment.ID)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	hosts, err := h.inventory.ListHosts(ctx, environment.ID)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	path := ports.InventoryEnvironmentScopePath{
		Organization: org,
		Project:      project,
		Environment:  environment,
		Apps:         make([]ports.InventoryAppScope, 0, len(apps)),
		Hosts:        make([]ports.InventoryHostScope, 0, len(hosts)),
	}
	for _, app := range apps {
		services, err := h.inventory.ListServices(ctx, app.ID)
		if err != nil {
			return ports.InventoryEnvironmentScopePath{}, false, err
		}
		path.Apps = append(path.Apps, ports.InventoryAppScope{App: app, Services: services})
	}
	for _, host := range hosts {
		agents, err := h.inventory.ListAgents(ctx, host.ID)
		if err != nil {
			return ports.InventoryEnvironmentScopePath{}, false, err
		}
		path.Hosts = append(path.Hosts, ports.InventoryHostScope{Host: host, Agents: agents})
	}
	return path, true, nil
}

func (h *Hub) listInventoryScopeTreeFallback(ctx context.Context) (ports.InventoryScopeTree, error) {
	organizations, err := h.inventory.ListOrganizations(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	tree := ports.InventoryScopeTree{
		Organizations: make([]ports.InventoryOrganizationScope, 0, len(organizations)),
	}
	for _, organization := range organizations {
		orgScope := ports.InventoryOrganizationScope{Organization: organization}
		projects, err := h.inventory.ListProjects(ctx, organization.ID)
		if err != nil {
			return ports.InventoryScopeTree{}, err
		}
		orgScope.Projects = make([]ports.InventoryProjectScope, 0, len(projects))
		for _, project := range projects {
			projectScope := ports.InventoryProjectScope{Project: project}
			environments, err := h.inventory.ListEnvironments(ctx, project.ID)
			if err != nil {
				return ports.InventoryScopeTree{}, err
			}
			projectScope.Environments = make([]ports.InventoryEnvironmentScope, 0, len(environments))
			for _, environment := range environments {
				environmentScope := ports.InventoryEnvironmentScope{Environment: environment}
				apps, err := h.inventory.ListMonitoredApps(ctx, environment.ID)
				if err != nil {
					return ports.InventoryScopeTree{}, err
				}
				environmentScope.Apps = make([]ports.InventoryAppScope, 0, len(apps))
				for _, app := range apps {
					services, err := h.inventory.ListServices(ctx, app.ID)
					if err != nil {
						return ports.InventoryScopeTree{}, err
					}
					environmentScope.Apps = append(environmentScope.Apps, ports.InventoryAppScope{
						App:      app,
						Services: services,
					})
				}
				hosts, err := h.inventory.ListHosts(ctx, environment.ID)
				if err != nil {
					return ports.InventoryScopeTree{}, err
				}
				environmentScope.Hosts = make([]ports.InventoryHostScope, 0, len(hosts))
				for _, host := range hosts {
					agents, err := h.inventory.ListAgents(ctx, host.ID)
					if err != nil {
						return ports.InventoryScopeTree{}, err
					}
					environmentScope.Hosts = append(environmentScope.Hosts, ports.InventoryHostScope{
						Host:   host,
						Agents: agents,
					})
				}
				projectScope.Environments = append(projectScope.Environments, environmentScope)
			}
			orgScope.Projects = append(orgScope.Projects, projectScope)
		}
		tree.Organizations = append(tree.Organizations, orgScope)
	}
	return tree, nil
}

func (h *Hub) UpdateOrganization(ctx context.Context, input UpdateOrganizationInput) (domain.Organization, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Organization{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.Organization{}, errors.New("organization id is required")
	}
	slug, err := domain.NormalizeSlug("organization", input.Slug)
	if err != nil {
		return domain.Organization{}, err
	}
	return h.inventory.UpdateOrganization(ctx, id, domain.OrganizationUpdate{
		Slug: slug,
		Name: defaultName(input.Name, slug),
	})
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

func (h *Hub) UpdateProject(ctx context.Context, input UpdateProjectInput) (domain.Project, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Project{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.Project{}, errors.New("project id is required")
	}
	slug, err := domain.NormalizeSlug("project", input.Slug)
	if err != nil {
		return domain.Project{}, err
	}
	return h.inventory.UpdateProject(ctx, id, domain.ProjectUpdate{
		Slug: slug,
		Name: defaultName(input.Name, slug),
	})
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

func (h *Hub) UpdateEnvironment(ctx context.Context, input UpdateEnvironmentInput) (domain.Environment, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Environment{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.Environment{}, errors.New("environment id is required")
	}
	slug, err := domain.NormalizeSlug("environment", input.Slug)
	if err != nil {
		return domain.Environment{}, err
	}
	return h.inventory.UpdateEnvironment(ctx, id, domain.EnvironmentUpdate{
		Slug: slug,
		Name: defaultName(input.Name, slug),
	})
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

func (h *Hub) UpdateMonitoredApp(ctx context.Context, input UpdateMonitoredAppInput) (domain.MonitoredApp, error) {
	if err := h.requireInventory(); err != nil {
		return domain.MonitoredApp{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.MonitoredApp{}, errors.New("app id is required")
	}
	slug, err := domain.NormalizeSlug("app", input.Slug)
	if err != nil {
		return domain.MonitoredApp{}, err
	}
	return h.inventory.UpdateMonitoredApp(ctx, id, domain.MonitoredAppUpdate{
		Slug: slug,
		Name: defaultName(input.Name, slug),
		Kind: strings.TrimSpace(input.Kind),
	})
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

func (h *Hub) UpdateService(ctx context.Context, input UpdateServiceInput) (domain.Service, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Service{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.Service{}, errors.New("service id is required")
	}
	slug, err := domain.NormalizeSlug("service", input.Slug)
	if err != nil {
		return domain.Service{}, err
	}
	return h.inventory.UpdateService(ctx, id, domain.ServiceUpdate{
		Slug: slug,
		Name: defaultName(input.Name, slug),
		Role: strings.TrimSpace(input.Role),
	})
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

func (h *Hub) UpdateHost(ctx context.Context, input UpdateHostInput) (domain.Host, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Host{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.Host{}, errors.New("host id is required")
	}
	slug, err := domain.NormalizeSlug("host", input.Slug)
	if err != nil {
		return domain.Host{}, err
	}
	hostname := strings.TrimSpace(input.Hostname)
	if hostname == "" {
		hostname = slug
	}
	return h.inventory.UpdateHost(ctx, id, domain.HostUpdate{
		Slug:     slug,
		Hostname: hostname,
		Region:   strings.TrimSpace(input.Region),
		Labels:   input.Labels,
	})
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
	nodePublicKey := strings.TrimSpace(input.NodePublicKey)
	wireProtocol := strings.TrimSpace(input.WireProtocol)
	if wireProtocol == "" {
		wireProtocol = wire.EnvelopeSchema
	}
	if fingerprint == "" && nodePublicKey != "" {
		var err error
		fingerprint, err = wire.PublicKeyFingerprint(nodePublicKey)
		if err != nil {
			return domain.Agent{}, fmt.Errorf("node public key: %w", err)
		}
	}
	if fingerprint == "" {
		return domain.Agent{}, errors.New("agent fingerprint is required")
	}
	now := time.Now().UTC()
	return h.inventory.SaveAgent(ctx, domain.Agent{
		HostID:        host.ID,
		AgentID:       agentID,
		Fingerprint:   fingerprint,
		Version:       strings.TrimSpace(input.Version),
		LastSeenAt:    &now,
		WireProtocol:  wireProtocol,
		NodePublicKey: nodePublicKey,
	})
}

func (h *Hub) ListAgents(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, hostSlug string) ([]domain.Agent, error) {
	host, err := h.resolveHostPath(ctx, organizationSlug, projectSlug, environmentSlug, hostSlug)
	if err != nil {
		return nil, err
	}
	return h.inventory.ListAgents(ctx, host.ID)
}

func (h *Hub) UpdateAgent(ctx context.Context, input UpdateAgentInput) (domain.Agent, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Agent{}, err
	}
	id := domain.ID(strings.TrimSpace(input.ID))
	if id == "" {
		return domain.Agent{}, errors.New("agent id is required")
	}
	agentID := strings.TrimSpace(input.AgentID)
	if agentID == "" {
		return domain.Agent{}, errors.New("node id is required")
	}
	return h.inventory.UpdateAgent(ctx, id, domain.AgentUpdate{
		AgentID: agentID,
		Version: strings.TrimSpace(input.Version),
	})
}

func (h *Hub) FindAgentByAgentID(ctx context.Context, agentID string) (domain.Agent, bool, error) {
	if err := h.requireInventory(); err != nil {
		return domain.Agent{}, false, err
	}
	return h.inventory.FindAgentByAgentID(ctx, strings.TrimSpace(agentID))
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

func (h *Hub) appMeta() domain.AppMeta {
	meta := h.meta
	if strings.TrimSpace(meta.Name) == "" {
		meta.Name = "Aegrail"
	}
	if strings.TrimSpace(meta.Binary) == "" {
		meta.Binary = "aegrail"
	}
	return meta
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
		return domain.Organization{}, fmt.Errorf("%w: organization %q does not exist", ErrHubNotFound, slug)
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
		return domain.Project{}, fmt.Errorf("%w: project %q does not exist in organization %q", ErrHubNotFound, slug, org.Slug)
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
		return domain.Organization{}, domain.Project{}, domain.Environment{}, fmt.Errorf("%w: project %q does not exist in organization %q", ErrHubNotFound, projectSlug, org.Slug)
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
		return domain.Organization{}, domain.Project{}, domain.Environment{}, fmt.Errorf("%w: environment %q does not exist in project %q", ErrHubNotFound, slug, project.Slug)
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
		return domain.MonitoredApp{}, fmt.Errorf("%w: app %q does not exist in environment %q", ErrHubNotFound, slug, environment.Slug)
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
		return domain.Host{}, fmt.Errorf("%w: host %q does not exist in environment %q", ErrHubNotFound, slug, environment.Slug)
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
