package ports

import (
	"context"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type InventoryRepository interface {
	SaveOrganization(ctx context.Context, organization domain.Organization) (domain.Organization, error)
	UpdateOrganization(ctx context.Context, organizationID domain.ID, update domain.OrganizationUpdate) (domain.Organization, error)
	ListOrganizations(ctx context.Context) ([]domain.Organization, error)
	FindOrganizationBySlug(ctx context.Context, slug string) (domain.Organization, bool, error)

	SaveProject(ctx context.Context, project domain.Project) (domain.Project, error)
	UpdateProject(ctx context.Context, projectID domain.ID, update domain.ProjectUpdate) (domain.Project, error)
	ListProjects(ctx context.Context, organizationID domain.ID) ([]domain.Project, error)
	FindProjectBySlug(ctx context.Context, organizationID domain.ID, slug string) (domain.Project, bool, error)

	SaveEnvironment(ctx context.Context, environment domain.Environment) (domain.Environment, error)
	UpdateEnvironment(ctx context.Context, environmentID domain.ID, update domain.EnvironmentUpdate) (domain.Environment, error)
	ListEnvironments(ctx context.Context, projectID domain.ID) ([]domain.Environment, error)
	FindEnvironmentBySlug(ctx context.Context, projectID domain.ID, slug string) (domain.Environment, bool, error)

	SaveMonitoredApp(ctx context.Context, app domain.MonitoredApp) (domain.MonitoredApp, error)
	UpdateMonitoredApp(ctx context.Context, appID domain.ID, update domain.MonitoredAppUpdate) (domain.MonitoredApp, error)
	ListMonitoredApps(ctx context.Context, environmentID domain.ID) ([]domain.MonitoredApp, error)
	FindMonitoredAppBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.MonitoredApp, bool, error)

	SaveService(ctx context.Context, service domain.Service) (domain.Service, error)
	UpdateService(ctx context.Context, serviceID domain.ID, update domain.ServiceUpdate) (domain.Service, error)
	ListServices(ctx context.Context, appID domain.ID) ([]domain.Service, error)
	FindServiceBySlug(ctx context.Context, appID domain.ID, slug string) (domain.Service, bool, error)

	SaveHost(ctx context.Context, host domain.Host) (domain.Host, error)
	UpdateHost(ctx context.Context, hostID domain.ID, update domain.HostUpdate) (domain.Host, error)
	ListHosts(ctx context.Context, environmentID domain.ID) ([]domain.Host, error)
	FindHostBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.Host, bool, error)

	SaveAgent(ctx context.Context, agent domain.Agent) (domain.Agent, error)
	UpdateAgent(ctx context.Context, agentID domain.ID, update domain.AgentUpdate) (domain.Agent, error)
	ListAgents(ctx context.Context, hostID domain.ID) ([]domain.Agent, error)
	FindAgentByAgentID(ctx context.Context, agentID string) (domain.Agent, bool, error)

	SaveDeploymentMarker(ctx context.Context, marker domain.DeploymentMarker) (domain.DeploymentMarker, error)
	ListDeploymentMarkers(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.DeploymentMarker, error)
}

type InventoryScopeTreeRepository interface {
	ListInventoryScopeTree(ctx context.Context) (InventoryScopeTree, error)
}

type InventoryEnvironmentScopeRepository interface {
	GetInventoryScopeForEnvironment(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) (InventoryEnvironmentScopePath, bool, error)
}

type InventoryIngestScopeRepository interface {
	GetInventoryIngestScope(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, hostSlug string, agentID string, appSlug string, serviceSlug string) (InventoryIngestScopePath, bool, error)
}

type InventoryScopeTree struct {
	Organizations []InventoryOrganizationScope
}

type InventoryIngestScopePath struct {
	Organization domain.Organization
	Project      domain.Project
	Environment  domain.Environment
	Host         domain.Host
	Agent        domain.Agent
	App          domain.MonitoredApp
	Service      domain.Service
}

type InventoryEnvironmentScopePath struct {
	Organization domain.Organization
	Project      domain.Project
	Environment  domain.Environment
	Apps         []InventoryAppScope
	Hosts        []InventoryHostScope
}

type InventoryOrganizationScope struct {
	Organization domain.Organization
	Projects     []InventoryProjectScope
}

type InventoryProjectScope struct {
	Project      domain.Project
	Environments []InventoryEnvironmentScope
}

type InventoryEnvironmentScope struct {
	Environment domain.Environment
	Apps        []InventoryAppScope
	Hosts       []InventoryHostScope
}

type InventoryAppScope struct {
	App      domain.MonitoredApp
	Services []domain.Service
}

type InventoryHostScope struct {
	Host   domain.Host
	Agents []domain.Agent
}
