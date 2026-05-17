package hub

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestBootstrapSingleSiteCreatesWordPressInventoryWithDefaults(t *testing.T) {
	repo := newMemoryInventoryRepository()
	hub := New(Dependencies{Inventory: repo})

	input := BootstrapSingleSiteInput{
		OrganizationSlug: "acme",
		OrganizationName: "Acme",
		ProjectSlug:      "customer-site",
		ProjectName:      "Customer Site",
		Kind:             "woocommerce",
		HostSlug:         "web-01",
		Region:           "eu-central",
		HostLabels: map[string]string{
			"pool": "blue",
			"role": "web",
		},
		AgentID:      "agt_web_01",
		Fingerprint:  "SHA256:test",
		AgentVersion: "dev",
	}

	result, err := hub.BootstrapSingleSite(context.Background(), input)
	if err != nil {
		t.Fatalf("BootstrapSingleSite returned error: %v", err)
	}

	if result.Organization.Slug != "acme" || result.Organization.Name != "Acme" {
		t.Fatalf("organization = %#v", result.Organization)
	}
	if result.Project.Slug != "customer-site" || result.Project.Name != "Customer Site" {
		t.Fatalf("project = %#v", result.Project)
	}
	if result.Environment.Slug != "production" || result.Environment.Name != "Production" {
		t.Fatalf("environment = %#v", result.Environment)
	}
	if result.App.Slug != "main-web" || result.App.Name != "WordPress" || result.App.Kind != "wordpress" {
		t.Fatalf("app = %#v", result.App)
	}
	if result.Service.Slug != "frontend" || result.Service.Name != "Frontend" || result.Service.Role != "web" {
		t.Fatalf("service = %#v", result.Service)
	}
	if result.Host.Slug != "web-01" || result.Host.Hostname != "web-01" || result.Host.Region != "eu-central" {
		t.Fatalf("host = %#v", result.Host)
	}
	if result.Host.Labels["pool"] != "blue" || result.Host.Labels["role"] != "web" {
		t.Fatalf("host labels = %#v", result.Host.Labels)
	}
	if result.Agent.AgentID != "agt_web_01" || result.Agent.Fingerprint != "SHA256:test" || result.Agent.Version != "dev" {
		t.Fatalf("agent = %#v", result.Agent)
	}

	second, err := hub.BootstrapSingleSite(context.Background(), input)
	if err != nil {
		t.Fatalf("second BootstrapSingleSite returned error: %v", err)
	}
	if second.Organization.ID != result.Organization.ID ||
		second.Project.ID != result.Project.ID ||
		second.Environment.ID != result.Environment.ID ||
		second.App.ID != result.App.ID ||
		second.Service.ID != result.Service.ID ||
		second.Host.ID != result.Host.ID ||
		second.Agent.ID != result.Agent.ID {
		t.Fatalf("bootstrap should be idempotent:\nfirst=%#v\nsecond=%#v", result, second)
	}
}

func TestBootstrapSingleSiteRejectsUnsupportedKind(t *testing.T) {
	repo := newMemoryInventoryRepository()
	hub := New(Dependencies{Inventory: repo})

	_, err := hub.BootstrapSingleSite(context.Background(), BootstrapSingleSiteInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		Kind:             "drupal",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		Fingerprint:      "SHA256:test",
	})
	if err == nil {
		t.Fatal("expected unsupported kind error")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported kind error, got %q", err)
	}
	if len(repo.organizations) != 0 {
		t.Fatalf("unsupported bootstrap should not save inventory, got %#v", repo.organizations)
	}
}

type memoryInventoryRepository struct {
	next          int
	organizations map[string]domain.Organization
	projects      map[string]domain.Project
	environments  map[string]domain.Environment
	apps          map[string]domain.MonitoredApp
	services      map[string]domain.Service
	hosts         map[string]domain.Host
	agents        map[string]domain.Agent
	deployments   []domain.DeploymentMarker
}

func newMemoryInventoryRepository() *memoryInventoryRepository {
	return &memoryInventoryRepository{
		organizations: make(map[string]domain.Organization),
		projects:      make(map[string]domain.Project),
		environments:  make(map[string]domain.Environment),
		apps:          make(map[string]domain.MonitoredApp),
		services:      make(map[string]domain.Service),
		hosts:         make(map[string]domain.Host),
		agents:        make(map[string]domain.Agent),
	}
}

func (r *memoryInventoryRepository) SaveOrganization(ctx context.Context, organization domain.Organization) (domain.Organization, error) {
	now := time.Now().UTC()
	if existing, ok := r.organizations[organization.Slug]; ok {
		organization.ID = existing.ID
		organization.CreatedAt = existing.CreatedAt
	} else {
		organization.ID = r.nextID("org")
		organization.CreatedAt = now
	}
	organization.UpdatedAt = now
	r.organizations[organization.Slug] = organization
	return organization, nil
}

func (r *memoryInventoryRepository) ListOrganizations(ctx context.Context) ([]domain.Organization, error) {
	items := make([]domain.Organization, 0, len(r.organizations))
	for _, item := range r.organizations {
		items = append(items, item)
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindOrganizationBySlug(ctx context.Context, slug string) (domain.Organization, bool, error) {
	item, ok := r.organizations[slug]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveProject(ctx context.Context, project domain.Project) (domain.Project, error) {
	now := time.Now().UTC()
	key := inventoryKey(string(project.OrganizationID), project.Slug)
	if existing, ok := r.projects[key]; ok {
		project.ID = existing.ID
		project.CreatedAt = existing.CreatedAt
	} else {
		project.ID = r.nextID("project")
		project.CreatedAt = now
	}
	project.UpdatedAt = now
	r.projects[key] = project
	return project, nil
}

func (r *memoryInventoryRepository) ListProjects(ctx context.Context, organizationID domain.ID) ([]domain.Project, error) {
	items := make([]domain.Project, 0)
	for _, item := range r.projects {
		if item.OrganizationID == organizationID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindProjectBySlug(ctx context.Context, organizationID domain.ID, slug string) (domain.Project, bool, error) {
	item, ok := r.projects[inventoryKey(string(organizationID), slug)]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveEnvironment(ctx context.Context, environment domain.Environment) (domain.Environment, error) {
	now := time.Now().UTC()
	key := inventoryKey(string(environment.ProjectID), environment.Slug)
	if existing, ok := r.environments[key]; ok {
		environment.ID = existing.ID
		environment.CreatedAt = existing.CreatedAt
	} else {
		environment.ID = r.nextID("environment")
		environment.CreatedAt = now
	}
	environment.UpdatedAt = now
	r.environments[key] = environment
	return environment, nil
}

func (r *memoryInventoryRepository) ListEnvironments(ctx context.Context, projectID domain.ID) ([]domain.Environment, error) {
	items := make([]domain.Environment, 0)
	for _, item := range r.environments {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindEnvironmentBySlug(ctx context.Context, projectID domain.ID, slug string) (domain.Environment, bool, error) {
	item, ok := r.environments[inventoryKey(string(projectID), slug)]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveMonitoredApp(ctx context.Context, app domain.MonitoredApp) (domain.MonitoredApp, error) {
	now := time.Now().UTC()
	key := inventoryKey(string(app.EnvironmentID), app.Slug)
	if existing, ok := r.apps[key]; ok {
		app.ID = existing.ID
		app.CreatedAt = existing.CreatedAt
	} else {
		app.ID = r.nextID("app")
		app.CreatedAt = now
	}
	app.UpdatedAt = now
	r.apps[key] = app
	return app, nil
}

func (r *memoryInventoryRepository) ListMonitoredApps(ctx context.Context, environmentID domain.ID) ([]domain.MonitoredApp, error) {
	items := make([]domain.MonitoredApp, 0)
	for _, item := range r.apps {
		if item.EnvironmentID == environmentID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindMonitoredAppBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.MonitoredApp, bool, error) {
	item, ok := r.apps[inventoryKey(string(environmentID), slug)]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveService(ctx context.Context, service domain.Service) (domain.Service, error) {
	now := time.Now().UTC()
	key := inventoryKey(string(service.AppID), service.Slug)
	if existing, ok := r.services[key]; ok {
		service.ID = existing.ID
		service.CreatedAt = existing.CreatedAt
	} else {
		service.ID = r.nextID("service")
		service.CreatedAt = now
	}
	service.UpdatedAt = now
	r.services[key] = service
	return service, nil
}

func (r *memoryInventoryRepository) ListServices(ctx context.Context, appID domain.ID) ([]domain.Service, error) {
	items := make([]domain.Service, 0)
	for _, item := range r.services {
		if item.AppID == appID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindServiceBySlug(ctx context.Context, appID domain.ID, slug string) (domain.Service, bool, error) {
	item, ok := r.services[inventoryKey(string(appID), slug)]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveHost(ctx context.Context, host domain.Host) (domain.Host, error) {
	now := time.Now().UTC()
	key := inventoryKey(string(host.EnvironmentID), host.Slug)
	if existing, ok := r.hosts[key]; ok {
		host.ID = existing.ID
		host.CreatedAt = existing.CreatedAt
	} else {
		host.ID = r.nextID("host")
		host.CreatedAt = now
	}
	host.UpdatedAt = now
	r.hosts[key] = host
	return host, nil
}

func (r *memoryInventoryRepository) ListHosts(ctx context.Context, environmentID domain.ID) ([]domain.Host, error) {
	items := make([]domain.Host, 0)
	for _, item := range r.hosts {
		if item.EnvironmentID == environmentID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindHostBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.Host, bool, error) {
	item, ok := r.hosts[inventoryKey(string(environmentID), slug)]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveAgent(ctx context.Context, agent domain.Agent) (domain.Agent, error) {
	now := time.Now().UTC()
	if existing, ok := r.agents[agent.AgentID]; ok {
		agent.ID = existing.ID
		agent.CreatedAt = existing.CreatedAt
	} else {
		agent.ID = r.nextID("agent")
		agent.CreatedAt = now
	}
	agent.UpdatedAt = now
	r.agents[agent.AgentID] = agent
	return agent, nil
}

func (r *memoryInventoryRepository) ListAgents(ctx context.Context, hostID domain.ID) ([]domain.Agent, error) {
	items := make([]domain.Agent, 0)
	for _, item := range r.agents {
		if item.HostID == hostID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) FindAgentByAgentID(ctx context.Context, agentID string) (domain.Agent, bool, error) {
	item, ok := r.agents[agentID]
	return item, ok, nil
}

func (r *memoryInventoryRepository) SaveDeploymentMarker(ctx context.Context, marker domain.DeploymentMarker) (domain.DeploymentMarker, error) {
	marker.ID = r.nextID("deploy")
	marker.CreatedAt = time.Now().UTC()
	r.deployments = append(r.deployments, marker)
	return marker, nil
}

func (r *memoryInventoryRepository) ListDeploymentMarkers(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.DeploymentMarker, error) {
	items := make([]domain.DeploymentMarker, 0)
	for _, item := range r.deployments {
		if item.EnvironmentID == environmentID && (appID == "" || item.AppID == appID) {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *memoryInventoryRepository) nextID(prefix string) domain.ID {
	r.next++
	return domain.ID(fmt.Sprintf("%s-%03d", prefix, r.next))
}

func inventoryKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}
