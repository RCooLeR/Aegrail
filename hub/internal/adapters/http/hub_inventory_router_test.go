package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/wire"
)

func TestHubRouterListsInventoryTopology(t *testing.T) {
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/topology?org=acme&project=customer-site&environment=production", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Counts map[string]int `json:"counts"`
		Apps   []struct {
			Slug string `json:"slug"`
			Kind string `json:"kind"`
		} `json:"apps"`
		Services []struct {
			Slug string `json:"slug"`
			Role string `json:"role"`
		} `json:"services"`
		Hosts []struct {
			Slug   string            `json:"slug"`
			Labels map[string]string `json:"labels"`
		} `json:"hosts"`
		Agents []struct {
			AgentID string `json:"agent_id"`
		} `json:"agents"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Counts["apps"] != 1 || body.Counts["services"] != 1 || body.Counts["hosts"] != 1 || body.Counts["agents"] != 1 {
		t.Fatalf("counts = %#v, want one app/service/host/agent", body.Counts)
	}
	if body.Apps[0].Slug != "main-web" || body.Apps[0].Kind != "wordpress" {
		t.Fatalf("apps = %#v", body.Apps)
	}
	if body.Services[0].Slug != "frontend" || body.Services[0].Role != "web" {
		t.Fatalf("services = %#v", body.Services)
	}
	if body.Hosts[0].Slug != "web-01" || body.Hosts[0].Labels["pool"] != "blue" {
		t.Fatalf("hosts = %#v", body.Hosts)
	}
	if body.Agents[0].AgentID != "agt_web_01" {
		t.Fatalf("agents = %#v", body.Agents)
	}
}

func TestHubRouterReturnsNotFoundForMissingInventoryTopology(t *testing.T) {
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/topology?org=acme&project=customer-site&environment=missing", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
}

func TestHubRouterDoesNotReplaceProvisionedNodeSecret(t *testing.T) {
	hubPrivateKey, _, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair returned error: %v", err)
	}
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{
		WirePrivateKey: hubPrivateKey,
	})

	body := `{"org":"acme","project":"customer-site","environment":"production","host":"web-01","agent_id":"agt_new","version":"test"}`
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/nodes", strings.NewReader(body))
	firstRequest.RemoteAddr = "127.0.0.1:12345"
	firstRequest.Header.Set("Content-Type", "application/json")
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, firstRequest)

	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("first status = %d body = %s", firstResponse.Code, firstResponse.Body.String())
	}
	if !strings.Contains(firstResponse.Body.String(), `"node_secret"`) {
		t.Fatalf("first body did not contain node secret: %s", firstResponse.Body.String())
	}

	secondRequest := httptest.NewRequest(http.MethodPost, "/api/v1/inventory/nodes", strings.NewReader(body))
	secondRequest.RemoteAddr = "127.0.0.1:12345"
	secondRequest.Header.Set("Content-Type", "application/json")
	secondResponse := httptest.NewRecorder()
	router.ServeHTTP(secondResponse, secondRequest)

	if secondResponse.Code != http.StatusConflict {
		t.Fatalf("second status = %d body = %s", secondResponse.Code, secondResponse.Body.String())
	}
}

func TestHubRouterListsInventoryScopes(t *testing.T) {
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/scopes", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Count         int `json:"count"`
		Projects      int `json:"projects"`
		Environments  int `json:"environments"`
		Apps          int `json:"apps"`
		Organizations []struct {
			Slug     string `json:"slug"`
			Name     string `json:"name"`
			Projects []struct {
				Slug         string `json:"slug"`
				Name         string `json:"name"`
				Environments []struct {
					Slug string `json:"slug"`
					Apps []struct {
						Slug     string `json:"slug"`
						Kind     string `json:"kind"`
						Services []struct {
							Slug string `json:"slug"`
						} `json:"services"`
					} `json:"apps"`
					Hosts []struct {
						Slug   string `json:"slug"`
						Agents []struct {
							AgentID string `json:"agent_id"`
						} `json:"agents"`
					} `json:"hosts"`
				} `json:"environments"`
			} `json:"projects"`
		} `json:"organizations"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Count != 1 || body.Projects != 1 || body.Environments != 1 || body.Apps != 1 {
		t.Fatalf("counts = %#v, want one organization/project/environment/app", body)
	}
	if body.Organizations[0].Slug != "acme" || body.Organizations[0].Projects[0].Slug != "customer-site" {
		t.Fatalf("organizations = %#v", body.Organizations)
	}
	environment := body.Organizations[0].Projects[0].Environments[0]
	if environment.Slug != "production" || environment.Apps[0].Slug != "main-web" || environment.Apps[0].Kind != "wordpress" {
		t.Fatalf("environment = %#v", environment)
	}
	if len(environment.Apps[0].Services) != 1 || environment.Apps[0].Services[0].Slug != "frontend" {
		t.Fatalf("services = %#v", environment.Apps[0].Services)
	}
	if len(environment.Hosts) != 1 || environment.Hosts[0].Slug != "web-01" || len(environment.Hosts[0].Agents) != 1 {
		t.Fatalf("hosts = %#v", environment.Hosts)
	}
}

func TestHubRouterUpdatesInventoryRecords(t *testing.T) {
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{})

	tests := []struct {
		method string
		path   string
		body   string
		want   string
	}{
		{method: http.MethodPatch, path: "/api/v1/inventory/companies/org-1", body: `{"slug":"renamed","name":"Renamed Co"}`, want: `"slug":"renamed"`},
		{method: http.MethodPatch, path: "/api/v1/inventory/projects/project-1", body: `{"slug":"renamed-site","name":"Renamed Site"}`, want: `"slug":"renamed-site"`},
		{method: http.MethodPatch, path: "/api/v1/inventory/environments/env-1", body: `{"slug":"local","name":"Local"}`, want: `"slug":"local"`},
		{method: http.MethodPatch, path: "/api/v1/inventory/apps/app-1", body: `{"slug":"admin-web","name":"Admin Web","kind":"prestashop"}`, want: `"kind":"prestashop"`},
		{method: http.MethodPatch, path: "/api/v1/inventory/services/service-1", body: `{"slug":"backend","name":"Backend","role":"worker"}`, want: `"role":"worker"`},
		{method: http.MethodPatch, path: "/api/v1/inventory/hosts/host-1", body: `{"slug":"node-a","hostname":"node-a.local","region":"local","labels":{"pool":"green"}}`, want: `"hostname":"node-a.local"`},
		{method: http.MethodPatch, path: "/api/v1/inventory/agents/agent-1", body: `{"agent_id":"agt_node_a","version":"dev"}`, want: `"agent_id":"agt_node_a"`},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("body = %s, want %s", response.Body.String(), test.want)
			}
		})
	}
}

func TestHubRouterListsAgentsForHost(t *testing.T) {
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/inventory/agents?org=acme&project=customer-site&environment=production&host=web-01", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Count  int `json:"count"`
		Agents []struct {
			AgentID     string `json:"agent_id"`
			Fingerprint string `json:"fingerprint"`
		} `json:"agents"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Count != 1 || body.Agents[0].AgentID != "agt_web_01" || body.Agents[0].Fingerprint != "SHA256:test" {
		t.Fatalf("body = %#v, want web-01 agent", body)
	}
}

func TestHubRouterListsDeployments(t *testing.T) {
	repo := newHTTPTestInventoryRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: repo}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/deployments?org=acme&project=customer-site&environment=production&app=main-web", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Count       int `json:"count"`
		Deployments []struct {
			AppID     string `json:"app_id"`
			Version   string `json:"version"`
			CommitSHA string `json:"commit_sha"`
			Actor     string `json:"actor"`
		} `json:"deployments"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Count != 1 {
		t.Fatalf("count = %d, want 1", body.Count)
	}
	deployment := body.Deployments[0]
	if deployment.AppID != "app-1" || deployment.Version != "v1.8.2" || deployment.CommitSHA != "a91f72c" || deployment.Actor != "github-actions" {
		t.Fatalf("deployment = %#v, want seeded deployment", deployment)
	}
}

type httpTestInventoryRepository struct {
	org         domain.Organization
	project     domain.Project
	environment domain.Environment
	apps        []domain.MonitoredApp
	services    map[domain.ID][]domain.Service
	hosts       []domain.Host
	agents      map[domain.ID][]domain.Agent
	deployments []domain.DeploymentMarker
}

func newHTTPTestInventoryRepository() *httpTestInventoryRepository {
	now := time.Date(2026, 5, 12, 17, 0, 0, 0, time.UTC)
	org := domain.Organization{ID: "org-1", Slug: "acme", Name: "Acme", CreatedAt: now, UpdatedAt: now}
	project := domain.Project{ID: "project-1", OrganizationID: org.ID, Slug: "customer-site", Name: "Customer Site", CreatedAt: now, UpdatedAt: now}
	environment := domain.Environment{ID: "env-1", ProjectID: project.ID, Slug: "production", Name: "Production", CreatedAt: now, UpdatedAt: now}
	app := domain.MonitoredApp{ID: "app-1", EnvironmentID: environment.ID, Slug: "main-web", Name: "Main Web", Kind: "wordpress", CreatedAt: now, UpdatedAt: now}
	service := domain.Service{ID: "service-1", AppID: app.ID, Slug: "frontend", Name: "Frontend", Role: "web", CreatedAt: now, UpdatedAt: now}
	host := domain.Host{ID: "host-1", EnvironmentID: environment.ID, Slug: "web-01", Hostname: "web-01", Region: "eu-central", Labels: map[string]string{"pool": "blue"}, CreatedAt: now, UpdatedAt: now}
	lastSeen := now
	agent := domain.Agent{ID: "agent-1", HostID: host.ID, AgentID: "agt_web_01", Fingerprint: "SHA256:test", Version: "test", LastSeenAt: &lastSeen, CreatedAt: now, UpdatedAt: now}
	finishedAt := now.Add(2 * time.Minute)
	deployment := domain.DeploymentMarker{ID: "deploy-1", EnvironmentID: environment.ID, AppID: app.ID, Version: "v1.8.2", CommitSHA: "a91f72c", Actor: "github-actions", StartedAt: now, FinishedAt: &finishedAt, CreatedAt: now}
	return &httpTestInventoryRepository{
		org:         org,
		project:     project,
		environment: environment,
		apps:        []domain.MonitoredApp{app},
		services:    map[domain.ID][]domain.Service{app.ID: {service}},
		hosts:       []domain.Host{host},
		agents:      map[domain.ID][]domain.Agent{host.ID: {agent}},
		deployments: []domain.DeploymentMarker{deployment},
	}
}

func (r *httpTestInventoryRepository) SaveOrganization(ctx context.Context, organization domain.Organization) (domain.Organization, error) {
	return organization, nil
}

func (r *httpTestInventoryRepository) UpdateOrganization(ctx context.Context, organizationID domain.ID, update domain.OrganizationUpdate) (domain.Organization, error) {
	if organizationID != r.org.ID {
		return domain.Organization{}, nil
	}
	r.org.Slug = update.Slug
	r.org.Name = update.Name
	r.org.UpdatedAt = time.Now().UTC()
	return r.org, nil
}

func (r *httpTestInventoryRepository) ListOrganizations(ctx context.Context) ([]domain.Organization, error) {
	return []domain.Organization{r.org}, nil
}

func (r *httpTestInventoryRepository) FindOrganizationBySlug(ctx context.Context, slug string) (domain.Organization, bool, error) {
	return r.org, slug == r.org.Slug, nil
}

func (r *httpTestInventoryRepository) SaveProject(ctx context.Context, project domain.Project) (domain.Project, error) {
	return project, nil
}

func (r *httpTestInventoryRepository) UpdateProject(ctx context.Context, projectID domain.ID, update domain.ProjectUpdate) (domain.Project, error) {
	if projectID != r.project.ID {
		return domain.Project{}, nil
	}
	r.project.Slug = update.Slug
	r.project.Name = update.Name
	r.project.UpdatedAt = time.Now().UTC()
	return r.project, nil
}

func (r *httpTestInventoryRepository) ListProjects(ctx context.Context, organizationID domain.ID) ([]domain.Project, error) {
	if organizationID != r.org.ID {
		return nil, nil
	}
	return []domain.Project{r.project}, nil
}

func (r *httpTestInventoryRepository) FindProjectBySlug(ctx context.Context, organizationID domain.ID, slug string) (domain.Project, bool, error) {
	return r.project, organizationID == r.org.ID && slug == r.project.Slug, nil
}

func (r *httpTestInventoryRepository) SaveEnvironment(ctx context.Context, environment domain.Environment) (domain.Environment, error) {
	return environment, nil
}

func (r *httpTestInventoryRepository) UpdateEnvironment(ctx context.Context, environmentID domain.ID, update domain.EnvironmentUpdate) (domain.Environment, error) {
	if environmentID != r.environment.ID {
		return domain.Environment{}, nil
	}
	r.environment.Slug = update.Slug
	r.environment.Name = update.Name
	r.environment.UpdatedAt = time.Now().UTC()
	return r.environment, nil
}

func (r *httpTestInventoryRepository) ListEnvironments(ctx context.Context, projectID domain.ID) ([]domain.Environment, error) {
	if projectID != r.project.ID {
		return nil, nil
	}
	return []domain.Environment{r.environment}, nil
}

func (r *httpTestInventoryRepository) FindEnvironmentBySlug(ctx context.Context, projectID domain.ID, slug string) (domain.Environment, bool, error) {
	return r.environment, projectID == r.project.ID && slug == r.environment.Slug, nil
}

func (r *httpTestInventoryRepository) SaveMonitoredApp(ctx context.Context, app domain.MonitoredApp) (domain.MonitoredApp, error) {
	return app, nil
}

func (r *httpTestInventoryRepository) UpdateMonitoredApp(ctx context.Context, appID domain.ID, update domain.MonitoredAppUpdate) (domain.MonitoredApp, error) {
	for index, app := range r.apps {
		if app.ID != appID {
			continue
		}
		app.Slug = update.Slug
		app.Name = update.Name
		app.Kind = update.Kind
		app.UpdatedAt = time.Now().UTC()
		r.apps[index] = app
		return app, nil
	}
	return domain.MonitoredApp{}, nil
}

func (r *httpTestInventoryRepository) ListMonitoredApps(ctx context.Context, environmentID domain.ID) ([]domain.MonitoredApp, error) {
	if environmentID != r.environment.ID {
		return nil, nil
	}
	return append([]domain.MonitoredApp(nil), r.apps...), nil
}

func (r *httpTestInventoryRepository) FindMonitoredAppBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.MonitoredApp, bool, error) {
	for _, app := range r.apps {
		if app.EnvironmentID == environmentID && app.Slug == slug {
			return app, true, nil
		}
	}
	return domain.MonitoredApp{}, false, nil
}

func (r *httpTestInventoryRepository) SaveService(ctx context.Context, service domain.Service) (domain.Service, error) {
	return service, nil
}

func (r *httpTestInventoryRepository) UpdateService(ctx context.Context, serviceID domain.ID, update domain.ServiceUpdate) (domain.Service, error) {
	for appID, services := range r.services {
		for index, service := range services {
			if service.ID != serviceID {
				continue
			}
			service.Slug = update.Slug
			service.Name = update.Name
			service.Role = update.Role
			service.UpdatedAt = time.Now().UTC()
			r.services[appID][index] = service
			return service, nil
		}
	}
	return domain.Service{}, nil
}

func (r *httpTestInventoryRepository) ListServices(ctx context.Context, appID domain.ID) ([]domain.Service, error) {
	return append([]domain.Service(nil), r.services[appID]...), nil
}

func (r *httpTestInventoryRepository) FindServiceBySlug(ctx context.Context, appID domain.ID, slug string) (domain.Service, bool, error) {
	for _, service := range r.services[appID] {
		if service.Slug == slug {
			return service, true, nil
		}
	}
	return domain.Service{}, false, nil
}

func (r *httpTestInventoryRepository) SaveHost(ctx context.Context, host domain.Host) (domain.Host, error) {
	return host, nil
}

func (r *httpTestInventoryRepository) UpdateHost(ctx context.Context, hostID domain.ID, update domain.HostUpdate) (domain.Host, error) {
	for index, host := range r.hosts {
		if host.ID != hostID {
			continue
		}
		host.Slug = update.Slug
		host.Hostname = update.Hostname
		host.Region = update.Region
		host.Labels = update.Labels
		host.UpdatedAt = time.Now().UTC()
		r.hosts[index] = host
		return host, nil
	}
	return domain.Host{}, nil
}

func (r *httpTestInventoryRepository) ListHosts(ctx context.Context, environmentID domain.ID) ([]domain.Host, error) {
	if environmentID != r.environment.ID {
		return nil, nil
	}
	return append([]domain.Host(nil), r.hosts...), nil
}

func (r *httpTestInventoryRepository) FindHostBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.Host, bool, error) {
	for _, host := range r.hosts {
		if host.EnvironmentID == environmentID && host.Slug == slug {
			return host, true, nil
		}
	}
	return domain.Host{}, false, nil
}

func (r *httpTestInventoryRepository) SaveAgent(ctx context.Context, agent domain.Agent) (domain.Agent, error) {
	now := time.Now().UTC()
	for hostID, agents := range r.agents {
		for index, existing := range agents {
			if existing.AgentID != agent.AgentID {
				continue
			}
			if existing.NodePublicKey != "" && agent.NodePublicKey != "" && existing.NodePublicKey != agent.NodePublicKey {
				return domain.Agent{}, hubapp.ErrAgentAlreadyProvisioned
			}
			if agent.NodePublicKey == "" {
				agent.NodePublicKey = existing.NodePublicKey
			}
			agent.ID = existing.ID
			agent.CreatedAt = existing.CreatedAt
			agent.UpdatedAt = now
			if agent.HostID == "" {
				agent.HostID = hostID
			}
			r.agents[hostID][index] = agent
			return agent, nil
		}
	}
	if agent.ID == "" {
		agent.ID = domain.ID("agent-" + agent.AgentID)
	}
	agent.CreatedAt = now
	agent.UpdatedAt = now
	r.agents[agent.HostID] = append(r.agents[agent.HostID], agent)
	return agent, nil
}

func (r *httpTestInventoryRepository) UpdateAgent(ctx context.Context, agentID domain.ID, update domain.AgentUpdate) (domain.Agent, error) {
	for hostID, agents := range r.agents {
		for index, agent := range agents {
			if agent.ID != agentID {
				continue
			}
			agent.AgentID = update.AgentID
			agent.Version = update.Version
			agent.UpdatedAt = time.Now().UTC()
			r.agents[hostID][index] = agent
			return agent, nil
		}
	}
	return domain.Agent{}, nil
}

func (r *httpTestInventoryRepository) ListAgents(ctx context.Context, hostID domain.ID) ([]domain.Agent, error) {
	return append([]domain.Agent(nil), r.agents[hostID]...), nil
}

func (r *httpTestInventoryRepository) FindAgentByAgentID(ctx context.Context, agentID string) (domain.Agent, bool, error) {
	for _, agents := range r.agents {
		for _, agent := range agents {
			if agent.AgentID == agentID {
				return agent, true, nil
			}
		}
	}
	return domain.Agent{}, false, nil
}

func (r *httpTestInventoryRepository) SaveDeploymentMarker(ctx context.Context, marker domain.DeploymentMarker) (domain.DeploymentMarker, error) {
	return marker, nil
}

func (r *httpTestInventoryRepository) ListDeploymentMarkers(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.DeploymentMarker, error) {
	var deployments []domain.DeploymentMarker
	for _, deployment := range r.deployments {
		if deployment.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && deployment.AppID != appID {
			continue
		}
		deployments = append(deployments, deployment)
	}
	return deployments, nil
}
