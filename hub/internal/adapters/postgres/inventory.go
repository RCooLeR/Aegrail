package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type InventoryRepository struct {
	pool *pgxpool.Pool
}

func NewInventoryRepository(pool *pgxpool.Pool) *InventoryRepository {
	return &InventoryRepository{pool: pool}
}

func (r *InventoryRepository) SaveOrganization(ctx context.Context, organization domain.Organization) (domain.Organization, error) {
	const query = `
		INSERT INTO organizations (slug, name)
		VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE
		SET name = EXCLUDED.name,
			updated_at = now()
		RETURNING id::text, slug::text, name, created_at, updated_at
	`
	var saved domain.Organization
	err := r.pool.QueryRow(ctx, query, organization.Slug, organization.Name).Scan(
		&saved.ID, &saved.Slug, &saved.Name, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) UpdateOrganization(ctx context.Context, organizationID domain.ID, update domain.OrganizationUpdate) (domain.Organization, error) {
	const query = `
		UPDATE organizations
		SET slug = $2,
			name = $3,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, slug::text, name, created_at, updated_at
	`
	var saved domain.Organization
	err := r.pool.QueryRow(ctx, query, organizationID, update.Slug, update.Name).Scan(
		&saved.ID, &saved.Slug, &saved.Name, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListOrganizations(ctx context.Context) ([]domain.Organization, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, slug::text, name, created_at, updated_at FROM organizations ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Organization
	for rows.Next() {
		var item domain.Organization
		if err := rows.Scan(&item.ID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindOrganizationBySlug(ctx context.Context, slug string) (domain.Organization, bool, error) {
	var item domain.Organization
	err := r.pool.QueryRow(ctx, `SELECT id::text, slug::text, name, created_at, updated_at FROM organizations WHERE slug = $1`, slug).Scan(
		&item.ID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveProject(ctx context.Context, project domain.Project) (domain.Project, error) {
	const query = `
		INSERT INTO projects (organization_id, slug, name)
		VALUES ($1, $2, $3)
		ON CONFLICT (organization_id, slug) DO UPDATE
		SET name = EXCLUDED.name,
			updated_at = now()
		RETURNING id::text, organization_id::text, slug::text, name, created_at, updated_at
	`
	var saved domain.Project
	err := r.pool.QueryRow(ctx, query, project.OrganizationID, project.Slug, project.Name).Scan(
		&saved.ID, &saved.OrganizationID, &saved.Slug, &saved.Name, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) UpdateProject(ctx context.Context, projectID domain.ID, update domain.ProjectUpdate) (domain.Project, error) {
	const query = `
		UPDATE projects
		SET slug = $2,
			name = $3,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, organization_id::text, slug::text, name, created_at, updated_at
	`
	var saved domain.Project
	err := r.pool.QueryRow(ctx, query, projectID, update.Slug, update.Name).Scan(
		&saved.ID, &saved.OrganizationID, &saved.Slug, &saved.Name, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListProjects(ctx context.Context, organizationID domain.ID) ([]domain.Project, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, organization_id::text, slug::text, name, created_at, updated_at FROM projects WHERE organization_id = $1 ORDER BY slug`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Project
	for rows.Next() {
		var item domain.Project
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindProjectBySlug(ctx context.Context, organizationID domain.ID, slug string) (domain.Project, bool, error) {
	var item domain.Project
	err := r.pool.QueryRow(ctx, `SELECT id::text, organization_id::text, slug::text, name, created_at, updated_at FROM projects WHERE organization_id = $1 AND slug = $2`, organizationID, slug).Scan(
		&item.ID, &item.OrganizationID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveEnvironment(ctx context.Context, environment domain.Environment) (domain.Environment, error) {
	const query = `
		INSERT INTO environments (project_id, slug, name)
		VALUES ($1, $2, $3)
		ON CONFLICT (project_id, slug) DO UPDATE
		SET name = EXCLUDED.name,
			updated_at = now()
		RETURNING id::text, project_id::text, slug::text, name, created_at, updated_at
	`
	var saved domain.Environment
	err := r.pool.QueryRow(ctx, query, environment.ProjectID, environment.Slug, environment.Name).Scan(
		&saved.ID, &saved.ProjectID, &saved.Slug, &saved.Name, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) UpdateEnvironment(ctx context.Context, environmentID domain.ID, update domain.EnvironmentUpdate) (domain.Environment, error) {
	const query = `
		UPDATE environments
		SET slug = $2,
			name = $3,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, project_id::text, slug::text, name, created_at, updated_at
	`
	var saved domain.Environment
	err := r.pool.QueryRow(ctx, query, environmentID, update.Slug, update.Name).Scan(
		&saved.ID, &saved.ProjectID, &saved.Slug, &saved.Name, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListEnvironments(ctx context.Context, projectID domain.ID) ([]domain.Environment, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, project_id::text, slug::text, name, created_at, updated_at FROM environments WHERE project_id = $1 ORDER BY slug`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Environment
	for rows.Next() {
		var item domain.Environment
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindEnvironmentBySlug(ctx context.Context, projectID domain.ID, slug string) (domain.Environment, bool, error) {
	var item domain.Environment
	err := r.pool.QueryRow(ctx, `SELECT id::text, project_id::text, slug::text, name, created_at, updated_at FROM environments WHERE project_id = $1 AND slug = $2`, projectID, slug).Scan(
		&item.ID, &item.ProjectID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveMonitoredApp(ctx context.Context, app domain.MonitoredApp) (domain.MonitoredApp, error) {
	const query = `
		INSERT INTO monitored_apps (environment_id, slug, name, kind)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (environment_id, slug) DO UPDATE
		SET name = EXCLUDED.name,
			kind = EXCLUDED.kind,
			updated_at = now()
		RETURNING id::text, environment_id::text, slug::text, name, kind, created_at, updated_at
	`
	var saved domain.MonitoredApp
	err := r.pool.QueryRow(ctx, query, app.EnvironmentID, app.Slug, app.Name, app.Kind).Scan(
		&saved.ID, &saved.EnvironmentID, &saved.Slug, &saved.Name, &saved.Kind, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) UpdateMonitoredApp(ctx context.Context, appID domain.ID, update domain.MonitoredAppUpdate) (domain.MonitoredApp, error) {
	const query = `
		UPDATE monitored_apps
		SET slug = $2,
			name = $3,
			kind = $4,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, environment_id::text, slug::text, name, kind, created_at, updated_at
	`
	var saved domain.MonitoredApp
	err := r.pool.QueryRow(ctx, query, appID, update.Slug, update.Name, update.Kind).Scan(
		&saved.ID, &saved.EnvironmentID, &saved.Slug, &saved.Name, &saved.Kind, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListMonitoredApps(ctx context.Context, environmentID domain.ID) ([]domain.MonitoredApp, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, environment_id::text, slug::text, name, kind, created_at, updated_at FROM monitored_apps WHERE environment_id = $1 ORDER BY slug`, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.MonitoredApp
	for rows.Next() {
		var item domain.MonitoredApp
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Slug, &item.Name, &item.Kind, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindMonitoredAppBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.MonitoredApp, bool, error) {
	var item domain.MonitoredApp
	err := r.pool.QueryRow(ctx, `SELECT id::text, environment_id::text, slug::text, name, kind, created_at, updated_at FROM monitored_apps WHERE environment_id = $1 AND slug = $2`, environmentID, slug).Scan(
		&item.ID, &item.EnvironmentID, &item.Slug, &item.Name, &item.Kind, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveService(ctx context.Context, service domain.Service) (domain.Service, error) {
	const query = `
		INSERT INTO services (app_id, slug, name, role)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (app_id, slug) DO UPDATE
		SET name = EXCLUDED.name,
			role = EXCLUDED.role,
			updated_at = now()
		RETURNING id::text, app_id::text, slug::text, name, role, created_at, updated_at
	`
	var saved domain.Service
	err := r.pool.QueryRow(ctx, query, service.AppID, service.Slug, service.Name, service.Role).Scan(
		&saved.ID, &saved.AppID, &saved.Slug, &saved.Name, &saved.Role, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) UpdateService(ctx context.Context, serviceID domain.ID, update domain.ServiceUpdate) (domain.Service, error) {
	const query = `
		UPDATE services
		SET slug = $2,
			name = $3,
			role = $4,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, app_id::text, slug::text, name, role, created_at, updated_at
	`
	var saved domain.Service
	err := r.pool.QueryRow(ctx, query, serviceID, update.Slug, update.Name, update.Role).Scan(
		&saved.ID, &saved.AppID, &saved.Slug, &saved.Name, &saved.Role, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListServices(ctx context.Context, appID domain.ID) ([]domain.Service, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, app_id::text, slug::text, name, role, created_at, updated_at FROM services WHERE app_id = $1 ORDER BY slug`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Service
	for rows.Next() {
		var item domain.Service
		if err := rows.Scan(&item.ID, &item.AppID, &item.Slug, &item.Name, &item.Role, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindServiceBySlug(ctx context.Context, appID domain.ID, slug string) (domain.Service, bool, error) {
	var item domain.Service
	err := r.pool.QueryRow(ctx, `SELECT id::text, app_id::text, slug::text, name, role, created_at, updated_at FROM services WHERE app_id = $1 AND slug = $2`, appID, slug).Scan(
		&item.ID, &item.AppID, &item.Slug, &item.Name, &item.Role, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveHost(ctx context.Context, host domain.Host) (domain.Host, error) {
	const query = `
		INSERT INTO hosts (environment_id, slug, hostname, region, labels)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (environment_id, slug) DO UPDATE
		SET hostname = EXCLUDED.hostname,
			region = EXCLUDED.region,
			labels = EXCLUDED.labels,
			updated_at = now()
		RETURNING id::text, environment_id::text, slug::text, hostname, region, labels, created_at, updated_at
	`
	labels := host.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	var saved domain.Host
	err := r.pool.QueryRow(ctx, query, host.EnvironmentID, host.Slug, host.Hostname, host.Region, labels).Scan(
		&saved.ID, &saved.EnvironmentID, &saved.Slug, &saved.Hostname, &saved.Region, &saved.Labels, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) UpdateHost(ctx context.Context, hostID domain.ID, update domain.HostUpdate) (domain.Host, error) {
	const query = `
		UPDATE hosts
		SET slug = $2,
			hostname = $3,
			region = $4,
			labels = $5,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, environment_id::text, slug::text, hostname, region, labels, created_at, updated_at
	`
	labels := update.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	var saved domain.Host
	err := r.pool.QueryRow(ctx, query, hostID, update.Slug, update.Hostname, update.Region, labels).Scan(
		&saved.ID, &saved.EnvironmentID, &saved.Slug, &saved.Hostname, &saved.Region, &saved.Labels, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListHosts(ctx context.Context, environmentID domain.ID) ([]domain.Host, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, environment_id::text, slug::text, hostname, region, labels, created_at, updated_at FROM hosts WHERE environment_id = $1 ORDER BY slug`, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Host
	for rows.Next() {
		var item domain.Host
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Slug, &item.Hostname, &item.Region, &item.Labels, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindHostBySlug(ctx context.Context, environmentID domain.ID, slug string) (domain.Host, bool, error) {
	var item domain.Host
	err := r.pool.QueryRow(ctx, `SELECT id::text, environment_id::text, slug::text, hostname, region, labels, created_at, updated_at FROM hosts WHERE environment_id = $1 AND slug = $2`, environmentID, slug).Scan(
		&item.ID, &item.EnvironmentID, &item.Slug, &item.Hostname, &item.Region, &item.Labels, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveAgent(ctx context.Context, agent domain.Agent) (domain.Agent, error) {
	const query = `
		INSERT INTO agents (host_id, agent_id, fingerprint, version, last_seen_at, wire_protocol, node_public_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (agent_id) DO UPDATE
		SET host_id = EXCLUDED.host_id,
			fingerprint = EXCLUDED.fingerprint,
			version = EXCLUDED.version,
			last_seen_at = EXCLUDED.last_seen_at,
			wire_protocol = EXCLUDED.wire_protocol,
			node_public_key = CASE
				WHEN EXCLUDED.node_public_key = '' THEN agents.node_public_key
				ELSE EXCLUDED.node_public_key
			END,
			updated_at = now()
		WHERE agents.node_public_key = ''
			OR EXCLUDED.node_public_key = ''
			OR agents.node_public_key = EXCLUDED.node_public_key
		RETURNING id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, wire_protocol, node_public_key, created_at, updated_at
	`
	var saved domain.Agent
	err := r.pool.QueryRow(ctx, query, agent.HostID, agent.AgentID, agent.Fingerprint, agent.Version, agent.LastSeenAt, agent.WireProtocol, agent.NodePublicKey).Scan(
		&saved.ID, &saved.HostID, &saved.AgentID, &saved.Fingerprint, &saved.Version, &saved.LastSeenAt, &saved.WireProtocol, &saved.NodePublicKey, &saved.CreatedAt, &saved.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Agent{}, ports.ErrAgentAlreadyProvisioned
	}
	return saved, err
}

func (r *InventoryRepository) UpdateAgent(ctx context.Context, agentID domain.ID, update domain.AgentUpdate) (domain.Agent, error) {
	const query = `
		UPDATE agents
		SET agent_id = $2,
			version = $3,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, wire_protocol, node_public_key, created_at, updated_at
	`
	var saved domain.Agent
	err := r.pool.QueryRow(ctx, query, agentID, update.AgentID, update.Version).Scan(
		&saved.ID, &saved.HostID, &saved.AgentID, &saved.Fingerprint, &saved.Version, &saved.LastSeenAt, &saved.WireProtocol, &saved.NodePublicKey, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListAgents(ctx context.Context, hostID domain.ID) ([]domain.Agent, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, wire_protocol, node_public_key, created_at, updated_at FROM agents WHERE host_id = $1 ORDER BY agent_id`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Agent
	for rows.Next() {
		var item domain.Agent
		if err := rows.Scan(&item.ID, &item.HostID, &item.AgentID, &item.Fingerprint, &item.Version, &item.LastSeenAt, &item.WireProtocol, &item.NodePublicKey, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindAgentByAgentID(ctx context.Context, agentID string) (domain.Agent, bool, error) {
	var item domain.Agent
	err := r.pool.QueryRow(ctx, `SELECT id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, wire_protocol, node_public_key, created_at, updated_at FROM agents WHERE agent_id = $1`, agentID).Scan(
		&item.ID, &item.HostID, &item.AgentID, &item.Fingerprint, &item.Version, &item.LastSeenAt, &item.WireProtocol, &item.NodePublicKey, &item.CreatedAt, &item.UpdatedAt,
	)
	ok, err := found(err)
	return item, ok, err
}

func (r *InventoryRepository) SaveDeploymentMarker(ctx context.Context, marker domain.DeploymentMarker) (domain.DeploymentMarker, error) {
	const query = `
		INSERT INTO deployment_markers (environment_id, app_id, version, commit_sha, actor, started_at, finished_at)
		VALUES ($1, nullif($2::text, '')::uuid, $3, $4, $5, $6, $7)
		RETURNING id::text, environment_id::text, coalesce(app_id::text, ''), version, commit_sha, actor, started_at, finished_at, created_at
	`
	var saved domain.DeploymentMarker
	err := r.pool.QueryRow(ctx, query, marker.EnvironmentID, string(marker.AppID), marker.Version, marker.CommitSHA, marker.Actor, marker.StartedAt, marker.FinishedAt).Scan(
		&saved.ID, &saved.EnvironmentID, &saved.AppID, &saved.Version, &saved.CommitSHA, &saved.Actor, &saved.StartedAt, &saved.FinishedAt, &saved.CreatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListDeploymentMarkers(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.DeploymentMarker, error) {
	const query = `
		SELECT id::text, environment_id::text, coalesce(app_id::text, ''), version, commit_sha, actor, started_at, finished_at, created_at
		FROM deployment_markers
		WHERE environment_id = $1
			AND (nullif($2::text, '') IS NULL OR app_id = nullif($2::text, '')::uuid)
		ORDER BY started_at DESC
		LIMIT 100
	`
	rows, err := r.pool.Query(ctx, query, environmentID, string(appID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.DeploymentMarker
	for rows.Next() {
		var item domain.DeploymentMarker
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.AppID, &item.Version, &item.CommitSHA, &item.Actor, &item.StartedAt, &item.FinishedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) ListInventoryScopeTree(ctx context.Context) (ports.InventoryScopeTree, error) {
	organizations, err := r.ListOrganizations(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	projects, err := r.listAllProjects(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	environments, err := r.listAllEnvironments(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	apps, err := r.listAllMonitoredApps(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	services, err := r.listAllServices(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	hosts, err := r.listAllHosts(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}
	agents, err := r.listAllAgents(ctx)
	if err != nil {
		return ports.InventoryScopeTree{}, err
	}

	tree := ports.InventoryScopeTree{
		Organizations: make([]ports.InventoryOrganizationScope, 0, len(organizations)),
	}
	organizationIndexes := map[domain.ID]int{}
	for _, organization := range organizations {
		organizationIndexes[organization.ID] = len(tree.Organizations)
		tree.Organizations = append(tree.Organizations, ports.InventoryOrganizationScope{
			Organization: organization,
		})
	}

	type projectIndex struct {
		organization int
		project      int
	}
	projectIndexes := map[domain.ID]projectIndex{}
	for _, project := range projects {
		organizationIndex, ok := organizationIndexes[project.OrganizationID]
		if !ok {
			continue
		}
		projects := &tree.Organizations[organizationIndex].Projects
		projectIndexes[project.ID] = projectIndex{organization: organizationIndex, project: len(*projects)}
		*projects = append(*projects, ports.InventoryProjectScope{Project: project})
	}

	type environmentIndex struct {
		organization int
		project      int
		environment  int
	}
	environmentIndexes := map[domain.ID]environmentIndex{}
	for _, environment := range environments {
		parent, ok := projectIndexes[environment.ProjectID]
		if !ok {
			continue
		}
		environments := &tree.Organizations[parent.organization].Projects[parent.project].Environments
		environmentIndexes[environment.ID] = environmentIndex{organization: parent.organization, project: parent.project, environment: len(*environments)}
		*environments = append(*environments, ports.InventoryEnvironmentScope{Environment: environment})
	}

	type appIndex struct {
		organization int
		project      int
		environment  int
		app          int
	}
	appIndexes := map[domain.ID]appIndex{}
	for _, app := range apps {
		parent, ok := environmentIndexes[app.EnvironmentID]
		if !ok {
			continue
		}
		apps := &tree.Organizations[parent.organization].Projects[parent.project].Environments[parent.environment].Apps
		appIndexes[app.ID] = appIndex{organization: parent.organization, project: parent.project, environment: parent.environment, app: len(*apps)}
		*apps = append(*apps, ports.InventoryAppScope{App: app})
	}
	for _, service := range services {
		parent, ok := appIndexes[service.AppID]
		if !ok {
			continue
		}
		app := &tree.Organizations[parent.organization].Projects[parent.project].Environments[parent.environment].Apps[parent.app]
		app.Services = append(app.Services, service)
	}

	type hostIndex struct {
		organization int
		project      int
		environment  int
		host         int
	}
	hostIndexes := map[domain.ID]hostIndex{}
	for _, host := range hosts {
		parent, ok := environmentIndexes[host.EnvironmentID]
		if !ok {
			continue
		}
		hosts := &tree.Organizations[parent.organization].Projects[parent.project].Environments[parent.environment].Hosts
		hostIndexes[host.ID] = hostIndex{organization: parent.organization, project: parent.project, environment: parent.environment, host: len(*hosts)}
		*hosts = append(*hosts, ports.InventoryHostScope{Host: host})
	}
	for _, agent := range agents {
		parent, ok := hostIndexes[agent.HostID]
		if !ok {
			continue
		}
		host := &tree.Organizations[parent.organization].Projects[parent.project].Environments[parent.environment].Hosts[parent.host]
		host.Agents = append(host.Agents, agent)
	}
	return tree, nil
}

func (r *InventoryRepository) GetInventoryScopeForEnvironment(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string) (ports.InventoryEnvironmentScopePath, bool, error) {
	const query = `
		SELECT
			o.id::text, o.slug::text, o.name, o.created_at, o.updated_at,
			p.id::text, p.organization_id::text, p.slug::text, p.name, p.created_at, p.updated_at,
			e.id::text, e.project_id::text, e.slug::text, e.name, e.created_at, e.updated_at
		FROM organizations o
		JOIN projects p ON p.organization_id = o.id
		JOIN environments e ON e.project_id = p.id
		WHERE o.slug = $1
			AND p.slug = $2
			AND e.slug = $3
	`
	var path ports.InventoryEnvironmentScopePath
	err := r.pool.QueryRow(ctx, query, organizationSlug, projectSlug, environmentSlug).Scan(
		&path.Organization.ID, &path.Organization.Slug, &path.Organization.Name, &path.Organization.CreatedAt, &path.Organization.UpdatedAt,
		&path.Project.ID, &path.Project.OrganizationID, &path.Project.Slug, &path.Project.Name, &path.Project.CreatedAt, &path.Project.UpdatedAt,
		&path.Environment.ID, &path.Environment.ProjectID, &path.Environment.Slug, &path.Environment.Name, &path.Environment.CreatedAt, &path.Environment.UpdatedAt,
	)
	ok, err := found(err)
	if err != nil || !ok {
		return ports.InventoryEnvironmentScopePath{}, ok, err
	}

	apps, err := r.ListMonitoredApps(ctx, path.Environment.ID)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	hosts, err := r.ListHosts(ctx, path.Environment.ID)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	services, err := r.listServicesForApps(ctx, apps)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}
	agents, err := r.listAgentsForHosts(ctx, hosts)
	if err != nil {
		return ports.InventoryEnvironmentScopePath{}, false, err
	}

	path.Apps = make([]ports.InventoryAppScope, 0, len(apps))
	for _, app := range apps {
		path.Apps = append(path.Apps, ports.InventoryAppScope{
			App:      app,
			Services: services[app.ID],
		})
	}
	path.Hosts = make([]ports.InventoryHostScope, 0, len(hosts))
	for _, host := range hosts {
		path.Hosts = append(path.Hosts, ports.InventoryHostScope{
			Host:   host,
			Agents: agents[host.ID],
		})
	}
	return path, true, nil
}

func (r *InventoryRepository) listServicesForApps(ctx context.Context, apps []domain.MonitoredApp) (map[domain.ID][]domain.Service, error) {
	byApp := make(map[domain.ID][]domain.Service, len(apps))
	if len(apps) == 0 {
		return byApp, nil
	}
	ids := make([]domain.ID, 0, len(apps))
	for _, app := range apps {
		ids = append(ids, app.ID)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, app_id::text, slug::text, name, role, created_at, updated_at
		FROM services
		WHERE app_id = ANY($1::uuid[])
		ORDER BY app_id, slug
	`, stringIDs(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.Service
		if err := rows.Scan(&item.ID, &item.AppID, &item.Slug, &item.Name, &item.Role, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		byApp[item.AppID] = append(byApp[item.AppID], item)
	}
	return byApp, rows.Err()
}

func (r *InventoryRepository) listAgentsForHosts(ctx context.Context, hosts []domain.Host) (map[domain.ID][]domain.Agent, error) {
	byHost := make(map[domain.ID][]domain.Agent, len(hosts))
	if len(hosts) == 0 {
		return byHost, nil
	}
	ids := make([]domain.ID, 0, len(hosts))
	for _, host := range hosts {
		ids = append(ids, host.ID)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, wire_protocol, node_public_key, created_at, updated_at
		FROM agents
		WHERE host_id = ANY($1::uuid[])
		ORDER BY host_id, agent_id
	`, stringIDs(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.Agent
		if err := rows.Scan(&item.ID, &item.HostID, &item.AgentID, &item.Fingerprint, &item.Version, &item.LastSeenAt, &item.WireProtocol, &item.NodePublicKey, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		byHost[item.HostID] = append(byHost[item.HostID], item)
	}
	return byHost, rows.Err()
}

func (r *InventoryRepository) listAllProjects(ctx context.Context) ([]domain.Project, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, organization_id::text, slug::text, name, created_at, updated_at FROM projects ORDER BY organization_id, slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Project
	for rows.Next() {
		var item domain.Project
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) listAllEnvironments(ctx context.Context) ([]domain.Environment, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, project_id::text, slug::text, name, created_at, updated_at FROM environments ORDER BY project_id, slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Environment
	for rows.Next() {
		var item domain.Environment
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.Slug, &item.Name, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) listAllMonitoredApps(ctx context.Context) ([]domain.MonitoredApp, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, environment_id::text, slug::text, name, kind, created_at, updated_at FROM monitored_apps ORDER BY environment_id, slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.MonitoredApp
	for rows.Next() {
		var item domain.MonitoredApp
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Slug, &item.Name, &item.Kind, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) listAllServices(ctx context.Context) ([]domain.Service, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, app_id::text, slug::text, name, role, created_at, updated_at FROM services ORDER BY app_id, slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Service
	for rows.Next() {
		var item domain.Service
		if err := rows.Scan(&item.ID, &item.AppID, &item.Slug, &item.Name, &item.Role, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) listAllHosts(ctx context.Context) ([]domain.Host, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, environment_id::text, slug::text, hostname, region, labels, created_at, updated_at FROM hosts ORDER BY environment_id, slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Host
	for rows.Next() {
		var item domain.Host
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Slug, &item.Hostname, &item.Region, &item.Labels, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) listAllAgents(ctx context.Context) ([]domain.Agent, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, wire_protocol, node_public_key, created_at, updated_at FROM agents ORDER BY host_id, agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Agent
	for rows.Next() {
		var item domain.Agent
		if err := rows.Scan(&item.ID, &item.HostID, &item.AgentID, &item.Fingerprint, &item.Version, &item.LastSeenAt, &item.WireProtocol, &item.NodePublicKey, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func found(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return false, err
}
