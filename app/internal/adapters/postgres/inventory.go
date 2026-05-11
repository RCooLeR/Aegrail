package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
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
		INSERT INTO agents (host_id, agent_id, fingerprint, version, last_seen_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (agent_id) DO UPDATE
		SET host_id = EXCLUDED.host_id,
			fingerprint = EXCLUDED.fingerprint,
			version = EXCLUDED.version,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = now()
		RETURNING id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, created_at, updated_at
	`
	var saved domain.Agent
	err := r.pool.QueryRow(ctx, query, agent.HostID, agent.AgentID, agent.Fingerprint, agent.Version, agent.LastSeenAt).Scan(
		&saved.ID, &saved.HostID, &saved.AgentID, &saved.Fingerprint, &saved.Version, &saved.LastSeenAt, &saved.CreatedAt, &saved.UpdatedAt,
	)
	return saved, err
}

func (r *InventoryRepository) ListAgents(ctx context.Context, hostID domain.ID) ([]domain.Agent, error) {
	rows, err := r.pool.Query(ctx, `SELECT id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, created_at, updated_at FROM agents WHERE host_id = $1 ORDER BY agent_id`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.Agent
	for rows.Next() {
		var item domain.Agent
		if err := rows.Scan(&item.ID, &item.HostID, &item.AgentID, &item.Fingerprint, &item.Version, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *InventoryRepository) FindAgentByAgentID(ctx context.Context, agentID string) (domain.Agent, bool, error) {
	var item domain.Agent
	err := r.pool.QueryRow(ctx, `SELECT id::text, host_id::text, agent_id::text, fingerprint, version, last_seen_at, created_at, updated_at FROM agents WHERE agent_id = $1`, agentID).Scan(
		&item.ID, &item.HostID, &item.AgentID, &item.Fingerprint, &item.Version, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt,
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

func found(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return false, err
}
