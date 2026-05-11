package hub

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type BootstrapSingleSiteInput struct {
	OrganizationSlug string
	OrganizationName string
	ProjectSlug      string
	ProjectName      string
	EnvironmentSlug  string
	EnvironmentName  string
	AppSlug          string
	AppName          string
	Kind             string
	ServiceSlug      string
	ServiceName      string
	ServiceRole      string
	HostSlug         string
	Hostname         string
	Region           string
	HostLabels       map[string]string
	AgentID          string
	Fingerprint      string
	AgentVersion     string
}

type BootstrapSingleSiteResult struct {
	Organization domain.Organization
	Project      domain.Project
	Environment  domain.Environment
	App          domain.MonitoredApp
	Service      domain.Service
	Host         domain.Host
	Agent        domain.Agent
}

func (h *Hub) BootstrapSingleSite(ctx context.Context, input BootstrapSingleSiteInput) (BootstrapSingleSiteResult, error) {
	if err := h.requireInventory(); err != nil {
		return BootstrapSingleSiteResult{}, err
	}

	kind, err := normalizeBootstrapKind(input.Kind)
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}

	environmentSlug := defaultString(input.EnvironmentSlug, "production")
	environmentName := defaultString(input.EnvironmentName, "Production")
	appSlug := defaultString(input.AppSlug, "main-web")
	appName := defaultString(input.AppName, bootstrapAppName(kind))
	serviceSlug := defaultString(input.ServiceSlug, "frontend")
	serviceName := defaultString(input.ServiceName, "Frontend")
	serviceRole := defaultString(input.ServiceRole, "web")

	hostSlug := strings.TrimSpace(input.HostSlug)
	if hostSlug == "" {
		return BootstrapSingleSiteResult{}, errors.New("host slug is required")
	}
	agentID := strings.TrimSpace(input.AgentID)
	if agentID == "" {
		return BootstrapSingleSiteResult{}, errors.New("agent id is required")
	}
	fingerprint := strings.TrimSpace(input.Fingerprint)
	if fingerprint == "" {
		return BootstrapSingleSiteResult{}, errors.New("agent fingerprint is required")
	}

	organization, err := h.SaveOrganization(ctx, SaveOrganizationInput{
		Slug: input.OrganizationSlug,
		Name: input.OrganizationName,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}
	project, err := h.SaveProject(ctx, SaveProjectInput{
		OrganizationSlug: organization.Slug,
		Slug:             input.ProjectSlug,
		Name:             input.ProjectName,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}
	environment, err := h.SaveEnvironment(ctx, SaveEnvironmentInput{
		OrganizationSlug: organization.Slug,
		ProjectSlug:      project.Slug,
		Slug:             environmentSlug,
		Name:             environmentName,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}
	app, err := h.SaveMonitoredApp(ctx, SaveMonitoredAppInput{
		OrganizationSlug: organization.Slug,
		ProjectSlug:      project.Slug,
		EnvironmentSlug:  environment.Slug,
		Slug:             appSlug,
		Name:             appName,
		Kind:             kind,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}
	service, err := h.SaveService(ctx, SaveServiceInput{
		OrganizationSlug: organization.Slug,
		ProjectSlug:      project.Slug,
		EnvironmentSlug:  environment.Slug,
		AppSlug:          app.Slug,
		Slug:             serviceSlug,
		Name:             serviceName,
		Role:             serviceRole,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}
	host, err := h.SaveHost(ctx, SaveHostInput{
		OrganizationSlug: organization.Slug,
		ProjectSlug:      project.Slug,
		EnvironmentSlug:  environment.Slug,
		Slug:             hostSlug,
		Hostname:         input.Hostname,
		Region:           input.Region,
		Labels:           input.HostLabels,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}
	agent, err := h.SaveAgent(ctx, SaveAgentInput{
		OrganizationSlug: organization.Slug,
		ProjectSlug:      project.Slug,
		EnvironmentSlug:  environment.Slug,
		HostSlug:         host.Slug,
		AgentID:          agentID,
		Fingerprint:      fingerprint,
		Version:          input.AgentVersion,
	})
	if err != nil {
		return BootstrapSingleSiteResult{}, err
	}

	return BootstrapSingleSiteResult{
		Organization: organization,
		Project:      project,
		Environment:  environment,
		App:          app,
		Service:      service,
		Host:         host,
		Agent:        agent,
	}, nil
}

func normalizeBootstrapKind(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "wordpress", "wp", "woocommerce":
		return "wordpress", nil
	case "prestashop", "ps":
		return "prestashop", nil
	case "":
		return "", errors.New("app kind is required")
	default:
		return "", fmt.Errorf("app kind %q is not supported; use wordpress or prestashop", value)
	}
}

func bootstrapAppName(kind string) string {
	switch kind {
	case "prestashop":
		return "PrestaShop"
	case "wordpress":
		return "WordPress"
	default:
		return kind
	}
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
