package hub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestCorrelateEventsSavesWordPressDatabaseDiffFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-db-admin",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			AppSlug:         app.Slug,
			HostID:          host.ID,
			HostSlug:        host.Slug,
			AgentID:         agent.ID,
			AgentExternalID: agent.AgentID,
			EventTime:       now,
			EventType:       "db.snapshot.check_changed",
			Target:          "wordpress:wp_usermeta:admin_users",
			Severity:        domain.SeverityMedium,
			Message:         "Database check wordpress.admin_users.count changed for wordpress",
			Labels: map[string]string{
				"db_profile": "wordpress",
				"db_check":   "wordpress.admin_users.count",
			},
			Payload: map[string]any{
				"database": "wordpress",
				"profile":  "wordpress",
				"check":    "wordpress.admin_users.count",
				"metric":   "admin_users",
				"table":    "wp_usermeta",
				"previous": map[string]any{
					"count":     1,
					"signature": "count:1",
				},
				"current": map[string]any{
					"count":     2,
					"signature": "count:2",
				},
			},
		},
	}

	result, err := hub.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		Window:           30 * time.Minute,
		SaveFindings:     true,
	})
	if err != nil {
		t.Fatalf("CorrelateEvents returned error: %v", err)
	}
	if len(result.Chains) != 1 {
		t.Fatalf("chains = %#v, want one DB finding chain", result.Chains)
	}
	chain := result.Chains[0]
	if chain.RuleID != "wordpress-admin-users-changed" || chain.Severity != domain.SeverityHigh || chain.Confidence != domain.ConfidenceHigh {
		t.Fatalf("chain = %#v, want high-confidence WordPress admin finding", chain)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one saved finding", result.Findings)
	}
	finding := result.Findings[0]
	if finding.RuleID != "wordpress-admin-users-changed" || finding.Title != "WordPress administrator count changed" {
		t.Fatalf("finding = %#v, want WordPress administrator finding", finding)
	}
	if len(finding.EventIDs) != 1 || finding.EventIDs[0] != "evt-db-admin" {
		t.Fatalf("event ids = %#v, want source DB event", finding.EventIDs)
	}
	risk, ok := finding.Metadata["risk"].(map[string]any)
	if !ok || risk["score"] == nil || risk["band"] == "" {
		t.Fatalf("risk metadata = %#v, want scored finding", finding.Metadata["risk"])
	}
}

func TestCorrelateEventsSavesWordPressAdminEntityFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 12, 30, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-db-admin-entity",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			AppSlug:         app.Slug,
			HostID:          host.ID,
			HostSlug:        host.Slug,
			AgentID:         agent.ID,
			AgentExternalID: agent.AgentID,
			EventTime:       now,
			EventType:       "db.entity.added",
			Target:          "wordpress:wordpress_user:wordpress_user:abc",
			Severity:        domain.SeverityHigh,
			Message:         "Privileged database entity wordpress_user added for wordpress",
			Labels: map[string]string{
				"db_profile":     "wordpress",
				"db_entity_type": "wordpress_user",
			},
			Payload: map[string]any{
				"database":    "wordpress",
				"profile":     "wordpress",
				"entity_type": "wordpress_user",
				"entity_key":  "wordpress_user:abc",
				"current": map[string]any{
					"type":       "wordpress_user",
					"key":        "wordpress_user:abc",
					"privileged": true,
					"signature":  "sig-admin",
					"attributes": map[string]any{
						"administrator":   true,
						"account_display": "r***n@gmail.com",
						"email_masked":    "r***n@gmail.com",
					},
				},
			},
		},
	}

	result, err := hub.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		SaveFindings:     true,
	})
	if err != nil {
		t.Fatalf("CorrelateEvents returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one saved finding", result.Findings)
	}
	finding := result.Findings[0]
	if finding.RuleID != "wordpress-admin-user-added" || finding.Severity != domain.SeverityHigh || finding.Confidence != domain.ConfidenceHigh {
		t.Fatalf("finding = %#v, want WordPress admin entity finding", finding)
	}
	if !strings.Contains(finding.Summary, "account r***n@gmail.com") {
		t.Fatalf("summary = %q, want masked account display", finding.Summary)
	}
}

func TestCorrelateEventsAddsDeploymentContextWithoutLoweringHighRiskFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 12, 35, 0, 0, time.UTC)
	finishedAt := now.Add(10 * time.Minute)
	if _, err := hub.SaveDeploymentMarker(ctx, SaveDeploymentMarkerInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Version:          "v1.8.2",
		CommitSHA:        "a91f72c",
		Actor:            "github-actions",
		StartedAt:        now.Add(-10 * time.Minute),
		FinishedAt:       &finishedAt,
	}); err != nil {
		t.Fatalf("SaveDeploymentMarker returned error: %v", err)
	}
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-db-admin-during-deploy",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			AppSlug:         app.Slug,
			HostID:          host.ID,
			HostSlug:        host.Slug,
			AgentID:         agent.ID,
			AgentExternalID: agent.AgentID,
			EventTime:       now,
			EventType:       "db.entity.added",
			Target:          "wordpress:wordpress_user:wordpress_user:abc",
			Severity:        domain.SeverityHigh,
			Message:         "Privileged database entity wordpress_user added for wordpress",
			Labels: map[string]string{
				"db_profile":     "wordpress",
				"db_entity_type": "wordpress_user",
			},
			Payload: map[string]any{
				"database":    "wordpress",
				"profile":     "wordpress",
				"entity_type": "wordpress_user",
				"entity_key":  "wordpress_user:abc",
				"current": map[string]any{
					"type":       "wordpress_user",
					"key":        "wordpress_user:abc",
					"privileged": true,
					"signature":  "sig-admin",
					"attributes": map[string]any{
						"administrator":     true,
						"account_display":   "r***n@gmail.com",
						"email_masked":      "r***n@gmail.com",
						"email_hmac_sha256": "fingerprint",
					},
				},
			},
		},
	}

	result, err := hub.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		SaveFindings:     true,
	})
	if err != nil {
		t.Fatalf("CorrelateEvents returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one saved finding", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Severity != domain.SeverityHigh {
		t.Fatalf("finding = %#v, want high-risk admin finding to remain high during deployment", finding)
	}
	deploymentContext, ok := finding.Metadata["deployment_context"].(map[string]any)
	if !ok || deploymentContext["active"] != true {
		t.Fatalf("deployment context = %#v, want active context", finding.Metadata["deployment_context"])
	}
	if deploymentContext["severity_adjusted"] != false || deploymentContext["original_severity"] != "high" || deploymentContext["adjusted_severity"] != "high" {
		t.Fatalf("deployment context = %#v, want high severity unchanged", deploymentContext)
	}
}

func TestCorrelateEventsBuildsWordPressPluginAndOptionEntityChains(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 45, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-wp-plugin",
			EventTime: now,
			EventType: "db.entity.added",
			Target:    "wordpress:wordpress_plugin:bad-builder/bad-builder.php",
			Severity:  domain.SeverityMedium,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "wordpress",
				"db_entity_type": "wordpress_plugin",
			},
			Payload: map[string]any{
				"profile":     "wordpress",
				"entity_type": "wordpress_plugin",
				"entity_key":  "wordpress_plugin:abc",
				"current": map[string]any{
					"type":      "wordpress_plugin",
					"key":       "wordpress_plugin:abc",
					"label":     "bad-builder/bad-builder.php",
					"signature": "sig-plugin",
					"attributes": map[string]any{
						"active":      true,
						"plugin_slug": "bad-builder",
					},
				},
			},
		},
		{
			ID:        "evt-wp-registration",
			EventTime: now.Add(time.Minute),
			EventType: "db.entity.changed",
			Target:    "wordpress:wordpress_option:site:default_role",
			Severity:  domain.SeverityHigh,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "wordpress",
				"db_entity_type": "wordpress_option",
			},
			Payload: map[string]any{
				"profile":     "wordpress",
				"entity_type": "wordpress_option",
				"entity_key":  "wordpress_option:def",
				"current": map[string]any{
					"type":      "wordpress_option",
					"key":       "wordpress_option:def",
					"label":     "site:default_role",
					"signature": "sig-option",
					"attributes": map[string]any{
						"option_name": "default_role",
					},
				},
			},
		},
	}, 30*time.Minute)
	if len(chains) != 2 {
		t.Fatalf("chains = %#v, want plugin and option chains", chains)
	}
	byRule := map[string]CorrelationChain{}
	for _, chain := range chains {
		byRule[chain.RuleID] = chain
	}
	if _, ok := byRule["wordpress-active-plugin-added"]; !ok {
		t.Fatalf("chains = %#v, want active plugin added", chains)
	}
	if byRule["wordpress-registration-option-changed"].Severity != domain.SeverityHigh {
		t.Fatalf("registration chain = %#v, want high severity", byRule["wordpress-registration-option-changed"])
	}
}

func TestCorrelateEventsBuildsWordPressCronAndScriptContentEntityChains(t *testing.T) {
	now := time.Date(2026, 5, 12, 12, 50, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-wp-cron",
			EventTime: now,
			EventType: "db.entity.added",
			Target:    "wordpress:wordpress_cron:evil_shell_exec",
			Severity:  domain.SeverityHigh,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "wordpress",
				"db_entity_type": "wordpress_cron",
			},
			Payload: map[string]any{
				"profile":     "wordpress",
				"entity_type": "wordpress_cron",
				"entity_key":  "wordpress_cron:abc",
				"current": map[string]any{
					"type":      "wordpress_cron",
					"key":       "wordpress_cron:abc",
					"label":     "evil_shell_exec",
					"signature": "sig-cron",
					"attributes": map[string]any{
						"hook_name":  "evil_shell_exec",
						"suspicious": true,
					},
				},
			},
		},
		{
			ID:        "evt-wp-content",
			EventTime: now.Add(time.Minute),
			EventType: "db.entity.changed",
			Target:    "wordpress:wordpress_content_script:post:page:abc",
			Severity:  domain.SeverityMedium,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "wordpress",
				"db_entity_type": "wordpress_content_script",
			},
			Payload: map[string]any{
				"profile":     "wordpress",
				"entity_type": "wordpress_content_script",
				"entity_key":  "wordpress_content_script:def",
				"previous": map[string]any{
					"type":      "wordpress_content_script",
					"key":       "wordpress_content_script:def",
					"signature": "sig-content-old",
					"attributes": map[string]any{
						"external_domains_count": 0,
					},
				},
				"current": map[string]any{
					"type":      "wordpress_content_script",
					"key":       "wordpress_content_script:def",
					"signature": "sig-content-new",
					"attributes": map[string]any{
						"external_domains_count": 1,
						"indicator_count":        2,
					},
				},
			},
		},
	}, 30*time.Minute)
	if len(chains) != 2 {
		t.Fatalf("chains = %#v, want cron and script content chains", chains)
	}
	byRule := map[string]CorrelationChain{}
	for _, chain := range chains {
		byRule[chain.RuleID] = chain
	}
	if byRule["wordpress-suspicious-cron-task-added"].Severity != domain.SeverityHigh {
		t.Fatalf("cron chain = %#v, want high severity suspicious cron", byRule["wordpress-suspicious-cron-task-added"])
	}
	if byRule["wordpress-script-content-domain-added"].Severity != domain.SeverityHigh {
		t.Fatalf("content chain = %#v, want high severity domain addition", byRule["wordpress-script-content-domain-added"])
	}
}

func TestCorrelateEventsBuildsPrestaShopDatabaseDiffChain(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-db-module",
			EventTime: now,
			EventType: "db.snapshot.check_changed",
			Target:    "prestashop:ps_module:active_modules",
			Severity:  domain.SeverityMedium,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile": "prestashop",
				"db_check":   "prestashop.active_modules.count",
			},
			Payload: map[string]any{
				"profile": "prestashop",
				"check":   "prestashop.active_modules.count",
				"metric":  "active_modules",
				"table":   "ps_module",
				"previous": map[string]any{
					"count":     20,
					"signature": "count:20",
				},
				"current": map[string]any{
					"count":     21,
					"signature": "count:21",
				},
			},
		},
	}, 30*time.Minute)
	if len(chains) != 1 {
		t.Fatalf("chains = %#v, want one PrestaShop DB chain", chains)
	}
	chain := chains[0]
	if chain.RuleID != "prestashop-modules-changed" || chain.Title != "PrestaShop module count changed" || chain.Severity != domain.SeverityMedium {
		t.Fatalf("chain = %#v, want PrestaShop module change", chain)
	}
	if chain.Summary == "" || chain.Events[0].EventID != "evt-db-module" {
		t.Fatalf("chain summary/events = %#v", chain)
	}
}

func TestCorrelateEventsBuildsPrestaShopModuleEntityChain(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 30, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-db-module-entity",
			EventTime: now,
			EventType: "db.entity.added",
			Target:    "prestashop:prestashop_module:ps_checkout",
			Severity:  domain.SeverityMedium,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "prestashop",
				"db_entity_type": "prestashop_module",
			},
			Payload: map[string]any{
				"profile":     "prestashop",
				"entity_type": "prestashop_module",
				"entity_key":  "prestashop_module:def",
				"current": map[string]any{
					"type":       "prestashop_module",
					"key":        "prestashop_module:def",
					"label":      "ps_checkout",
					"signature":  "sig-module",
					"attributes": map[string]any{"active": true, "module_name": "ps_checkout"},
				},
			},
		},
	}, 30*time.Minute)
	if len(chains) != 1 {
		t.Fatalf("chains = %#v, want one PrestaShop module entity chain", chains)
	}
	chain := chains[0]
	if chain.RuleID != "prestashop-active-module-added" || chain.Title != "PrestaShop active module added" {
		t.Fatalf("chain = %#v, want active module entity finding", chain)
	}
}

func TestCorrelateEventsBuildsPrestaShopConfigurationEntityChains(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 45, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-ps-debug-config",
			EventTime: now,
			EventType: "db.entity.changed",
			Target:    "prestashop:prestashop_configuration:PS_MODE_DEV",
			Severity:  domain.SeverityHigh,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "prestashop",
				"db_entity_type": "prestashop_configuration",
			},
			Payload: map[string]any{
				"profile":     "prestashop",
				"entity_type": "prestashop_configuration",
				"entity_key":  "prestashop_configuration:debug",
				"previous": map[string]any{
					"type":      "prestashop_configuration",
					"key":       "prestashop_configuration:debug",
					"signature": "sig-debug-old",
					"attributes": map[string]any{
						"category":   "debug",
						"suspicious": false,
					},
				},
				"current": map[string]any{
					"type":      "prestashop_configuration",
					"key":       "prestashop_configuration:debug",
					"signature": "sig-debug-new",
					"attributes": map[string]any{
						"category":    "debug",
						"config_name": "PS_MODE_DEV",
						"suspicious":  true,
					},
				},
			},
		},
		{
			ID:        "evt-ps-payment-config",
			EventTime: now.Add(time.Minute),
			EventType: "db.entity.changed",
			Target:    "prestashop:prestashop_configuration:PS_CHECKOUT_CLIENT_SECRET",
			Severity:  domain.SeverityMedium,
			HostSlug:  "web-01",
			Labels: map[string]string{
				"db_profile":     "prestashop",
				"db_entity_type": "prestashop_configuration",
			},
			Payload: map[string]any{
				"profile":     "prestashop",
				"entity_type": "prestashop_configuration",
				"entity_key":  "prestashop_configuration:payment",
				"current": map[string]any{
					"type":      "prestashop_configuration",
					"key":       "prestashop_configuration:payment",
					"signature": "sig-payment-new",
					"attributes": map[string]any{
						"category":    "payment",
						"config_name": "PS_CHECKOUT_CLIENT_SECRET",
						"sensitive":   true,
					},
				},
			},
		},
	}, 30*time.Minute)
	if len(chains) != 2 {
		t.Fatalf("chains = %#v, want two PrestaShop configuration chains", chains)
	}
	byRule := map[string]CorrelationChain{}
	for _, chain := range chains {
		byRule[chain.RuleID] = chain
	}
	if byRule["prestashop-suspicious-configuration-changed"].Severity != domain.SeverityHigh {
		t.Fatalf("debug config chain = %#v, want high severity suspicious config", byRule["prestashop-suspicious-configuration-changed"])
	}
	if byRule["prestashop-payment-configuration-changed"].Severity != domain.SeverityHigh {
		t.Fatalf("payment config chain = %#v, want high severity payment config", byRule["prestashop-payment-configuration-changed"])
	}
}

func bootstrapDatabaseDiffInventory(t *testing.T, ctx context.Context, hub *Hub, appKind string) (domain.Environment, domain.MonitoredApp, domain.Host, domain.Agent) {
	t.Helper()
	if _, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme"}); err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	if _, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site"}); err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	environment, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production"})
	if err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		Slug:             "main-web",
		Kind:             appKind,
	})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	host, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-01"})
	if err != nil {
		t.Fatalf("SaveHost returned error: %v", err)
	}
	agent, err := hub.SaveAgent(ctx, SaveAgentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", HostSlug: "web-01", AgentID: "agt_web_01", Fingerprint: "SHA256:test"})
	if err != nil {
		t.Fatalf("SaveAgent returned error: %v", err)
	}
	return environment, app, host, agent
}
