package hub

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestCorrelateEventsBuildsProbableIncidentChain(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

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
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	host, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-02"})
	if err != nil {
		t.Fatalf("SaveHost returned error: %v", err)
	}
	agent, err := hub.SaveAgent(ctx, SaveAgentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", HostSlug: "web-02", AgentID: "agt_web_02", Fingerprint: "SHA256:test"})
	if err != nil {
		t.Fatalf("SaveAgent returned error: %v", err)
	}

	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-login",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "web-02",
			AgentID:         agent.ID,
			AgentExternalID: "agt_web_02",
			EventTime:       now,
			EventType:       "log.access",
			Target:          "/wp-login.php",
			Severity:        domain.SeverityInfo,
			Payload: map[string]any{
				"path":        "/wp-login.php",
				"status_code": 200,
			},
		},
		{
			ID:              "evt-file",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "web-02",
			AgentID:         agent.ID,
			AgentExternalID: "agt_web_02",
			EventTime:       now.Add(4 * time.Minute),
			EventType:       "file.created",
			Target:          "/var/www/wp-content/uploads/avatar.php",
			Severity:        domain.SeverityHigh,
			Payload: map[string]any{
				"relative_path": "wp-content/uploads/avatar.php",
				"sha256":        "shell",
			},
		},
		{
			ID:              "evt-db",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "db-01",
			AgentID:         agent.ID,
			AgentExternalID: "agt_db_01",
			EventTime:       now.Add(8 * time.Minute),
			EventType:       "db.role_changed",
			Target:          "users:42",
			Severity:        domain.SeverityHigh,
			Message:         "role changed from editor to admin",
			Payload:         map[string]any{},
		},
	}

	result, err := hub.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		Window:           30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CorrelateEvents returned error: %v", err)
	}
	if result.Events != 3 {
		t.Fatalf("events = %d, want 3", result.Events)
	}
	if len(result.Chains) == 0 {
		t.Fatal("expected at least one correlation chain")
	}
	if len(result.Chains) != 1 {
		t.Fatalf("chains = %#v, want only the highest-signal chain", result.Chains)
	}
	chain := result.Chains[0]
	if chain.RuleID != "probable-incident-chain" || chain.Severity != domain.SeverityHigh || chain.Confidence != domain.ConfidenceHigh {
		t.Fatalf("chain = %#v", chain)
	}
	if len(chain.Events) != 3 {
		t.Fatalf("chain events = %#v, want 3", chain.Events)
	}
}

func TestCorrelateEventsSavesAndDeduplicatesFindings(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest, Findings: findings})
	ctx := context.Background()

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
	app, err := hub.SaveMonitoredApp(ctx, SaveMonitoredAppInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "main-web", Kind: "wordpress"})
	if err != nil {
		t.Fatalf("SaveMonitoredApp returned error: %v", err)
	}
	host, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-02"})
	if err != nil {
		t.Fatalf("SaveHost returned error: %v", err)
	}
	agent, err := hub.SaveAgent(ctx, SaveAgentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", HostSlug: "web-02", AgentID: "agt_web_02", Fingerprint: "SHA256:test"})
	if err != nil {
		t.Fatalf("SaveAgent returned error: %v", err)
	}

	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-login",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "web-02",
			AgentID:         agent.ID,
			AgentExternalID: "agt_web_02",
			EventTime:       now,
			EventType:       "log.access",
			Target:          "/wp-login.php",
			Severity:        domain.SeverityInfo,
			Payload: map[string]any{
				"path":        "/wp-login.php",
				"status_code": 200,
			},
		},
		{
			ID:              "evt-file",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "web-02",
			AgentID:         agent.ID,
			AgentExternalID: "agt_web_02",
			EventTime:       now.Add(4 * time.Minute),
			EventType:       "file.created",
			Target:          "/var/www/wp-content/uploads/avatar.php",
			Severity:        domain.SeverityHigh,
			Payload: map[string]any{
				"relative_path": "wp-content/uploads/avatar.php",
			},
		},
		{
			ID:              "evt-db",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        "db-01",
			AgentID:         agent.ID,
			AgentExternalID: "agt_db_01",
			EventTime:       now.Add(8 * time.Minute),
			EventType:       "db.role_changed",
			Target:          "users:42",
			Severity:        domain.SeverityHigh,
			Message:         "role changed from editor to admin",
			Payload:         map[string]any{},
		},
	}

	input := CorrelateEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
		Window:           30 * time.Minute,
		SaveFindings:     true,
	}
	result, err := hub.CorrelateEvents(ctx, input)
	if err != nil {
		t.Fatalf("CorrelateEvents returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("saved findings = %#v, want 1", result.Findings)
	}
	if result.Findings[0].RuleID != "probable-incident-chain" || result.Findings[0].DedupeKey == "" {
		t.Fatalf("saved finding = %#v", result.Findings[0])
	}

	if _, err := hub.CorrelateEvents(ctx, input); err != nil {
		t.Fatalf("second CorrelateEvents returned error: %v", err)
	}
	stored, err := hub.ListHubFindings(ctx, ListHubFindingsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
	})
	if err != nil {
		t.Fatalf("ListHubFindings returned error: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored findings = %#v, want one deduplicated row", stored)
	}
	if got, want := len(stored[0].EventIDs), 3; got != want {
		t.Fatalf("stored event ids = %d, want %d", got, want)
	}
}

func TestCorrelateEventsBuildsSuspiciousFilePathChains(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-upload-php",
			EventTime: now,
			EventType: "file.created",
			Target:    "wp-content/uploads/avatar.php",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-content/uploads/avatar.php", "sha256": "upload-php"},
		},
		{
			ID:        "evt-config",
			EventTime: now.Add(time.Minute),
			EventType: "file.modified",
			Target:    "wp-config.php",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-config.php", "sha256": "config"},
		},
		{
			ID:        "evt-plugin",
			EventTime: now.Add(2 * time.Minute),
			EventType: "file.modified",
			Target:    "wp-content/plugins/shop/plugin.php",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-content/plugins/shop/plugin.php", "sha256": "plugin"},
		},
		{
			ID:        "evt-php",
			EventTime: now.Add(3 * time.Minute),
			EventType: "file.modified",
			Target:    "public/index.php",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "public/index.php", "sha256": "php"},
		},
		{
			ID:        "evt-shell-name",
			EventTime: now.Add(4 * time.Minute),
			EventType: "file.created",
			Target:    "assets/shell.txt",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "assets/shell.txt", "sha256": "shell-name"},
		},
		{
			ID:        "evt-static",
			EventTime: now.Add(5 * time.Minute),
			EventType: "file.created",
			Target:    "wp-content/uploads/logo.png",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-content/uploads/logo.png", "sha256": "static"},
		},
	}, 30*time.Minute)

	byRule := map[string]CorrelationChain{}
	for _, chain := range chains {
		byRule[chain.RuleID] = chain
	}
	for _, ruleID := range []string{
		"file-php-in-writable-path",
		"file-sensitive-config-changed",
		"file-plugin-theme-module-changed",
		"file-php-changed",
		"file-suspicious-path-pattern",
	} {
		if _, ok := byRule[ruleID]; !ok {
			t.Fatalf("chains = %#v, missing %s", chains, ruleID)
		}
	}
	if len(chains) != 5 {
		t.Fatalf("chains = %#v, want five suspicious file path findings", chains)
	}
	if byRule["file-php-in-writable-path"].Severity != domain.SeverityHigh ||
		byRule["file-sensitive-config-changed"].Severity != domain.SeverityHigh {
		t.Fatalf("chains = %#v, want high severity upload PHP and config findings", chains)
	}
}

func TestCorrelateEventsGroupsPluginFileChanges(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 15, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-plugin-main",
			EventTime: now,
			EventType: "file.created",
			Target:    "wp-content/plugins/shop/shop.php",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-content/plugins/shop/shop.php", "sha256": "plugin-main"},
		},
		{
			ID:        "evt-plugin-readme",
			EventTime: now.Add(time.Minute),
			EventType: "file.created",
			Target:    "wp-content/plugins/shop/readme.txt",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-content/plugins/shop/readme.txt", "sha256": "plugin-readme"},
		},
		{
			ID:        "evt-plugin-admin",
			EventTime: now.Add(2 * time.Minute),
			EventType: "file.created",
			Target:    "wp-content/plugins/shop/includes/admin.php",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "wp-content/plugins/shop/includes/admin.php", "sha256": "plugin-admin"},
		},
	}, 30*time.Minute)

	if len(chains) != 1 {
		t.Fatalf("chains = %#v, want one grouped plugin finding", chains)
	}
	chain := chains[0]
	if chain.RuleID != "file-plugin-theme-module-changed" || len(chain.Events) != 3 {
		t.Fatalf("chain = %#v, want one plugin chain with three events", chain)
	}
	if !strings.Contains(chain.Title, "shop") || !strings.Contains(chain.Summary, "3 created file(s)") {
		t.Fatalf("chain title/summary = %q / %q, want grouped plugin context", chain.Title, chain.Summary)
	}
	files, ok := chain.Metadata["files"].([]string)
	if !ok || len(files) != 3 || files[0] != "wp-content/plugins/shop/shop.php" {
		t.Fatalf("files metadata = %#v, want changed file list", chain.Metadata["files"])
	}
}

func TestCorrelateEventsIgnoresRoutineDatabaseChecksAfterFileChange(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 20, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-file",
			EventTime: now,
			EventType: "file.deleted",
			Target:    "modules/netreviews/logs/logs.txt",
			Severity:  domain.SeverityLow,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "modules/netreviews/logs/logs.txt"},
		},
		{
			ID:        "evt-db-check",
			EventTime: now.Add(time.Minute),
			EventType: "db.snapshot.check",
			Target:    "prestashop:ps_module:modules",
			Severity:  domain.SeverityInfo,
			HostSlug:  "web-01",
			Message:   "Database check prestashop.modules.count observed count 99",
		},
	}, 30*time.Minute)

	for _, chain := range chains {
		if chain.RuleID == "file-change-to-db-security-change" {
			t.Fatalf("chains = %#v, routine database check should not be a security tail", chains)
		}
	}
}

func TestCorrelateEventsTreatsDatabaseDiffsAsSecurityTails(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 25, 0, 0, time.UTC)
	chains := correlateTimelineEvents([]domain.TimelineEvent{
		{
			ID:        "evt-file",
			EventTime: now,
			EventType: "file.modified",
			Target:    "modules/payment/payment.php",
			Severity:  domain.SeverityLow,
			HostSlug:  "web-01",
			Payload:   map[string]any{"relative_path": "modules/payment/payment.php"},
		},
		{
			ID:        "evt-db-change",
			EventTime: now.Add(time.Minute),
			EventType: "db.snapshot.check_changed",
			Target:    "prestashop:ps_module:payment",
			Severity:  domain.SeverityMedium,
			HostSlug:  "web-01",
			Message:   "Database check prestashop.modules.enabled changed",
		},
	}, 30*time.Minute)

	for _, chain := range chains {
		if chain.RuleID == "file-change-to-db-security-change" {
			return
		}
	}
	t.Fatalf("chains = %#v, want database diff linked as a security tail", chains)
}

func TestCorrelateEventsBuildsAdminRequestAnomalyChains(t *testing.T) {
	now := time.Date(2026, 5, 12, 13, 30, 0, 0, time.UTC)
	events := []domain.TimelineEvent{
		adminAccessEvent("evt-admin-fail-1", now, "GET", "/wp-admin/", 403, "203.0.113.10"),
		adminAccessEvent("evt-admin-fail-2", now.Add(time.Minute), "GET", "/wp-admin/", 403, "203.0.113.10"),
		adminAccessEvent("evt-admin-fail-3", now.Add(2*time.Minute), "GET", "/wp-admin/", 403, "203.0.113.10"),
		adminAccessEvent("evt-admin-success", now.Add(3*time.Minute), "POST", "/wp-login.php?redirect_to=/wp-admin/&token=abc", 302, "203.0.113.10"),
		adminAccessEvent("evt-login-post-1", now.Add(10*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		adminAccessEvent("evt-login-post-2", now.Add(11*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		adminAccessEvent("evt-login-post-3", now.Add(12*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		adminAccessEvent("evt-login-post-4", now.Add(13*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		adminAccessEvent("evt-login-post-5", now.Add(14*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		adminAccessEvent("evt-tool-probe", now.Add(20*time.Minute), "GET", "/phpmyadmin/index.php", 404, "203.0.113.30"),
		adminAccessEvent("evt-admin-ajax", now.Add(21*time.Minute), "POST", "/wp-admin/admin-ajax.php", 200, "203.0.113.40"),
		adminAccessEvent("evt-unknown-fail-1", now.Add(22*time.Minute), "GET", "/wp-admin/", 403, ""),
		adminAccessEvent("evt-unknown-fail-2", now.Add(23*time.Minute), "GET", "/wp-admin/", 403, ""),
		adminAccessEvent("evt-unknown-fail-3", now.Add(24*time.Minute), "GET", "/wp-admin/", 403, ""),
		adminAccessEvent("evt-unknown-success", now.Add(25*time.Minute), "POST", "/wp-login.php", 302, ""),
	}

	chains := correlateTimelineEvents(events, 30*time.Minute)
	byRule := map[string]CorrelationChain{}
	for _, chain := range chains {
		byRule[chain.RuleID] = chain
	}
	for _, ruleID := range []string{
		"web-admin-success-after-failures",
		"web-admin-login-post-burst",
		"web-admin-tool-probe",
	} {
		if _, ok := byRule[ruleID]; !ok {
			t.Fatalf("chains = %#v, missing %s", chains, ruleID)
		}
	}
	if _, ok := byRule["web-admin-failed-request-burst"]; ok {
		t.Fatalf("chains = %#v, failure burst should be suppressed by success-after-failures", chains)
	}
	if len(chains) != 3 {
		t.Fatalf("chains = %#v, want three admin request anomaly findings", chains)
	}
	if byRule["web-admin-success-after-failures"].Severity != domain.SeverityHigh ||
		byRule["web-admin-success-after-failures"].Confidence != domain.ConfidenceMedium {
		t.Fatalf("success chain = %#v, want high/medium", byRule["web-admin-success-after-failures"])
	}
	if len(byRule["web-admin-login-post-burst"].Events) != 5 {
		t.Fatalf("login post burst = %#v, want five events", byRule["web-admin-login-post-burst"])
	}
	for _, event := range byRule["web-admin-success-after-failures"].Events {
		if strings.Contains(event.Target, "?") {
			t.Fatalf("success chain event target = %q, want query string redacted", event.Target)
		}
	}
}

func TestCorrelateEventsBuildsTrafficAndTorWebRequestChains(t *testing.T) {
	now := time.Date(2026, 5, 12, 14, 30, 0, 0, time.UTC)
	var events []domain.TimelineEvent
	for index := range 20 {
		events = append(events, accessEvent(fmt.Sprintf("evt-volume-%02d", index), now.Add(time.Duration(index)*10*time.Second), "GET", "/catalog?page=1", 200, "198.51.100.10", nil))
	}
	for index := range 6 {
		events = append(events, accessEvent(fmt.Sprintf("evt-error-%02d", index), now.Add(time.Minute+time.Duration(index)*10*time.Second), "GET", "/checkout", 500, fmt.Sprintf("198.51.100.%d", 20+index), nil))
	}
	for index := range 10 {
		events = append(events, accessEvent(fmt.Sprintf("evt-admin-post-%02d", index), now.Add(2*time.Minute+time.Duration(index)*10*time.Second), "POST", "/wp-login.php", 200, fmt.Sprintf("203.0.113.%d", 10+index), nil))
	}
	events = append(events,
		accessEvent("evt-tor-admin", now.Add(4*time.Minute), "GET", "/wp-admin/", 403, "203.0.113.200", map[string]any{"remote_is_tor": true}),
		accessEvent("evt-tor-public", now.Add(5*time.Minute), "GET", "/", 200, "203.0.113.201", map[string]any{"remote_network": "tor_exit"}),
	)

	chains := correlateTimelineEvents(events, 30*time.Minute)
	byRule := map[string]CorrelationChain{}
	for _, chain := range chains {
		byRule[chain.RuleID] = chain
	}
	for _, ruleID := range []string{
		"web-request-volume-spike",
		"web-error-rate-spike",
		"web-admin-post-volume-spike",
		"web-tor-admin-request",
		"web-tor-request-observed",
	} {
		if _, ok := byRule[ruleID]; !ok {
			t.Fatalf("chains = %#v, missing %s", chains, ruleID)
		}
	}
	if len(chains) != 5 {
		t.Fatalf("chains = %#v, want five web request traffic findings", chains)
	}
	if byRule["web-error-rate-spike"].Confidence != domain.ConfidenceHigh ||
		byRule["web-tor-admin-request"].Severity != domain.SeverityMedium {
		t.Fatalf("chains = %#v, want high-confidence errors and medium tor admin finding", chains)
	}
	if len(byRule["web-request-volume-spike"].Events) != 20 {
		t.Fatalf("volume spike = %#v, want 20 events", byRule["web-request-volume-spike"])
	}
}

func TestCorrelateEventsIgnoresAegrailCrawlerTraffic(t *testing.T) {
	now := time.Date(2026, 5, 17, 15, 0, 0, 0, time.UTC)
	var events []domain.TimelineEvent
	for index := range 25 {
		events = append(events, accessEvent(
			fmt.Sprintf("evt-self-%02d", index),
			now.Add(time.Duration(index)*10*time.Second),
			"GET",
			"/",
			403,
			"172.18.0.1",
			map[string]any{"user_agent": "AegrailBot/0.1 (+https://aegrail.com/monitoring; Aegrail bot)"},
		))
	}

	chains := correlateTimelineEvents(events, 30*time.Minute)
	for _, chain := range chains {
		if chain.RuleID == "web-request-volume-spike" {
			t.Fatalf("chains = %#v, want no self-monitoring volume spike", chains)
		}
	}
}

func TestCorrelateEventsIgnoresPrivateRemoteVolumeSpike(t *testing.T) {
	now := time.Date(2026, 5, 17, 15, 0, 0, 0, time.UTC)
	var events []domain.TimelineEvent
	for index := range 25 {
		events = append(events, accessEvent(
			fmt.Sprintf("evt-private-%02d", index),
			now.Add(time.Duration(index)*10*time.Second),
			"GET",
			"/",
			403,
			"172.18.0.1",
			map[string]any{"user_agent": "Mozilla/5.0 fallback browser"},
		))
	}

	chains := correlateTimelineEvents(events, 30*time.Minute)
	for _, chain := range chains {
		if chain.RuleID == "web-request-volume-spike" {
			t.Fatalf("chains = %#v, want no private-remote volume spike", chains)
		}
	}
}

func TestListTimelineEventsResolvesEnvironmentAndOptionalApp(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	ingest := &memoryIngestRepository{}
	hub := New(Dependencies{Inventory: inventory, Ingest: ingest})
	ctx := context.Background()

	environment, app, host, agent := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	ingest.timelineEvents = []domain.TimelineEvent{
		{
			ID:              "evt-old",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        host.Slug,
			AgentID:         agent.ID,
			AgentExternalID: agent.AgentID,
			EventTime:       now.Add(-2 * time.Hour),
			EventType:       "file.modified",
		},
		{
			ID:              "evt-current",
			EnvironmentID:   environment.ID,
			AppID:           app.ID,
			HostID:          host.ID,
			HostSlug:        host.Slug,
			AgentID:         agent.ID,
			AgentExternalID: agent.AgentID,
			EventTime:       now,
			EventType:       "db.entity.changed",
		},
	}

	events, err := hub.ListTimelineEvents(ctx, ListTimelineEventsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("ListTimelineEvents returned error: %v", err)
	}
	if len(events) != 1 || events[0].ID != "evt-current" {
		t.Fatalf("events = %#v, want current app event", events)
	}
}

type memoryHubFindingRepository struct {
	byKey map[string]domain.HubFinding
}

func newMemoryHubFindingRepository() *memoryHubFindingRepository {
	return &memoryHubFindingRepository{byKey: map[string]domain.HubFinding{}}
}

func (r *memoryHubFindingRepository) SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error) {
	saved := make([]domain.HubFinding, 0, len(findings))
	now := time.Now().UTC()
	for _, finding := range findings {
		key := string(finding.EnvironmentID) + ":" + finding.RuleID + ":" + finding.DedupeKey
		existing, ok := r.byKey[key]
		if ok {
			if memoryHubFindingContentEqual(existing, finding) {
				saved = append(saved, existing)
				continue
			}
			finding.ID = existing.ID
			finding.CreatedAt = existing.CreatedAt
			finding.Status = existing.Status
			finding.StatusReason = existing.StatusReason
			finding.StatusNote = existing.StatusNote
			finding.StatusActor = existing.StatusActor
			finding.StatusUpdatedAt = existing.StatusUpdatedAt
		} else {
			finding.ID = domain.ID(fmt.Sprintf("finding-%d", len(r.byKey)+1))
			finding.CreatedAt = now
			finding.Status = "open"
			finding.StatusUpdatedAt = now
		}
		finding.UpdatedAt = now
		r.byKey[key] = finding
		saved = append(saved, finding)
	}
	return saved, nil
}

func memoryHubFindingContentEqual(existing domain.HubFinding, incoming domain.HubFinding) bool {
	return existing.RuleVersion == incoming.RuleVersion &&
		existing.Severity == incoming.Severity &&
		existing.Confidence == incoming.Confidence &&
		existing.Title == incoming.Title &&
		existing.Summary == incoming.Summary &&
		existing.Description == incoming.Description &&
		existing.FirstEventAt.Equal(incoming.FirstEventAt) &&
		existing.LastEventAt.Equal(incoming.LastEventAt) &&
		reflect.DeepEqual(existing.EventIDs, incoming.EventIDs) &&
		reflect.DeepEqual(existing.Metadata, incoming.Metadata)
}

func (r *memoryHubFindingRepository) ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error) {
	var findings []domain.HubFinding
	for _, finding := range r.byKey {
		if finding.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && finding.AppID != appID {
			continue
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (r *memoryHubFindingRepository) GetHubFinding(ctx context.Context, findingID domain.ID, environmentID domain.ID, appID domain.ID) (domain.HubFinding, error) {
	for _, finding := range r.byKey {
		if finding.ID != findingID || finding.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && finding.AppID != appID {
			continue
		}
		return finding, nil
	}
	return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
}

func adminAccessEvent(id string, eventTime time.Time, method string, path string, status int, remoteAddr string) domain.TimelineEvent {
	return accessEvent(id, eventTime, method, path, status, remoteAddr, nil)
}

func accessEvent(id string, eventTime time.Time, method string, path string, status int, remoteAddr string, extraPayload map[string]any) domain.TimelineEvent {
	payload := map[string]any{
		"method":      method,
		"path":        path,
		"status_code": status,
		"remote_addr": remoteAddr,
	}
	for key, value := range extraPayload {
		payload[key] = value
	}
	return domain.TimelineEvent{
		ID:        domain.ID(id),
		HostSlug:  "web-01",
		EventTime: eventTime,
		EventType: "log.access",
		Target:    "access.log",
		Severity:  domain.SeverityInfo,
		Message:   fmt.Sprintf("HTTP %d %s %s", status, method, path),
		Payload:   payload,
	}
}

func (r *memoryHubFindingRepository) UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error) {
	now := time.Now().UTC()
	for key, finding := range r.byKey {
		if finding.ID != findingID || finding.EnvironmentID != environmentID {
			continue
		}
		finding.Status = update.Status
		finding.StatusReason = update.Reason
		finding.StatusNote = update.Note
		finding.StatusActor = update.Actor
		finding.StatusUpdatedAt = now
		finding.UpdatedAt = now
		r.byKey[key] = finding
		return finding, nil
	}
	return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
}

func (r *memoryHubFindingRepository) UpdateOpenHubFindingStatuses(ctx context.Context, environmentID domain.ID, appID domain.ID, update domain.HubFindingStatusUpdate) (int, error) {
	now := time.Now().UTC()
	updated := 0
	for key, finding := range r.byKey {
		if finding.EnvironmentID != environmentID || finding.Status != "open" {
			continue
		}
		if appID != "" && finding.AppID != appID {
			continue
		}
		finding.Status = update.Status
		finding.StatusReason = update.Reason
		finding.StatusNote = update.Note
		finding.StatusActor = update.Actor
		finding.StatusUpdatedAt = now
		finding.UpdatedAt = now
		r.byKey[key] = finding
		updated++
	}
	return updated, nil
}
