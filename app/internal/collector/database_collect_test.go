package collector

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeDatabaseDSNConvertsMySQLURL(t *testing.T) {
	dsn, err := normalizeDatabaseDSN("mysql", "mysql://user:pass@127.0.0.1:3306/site_db?charset=utf8mb4")
	if err != nil {
		t.Fatalf("normalizeDatabaseDSN returned error: %v", err)
	}
	if !strings.Contains(dsn, "user:pass@tcp(127.0.0.1:3306)/site_db") {
		t.Fatalf("dsn = %q, want formatted tcp DSN", dsn)
	}
	if !strings.Contains(dsn, "parseTime=true") || !strings.Contains(dsn, "charset=utf8mb4") {
		t.Fatalf("dsn = %q, want query params preserved", dsn)
	}
}

func TestCollectDatabaseSnapshotUnsupportedEngineReturnsWarning(t *testing.T) {
	runtime := NewRuntime(Config{Name: "database"})
	result, err := runtime.CollectDatabaseSnapshot(context.Background(), DatabaseCollectInput{
		Name:    "main",
		Engine:  "postgres",
		Profile: "wordpress",
		DSN:     "postgres://example",
	})
	if err != nil {
		t.Fatalf("CollectDatabaseSnapshot returned error: %v", err)
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("warnings = %#v, want unsupported engine warning", result.Warnings)
	}
	if len(result.Checks) != 0 {
		t.Fatalf("checks = %d, want no checks for unsupported engine", len(result.Checks))
	}
}

func TestNormalizeDatabaseProfileTreatsWordPressNetworkAsWordPress(t *testing.T) {
	for _, profile := range []string{"wp", "wordpress", "wordpress-multisite", "woocommerce"} {
		if got := normalizeDatabaseProfile(profile); got != "wordpress" {
			t.Fatalf("normalizeDatabaseProfile(%q) = %q, want wordpress", profile, got)
		}
	}
}

func TestBuildDatabaseSnapshotEventsRedactsDigestValues(t *testing.T) {
	result := DatabaseCollectResult{
		Name:    "main",
		Engine:  "mysql",
		Profile: "wordpress",
		Checks: []DatabaseCheckResult{
			{
				Name:        "wordpress.active_plugins.digest",
				Status:      "ok",
				Metric:      "active_plugins",
				Table:       "wp_options",
				OptionName:  "active_plugins",
				ValueSHA256: "abc123",
				ValueBytes:  42,
			},
		},
	}
	events := BuildDatabaseSnapshotEvents(result, map[string]string{"site_slug": "example-com"})
	if len(events) != 2 {
		t.Fatalf("events = %d, want completed and check events", len(events))
	}
	check := events[1]
	if check.Type != "db.snapshot.check" || check.Payload["value_sha256"] != "abc123" {
		t.Fatalf("check event = %#v, want digest payload", check)
	}
	if _, ok := check.Payload["value"]; ok {
		t.Fatalf("payload leaked raw value: %#v", check.Payload)
	}
	if check.Labels["collector"] != "database" || check.Labels["site_slug"] != "example-com" {
		t.Fatalf("labels = %#v, want database and site context", check.Labels)
	}
}

func TestWordPressUserEntityIncludesIdentityAndUsesKeyedFingerprint(t *testing.T) {
	entity := wordpressUserEntity(42, "roman", "roman@gmail.com", `a:1:{s:13:"administrator";b:1;}`, newDatabasePIIProtector("local-test-key"))
	if entity.Label != "wordpress_user:roman@gmail.com" || !entity.Privileged {
		t.Fatalf("entity = %#v, want privileged user label with full email", entity)
	}
	if entity.Attributes["account_display"] != "roman@gmail.com" ||
		entity.Attributes["email"] != "roman@gmail.com" ||
		entity.Attributes["login"] != "roman" ||
		entity.Attributes["email_masked"] != "r***n@gmail.com" ||
		entity.Attributes["login_masked"] != "r***n" {
		t.Fatalf("attributes = %#v, want full identity hints plus masked compatibility fields", entity.Attributes)
	}
	if _, ok := entity.Attributes["email_sha256"]; ok {
		t.Fatalf("attributes leaked plain email sha256 field: %#v", entity.Attributes)
	}
	if _, ok := entity.Attributes["login_sha256"]; ok {
		t.Fatalf("attributes leaked plain login sha256 field: %#v", entity.Attributes)
	}
	emailHMAC, ok := entity.Attributes["email_hmac_sha256"].(string)
	if !ok || emailHMAC == "" || emailHMAC == databaseSHA256Hex("roman@gmail.com") {
		t.Fatalf("email_hmac_sha256 = %#v, want keyed fingerprint distinct from plain sha256", entity.Attributes["email_hmac_sha256"])
	}
	loginHMAC, ok := entity.Attributes["login_hmac_sha256"].(string)
	if !ok || loginHMAC == "" || loginHMAC == databaseSHA256Hex("roman") {
		t.Fatalf("login_hmac_sha256 = %#v, want keyed fingerprint distinct from plain sha256", entity.Attributes["login_hmac_sha256"])
	}
}

func TestWordPressNetworkSuperAdminUserIsPrivileged(t *testing.T) {
	entity := wordpressUserEntityWithAccess(9, "network-owner", "owner@example.com", "", true, newDatabasePIIProtector("local-test-key"))
	if !entity.Privileged {
		t.Fatalf("entity = %#v, want network super admin privileged", entity)
	}
	if entity.Attributes["administrator"] != false || entity.Attributes["network_super_admin"] != true {
		t.Fatalf("attributes = %#v, want network super admin without site administrator capability", entity.Attributes)
	}
	if entity.Attributes["capabilities_sha256"] != databaseSHA256Hex("") || entity.Attributes["has_capabilities"] != false {
		t.Fatalf("attributes = %#v, want empty capability state still tracked", entity.Attributes)
	}
}

func TestParseWordPressSiteAdminsFromSerializedNetworkOption(t *testing.T) {
	admins := parseWordPressSiteAdmins(`a:3:{i:0;s:5:"Admin";i:1;s:13:"network-owner";i:2;s:5:"admin";}`)
	if got, want := strings.Join(admins, ","), "admin,network-owner"; got != want {
		t.Fatalf("admins = %#v, want %s", admins, want)
	}
}

func TestWordPressAdminUsersCheckMatchesNetworkCapabilityKeys(t *testing.T) {
	specs, warnings := wordpressDatabaseCheckSpecs("wp_")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	var adminSpec databaseCheckSpec
	for _, spec := range specs {
		if spec.Name == "wordpress.admin_users.count" {
			adminSpec = spec
			break
		}
	}
	if adminSpec.Query == "" {
		t.Fatal("wordpress.admin_users.count spec not found")
	}
	if !strings.Contains(adminSpec.Query, "COUNT(DISTINCT user_id)") || !strings.Contains(adminSpec.Query, "REGEXP") {
		t.Fatalf("query = %q, want distinct users across multisite capability keys", adminSpec.Query)
	}
	if got, want := adminSpec.Args[0], "^wp_([0-9]+_)?capabilities$"; got != want {
		t.Fatalf("regexp arg = %#v, want %q", got, want)
	}
}

func TestPrestaShopEmployeeEntityIncludesIdentityAndUsesKeyedFingerprint(t *testing.T) {
	entity := prestashopEmployeeEntity(7, "owner@example.com", true, 1, newDatabasePIIProtector("local-test-key"))
	if entity.Label != "prestashop_employee:owner@example.com" || !entity.Privileged {
		t.Fatalf("entity = %#v, want privileged employee label with full email", entity)
	}
	if entity.Attributes["account_display"] != "owner@example.com" ||
		entity.Attributes["email"] != "owner@example.com" ||
		entity.Attributes["email_masked"] != "o***r@example.com" {
		t.Fatalf("attributes = %#v, want full employee email plus masked compatibility field", entity.Attributes)
	}
	if _, ok := entity.Attributes["email_sha256"]; ok {
		t.Fatalf("attributes leaked plain email sha256 field: %#v", entity.Attributes)
	}
	if fingerprint, ok := entity.Attributes["email_hmac_sha256"].(string); !ok || fingerprint == "" {
		t.Fatalf("email_hmac_sha256 = %#v, want keyed fingerprint", entity.Attributes["email_hmac_sha256"])
	}
}

func TestParseWordPressActivePluginsFromSerializedOption(t *testing.T) {
	value := `a:2:{i:0;s:19:"akismet/akismet.php";i:1;s:27:"woocommerce/woocommerce.php";}`
	plugins := parseWordPressActivePlugins(value)
	if got, want := len(plugins), 2; got != want {
		t.Fatalf("plugins = %#v, want %d", plugins, want)
	}
	if plugins[0] != "akismet/akismet.php" || plugins[1] != "woocommerce/woocommerce.php" {
		t.Fatalf("plugins = %#v, want normalized plugin files", plugins)
	}
}

func TestWordPressOptionEntitiesIncludeDerivedPluginAndTheme(t *testing.T) {
	pluginEntities := wordpressEntitiesFromOption("site", "active_plugins", `a:1:{i:0;s:19:"akismet/akismet.php";}`)
	if len(pluginEntities) != 2 {
		t.Fatalf("plugin entities = %#v, want option plus plugin", pluginEntities)
	}
	if pluginEntities[0].Type != "wordpress_option" || !pluginEntities[0].Privileged {
		t.Fatalf("option entity = %#v, want privileged redacted option", pluginEntities[0])
	}
	if _, ok := pluginEntities[0].Attributes["value"]; ok {
		t.Fatalf("option entity leaked raw value: %#v", pluginEntities[0].Attributes)
	}
	plugin := pluginEntities[1]
	if plugin.Type != "wordpress_plugin" || plugin.Label != "akismet/akismet.php" || plugin.Attributes["plugin_slug"] != "akismet" {
		t.Fatalf("plugin entity = %#v, want derived plugin identity", plugin)
	}

	themeEntities := wordpressEntitiesFromOption("site", "stylesheet", "twentytwentysix")
	if len(themeEntities) != 2 {
		t.Fatalf("theme entities = %#v, want option plus theme", themeEntities)
	}
	if themeEntities[1].Type != "wordpress_theme" || themeEntities[1].Attributes["theme_slug"] != "twentytwentysix" {
		t.Fatalf("theme entity = %#v, want active theme identity", themeEntities[1])
	}
}

func TestWordPressOptionEntitiesIncludeCronHooks(t *testing.T) {
	cron := `a:1:{i:1715540000;a:2:{s:16:"wp_version_check";a:1:{s:32:"0123456789abcdef0123456789abcdef";a:3:{s:8:"schedule";s:10:"twicedaily";s:4:"args";a:0:{}s:8:"interval";i:43200;}}s:15:"evil_shell_exec";a:1:{s:32:"abcdefabcdefabcdefabcdefabcdefab";a:3:{s:8:"schedule";s:6:"hourly";s:4:"args";a:0:{}s:8:"interval";i:3600;}}}}`
	entities := wordpressEntitiesFromOption("site", "cron", cron)
	var hooks []DatabaseEntityObservation
	for _, entity := range entities {
		if entity.Type == "wordpress_cron" {
			hooks = append(hooks, entity)
		}
	}
	if len(hooks) != 2 {
		t.Fatalf("hooks = %#v, want two cron hook entities", hooks)
	}
	if hooks[0].Label != "evil_shell_exec" || !hooks[0].Privileged || hooks[0].Attributes["suspicious"] != true {
		t.Fatalf("first hook = %#v, want suspicious evil_shell_exec", hooks[0])
	}
	if hooks[1].Label != "wp_version_check" || hooks[1].Privileged {
		t.Fatalf("second hook = %#v, want normal wp_version_check", hooks[1])
	}
}

func TestWordPressScriptContentEntityRedactsContentAndExtractsIndicators(t *testing.T) {
	entity := wordpressScriptContentEntity("post_content", "42", "post:page:hash", `<p>Hello</p><script src="https://evil.example/skimmer.js"></script><img src=x onerror="eval(atob('x'))">`, map[string]any{
		"post_type": "page",
	})
	if entity.Type != "wordpress_content_script" || entity.Label != "post:page:hash" {
		t.Fatalf("entity = %#v, want script content entity", entity)
	}
	if _, ok := entity.Attributes["content"]; ok {
		t.Fatalf("entity leaked raw content: %#v", entity.Attributes)
	}
	if entity.Attributes["content_sha256"] == "" || entity.Attributes["post_type"] != "page" {
		t.Fatalf("attributes = %#v, want redacted content metadata", entity.Attributes)
	}
	domains, ok := entity.Attributes["external_domains"].([]string)
	if !ok || len(domains) != 1 || domains[0] != "evil.example" {
		t.Fatalf("domains = %#v, want evil.example", entity.Attributes["external_domains"])
	}
	indicators, ok := entity.Attributes["indicators"].([]string)
	if !ok || len(indicators) < 3 {
		t.Fatalf("indicators = %#v, want multiple script indicators", entity.Attributes["indicators"])
	}
}

func TestPrestaShopConfigurationEntityRedactsValueAndClassifiesRisk(t *testing.T) {
	entity, ok := prestashopConfigurationEntity("PS_MODE_DEV", "1")
	if !ok {
		t.Fatal("prestashopConfigurationEntity returned ok=false")
	}
	if entity.Type != "prestashop_configuration" || entity.Label != "PS_MODE_DEV" || !entity.Privileged {
		t.Fatalf("entity = %#v, want privileged PrestaShop configuration entity", entity)
	}
	if _, ok := entity.Attributes["value"]; ok {
		t.Fatalf("entity leaked raw config value: %#v", entity.Attributes)
	}
	if entity.Attributes["category"] != "debug" || entity.Attributes["value_bool"] != true || entity.Attributes["suspicious"] != true {
		t.Fatalf("attributes = %#v, want suspicious debug config", entity.Attributes)
	}
	reasons, ok := entity.Attributes["suspicious_reason"].([]string)
	if !ok || len(reasons) != 1 || reasons[0] != "debug mode enabled" {
		t.Fatalf("reasons = %#v, want debug mode reason", entity.Attributes["suspicious_reason"])
	}
}

func TestPrestaShopConfigurationEntityClassifiesPaymentSecrets(t *testing.T) {
	entity, ok := prestashopConfigurationEntity("PS_CHECKOUT_CLIENT_SECRET", "super-secret")
	if !ok {
		t.Fatal("prestashopConfigurationEntity returned ok=false")
	}
	if entity.Attributes["category"] != "payment" || entity.Attributes["sensitive"] != true || entity.Attributes["suspicious"] != true {
		t.Fatalf("attributes = %#v, want sensitive payment config", entity.Attributes)
	}
	if _, ok := entity.Attributes["value"]; ok {
		t.Fatalf("entity leaked raw payment secret: %#v", entity.Attributes)
	}
}

func TestPrestaShopConfigurationEntityClassifiesCommonModuleConfigs(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		category string
	}{
		{name: "MOLLIE_API_KEY", value: "test_x", category: "payment"},
		{name: "PAYPLUG_SECRET_KEY", value: "sk_live_x", category: "payment"},
		{name: "ADYEN_MERCHANT_ACCOUNT", value: "merchant", category: "payment"},
		{name: "MAILCHIMP_API_KEY", value: "mail-x", category: "mail"},
		{name: "BREVO_API_KEY", value: "brevo-x", category: "mail"},
	}
	for _, tc := range cases {
		entity, ok := prestashopConfigurationEntity(tc.name, tc.value)
		if !ok {
			t.Fatalf("%s returned ok=false", tc.name)
		}
		if entity.Attributes["category"] != tc.category {
			t.Fatalf("%s category = %#v, want %s", tc.name, entity.Attributes["category"], tc.category)
		}
		if _, ok := entity.Attributes["value"]; ok {
			t.Fatalf("%s leaked raw value: %#v", tc.name, entity.Attributes)
		}
	}
}
