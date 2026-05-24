package collector

import (
	"context"
	"strings"
	"testing"
	"time"
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

func TestNormalizeDatabaseDSNAcceptsPostgresURLAndPDOStyleDSN(t *testing.T) {
	urlDSN, err := normalizeDatabaseDSN("postgres", "postgres://user:pass@127.0.0.1:5432/site_db?sslmode=disable")
	if err != nil {
		t.Fatalf("normalizeDatabaseDSN postgres URL returned error: %v", err)
	}
	if urlDSN != "postgres://user:pass@127.0.0.1:5432/site_db?sslmode=disable" {
		t.Fatalf("url dsn = %q", urlDSN)
	}

	pdoDSN, err := normalizeDatabaseDSN("postgres", "pgsql:host=127.0.0.1;port=5432;dbname=site_db;user=user;password=pass;sslmode=disable")
	if err != nil {
		t.Fatalf("normalizeDatabaseDSN pgsql returned error: %v", err)
	}
	if !strings.Contains(pdoDSN, "postgres://user:pass@127.0.0.1:5432/site_db") || !strings.Contains(pdoDSN, "sslmode=disable") {
		t.Fatalf("pdo dsn = %q, want postgres URL", pdoDSN)
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

func TestDatabaseConnectionReusesPersistentHandle(t *testing.T) {
	runtime := NewRuntime(Config{Name: "database"})
	defer runtime.Close()

	dsn := "user:pass@tcp(127.0.0.1:3306)/site_db?parseTime=true"
	first, releaseFirst, err := runtime.databaseConnection("mysql", dsn, true)
	if err != nil {
		t.Fatalf("databaseConnection first returned error: %v", err)
	}
	defer releaseFirst()
	second, releaseSecond, err := runtime.databaseConnection("mysql", dsn, true)
	if err != nil {
		t.Fatalf("databaseConnection second returned error: %v", err)
	}
	defer releaseSecond()
	if first != second {
		t.Fatalf("persistent databaseConnection returned different handles")
	}
}

func TestDatabaseConnectionCanUseOneShotHandle(t *testing.T) {
	runtime := NewRuntime(Config{Name: "database"})
	defer runtime.Close()

	dsn := "user:pass@tcp(127.0.0.1:3306)/site_db?parseTime=true"
	first, releaseFirst, err := runtime.databaseConnection("mysql", dsn, false)
	if err != nil {
		t.Fatalf("databaseConnection first returned error: %v", err)
	}
	defer releaseFirst()
	second, releaseSecond, err := runtime.databaseConnection("mysql", dsn, false)
	if err != nil {
		t.Fatalf("databaseConnection second returned error: %v", err)
	}
	defer releaseSecond()
	if first == second {
		t.Fatalf("one-shot databaseConnection reused a handle")
	}
}

func TestNormalizeDatabaseProfileTreatsWordPressNetworkAsWordPress(t *testing.T) {
	for _, profile := range []string{"wp", "wordpress", "wordpress-multisite", "woocommerce"} {
		if got := normalizeDatabaseProfile(profile); got != "wordpress" {
			t.Fatalf("normalizeDatabaseProfile(%q) = %q, want wordpress", profile, got)
		}
	}
}

func TestNormalizeDatabaseProfileTreatsYii2RBACAliases(t *testing.T) {
	for _, profile := range []string{"yii2-rbac", "yii2_rbac"} {
		if got := normalizeDatabaseProfile(profile); got != "yii2-rbac" {
			t.Fatalf("normalizeDatabaseProfile(%q) = %q, want yii2-rbac", profile, got)
		}
	}
}

func TestNormalizeDatabaseProfileTreatsLaravelAsCanonical(t *testing.T) {
	for _, profile := range []string{"laravel"} {
		if got := normalizeDatabaseProfile(profile); got != "laravel" {
			t.Fatalf("normalizeDatabaseProfile(%q) = %q, want laravel", profile, got)
		}
	}
}

func TestYii2RBACUserEntityIncludesRolesAndKeyedFingerprint(t *testing.T) {
	createdAt := time.Unix(1715900000, 0).UTC()
	entity := yii2RBACUserEntity("42", "", "owner@example.com", "10", []string{"admin", "admin"}, createdAt, createdAt, newDatabasePIIProtector("local-test-key"))
	if entity.Type != "yii2_rbac_user" || entity.Label != "yii2_rbac_user:owner@example.com" || !entity.Privileged {
		t.Fatalf("entity = %#v, want privileged Yii2 RBAC user", entity)
	}
	if entity.Attributes["account_display"] != "owner@example.com" ||
		entity.Attributes["email"] != "owner@example.com" ||
		entity.Attributes["email_masked"] != "o***r@example.com" ||
		entity.Attributes["active"] != true ||
		entity.Attributes["role_count"] != 1 ||
		entity.Attributes["admin_role"] != true {
		t.Fatalf("attributes = %#v, want full account details and admin role metadata", entity.Attributes)
	}
	if fingerprint, ok := entity.Attributes["email_hmac_sha256"].(string); !ok || fingerprint == "" {
		t.Fatalf("email_hmac_sha256 = %#v, want keyed fingerprint", entity.Attributes["email_hmac_sha256"])
	}
}

func TestLaravelUserEntityIncludesRolesAndKeyedFingerprint(t *testing.T) {
	createdAt := time.Unix(1715900000, 0).UTC()
	entity := laravelUserEntity("42", "Owner", "owner@example.com", "1", "2026-05-17 01:00:00", "2026-05-17 02:00:00", "192.0.2.10", []string{"admin", "admin"}, createdAt, createdAt, newDatabasePIIProtector("local-test-key"))
	if entity.Type != "laravel_user" || entity.Label != "laravel_user:owner@example.com" || !entity.Privileged {
		t.Fatalf("entity = %#v, want privileged Laravel user", entity)
	}
	if entity.Attributes["account_display"] != "owner@example.com" ||
		entity.Attributes["email"] != "owner@example.com" ||
		entity.Attributes["email_masked"] != "o***r@example.com" ||
		entity.Attributes["active"] != true ||
		entity.Attributes["email_verified"] != true ||
		entity.Attributes["role_count"] != 1 ||
		entity.Attributes["admin_role"] != true {
		t.Fatalf("attributes = %#v, want full account details and admin role metadata", entity.Attributes)
	}
	if fingerprint, ok := entity.Attributes["email_hmac_sha256"].(string); !ok || fingerprint == "" {
		t.Fatalf("email_hmac_sha256 = %#v, want keyed fingerprint", entity.Attributes["email_hmac_sha256"])
	}
	if _, ok := entity.Attributes["last_login_ip_sha256"].(string); !ok {
		t.Fatalf("last_login_ip_sha256 = %#v, want hashed last login IP", entity.Attributes["last_login_ip_sha256"])
	}
}

func TestDatabaseSourceTimeParsesUnixSeconds(t *testing.T) {
	got := databaseSourceTime("1715900000")
	want := time.Unix(1715900000, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("databaseSourceTime unix = %s, want %s", got, want)
	}
}

func TestMauticDatabaseCheckSpecsUseUnprefixedTablesByDefault(t *testing.T) {
	specs, warnings := mauticDatabaseCheckSpecs("")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	var usersSpec databaseCheckSpec
	var oauthSpec databaseCheckSpec
	for _, spec := range specs {
		switch spec.Name {
		case "mautic.users.count":
			usersSpec = spec
		case "mautic.oauth_clients.count":
			oauthSpec = spec
		}
	}
	if usersSpec.Query == "" || !strings.Contains(usersSpec.Query, "FROM `users`") {
		t.Fatalf("users spec = %#v, want unprefixed users table", usersSpec)
	}
	if oauthSpec.Query == "" || !strings.Contains(oauthSpec.Query, "FROM `oauth2_clients`") {
		t.Fatalf("oauth spec = %#v, want oauth client table", oauthSpec)
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
	entity := wordpressUserEntityWithAccess(9, "network-owner", "owner@example.com", "", true, time.Time{}, time.Time{}, newDatabasePIIProtector("local-test-key"))
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
	entity := prestashopEmployeeEntity(7, "owner@example.com", true, 1, time.Time{}, time.Time{}, newDatabasePIIProtector("local-test-key"))
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

func TestMauticUserEntityIncludesRoleAndKeyedFingerprint(t *testing.T) {
	entity := mauticUserEntity(3, "owner", "owner@example.com", 1, "Administrators", true, true, time.Time{}, time.Time{}, newDatabasePIIProtector("local-test-key"))
	if entity.Label != "mautic_user:owner@example.com" || !entity.Privileged {
		t.Fatalf("entity = %#v, want privileged Mautic user label with full email", entity)
	}
	if entity.Attributes["account_display"] != "owner@example.com" ||
		entity.Attributes["email"] != "owner@example.com" ||
		entity.Attributes["login"] != "owner" ||
		entity.Attributes["role_name"] != "Administrators" ||
		entity.Attributes["admin_role"] != true ||
		entity.Attributes["published"] != true {
		t.Fatalf("attributes = %#v, want full identity and role details", entity.Attributes)
	}
	if fingerprint, ok := entity.Attributes["email_hmac_sha256"].(string); !ok || fingerprint == "" {
		t.Fatalf("email_hmac_sha256 = %#v, want keyed fingerprint", entity.Attributes["email_hmac_sha256"])
	}
}

func TestMauticAccessEntitiesRedactSecrets(t *testing.T) {
	integration := mauticIntegrationEntity(4, 2, "mailer", true, "email,sms", "api-key-secret", "settings", time.Time{}, time.Time{})
	if integration.Type != "mautic_integration" || !integration.Privileged {
		t.Fatalf("integration = %#v, want privileged published integration with API keys", integration)
	}
	if _, ok := integration.Attributes["api_keys"]; ok {
		t.Fatalf("integration leaked raw API keys: %#v", integration.Attributes)
	}
	if integration.Attributes["api_keys_present"] != true || integration.Attributes["api_keys_sha256"] == "" {
		t.Fatalf("integration attributes = %#v, want key hash metadata", integration.Attributes)
	}

	webhook := mauticWebhookEntity(5, "lead hook", "https://hooks.example.test/path?token=secret", "hook-secret", true, time.Time{}, time.Time{})
	if webhook.Attributes["webhook_url_host"] != "hooks.example.test" || webhook.Attributes["secret_present"] != true {
		t.Fatalf("webhook attributes = %#v, want host-only URL and secret flag", webhook.Attributes)
	}
	if _, ok := webhook.Attributes["webhook_url"]; ok {
		t.Fatalf("webhook leaked raw URL: %#v", webhook.Attributes)
	}
	if _, ok := webhook.Attributes["secret"]; ok {
		t.Fatalf("webhook leaked raw secret: %#v", webhook.Attributes)
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

func TestWordPressTrackedOptionsAreHighSignalOnly(t *testing.T) {
	siteOptions := map[string]bool{}
	for _, name := range wordpressTrackedSiteOptionNames("wp_") {
		siteOptions[name] = true
	}
	for _, name := range []string{"active_plugins", "admin_email", "default_role", "home", "siteurl", "users_can_register", "wp_user_roles"} {
		if !siteOptions[name] {
			t.Fatalf("site options = %#v, want %s tracked", siteOptions, name)
		}
	}
	for _, name := range []string{"blog_public", "cron", "permalink_structure", "stylesheet", "template"} {
		if siteOptions[name] {
			t.Fatalf("site options = %#v, want noisy option %s ignored", siteOptions, name)
		}
	}

	networkOptions := map[string]bool{}
	for _, name := range wordpressTrackedNetworkOptionNames() {
		networkOptions[name] = true
	}
	for _, name := range []string{"active_sitewide_plugins", "admin_email", "registration", "site_admins", "siteurl"} {
		if !networkOptions[name] {
			t.Fatalf("network options = %#v, want %s tracked", networkOptions, name)
		}
	}
	if networkOptions["upload_space_check_disabled"] {
		t.Fatalf("network options = %#v, want noisy upload_space_check_disabled ignored", networkOptions)
	}

	specs, warnings := wordpressDatabaseCheckSpecs("wp_")
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v", warnings)
	}
	specNames := map[string]bool{}
	for _, spec := range specs {
		specNames[spec.Name] = true
	}
	if !specNames["wordpress.active_plugins.digest"] {
		t.Fatalf("specs = %#v, want active plugin digest", specNames)
	}
	for _, name := range []string{"wordpress.options.count", "wordpress.cron.digest", "wordpress.theme_stylesheet.digest", "wordpress.theme_template.digest"} {
		if specNames[name] {
			t.Fatalf("specs = %#v, want noisy check %s ignored", specNames, name)
		}
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
