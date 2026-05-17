package collector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type DatabaseCollectInput struct {
	Name        string
	Engine      string
	DSN         string
	Profile     string
	TablePrefix string
	Timeout     time.Duration
	PIIKey      string
}

type DatabaseCollectResult struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Name       string
	Engine     string
	Profile    string
	Checks     []DatabaseCheckResult
	Entities   []DatabaseEntityObservation
	Warnings   []string
}

type DatabaseCheckResult struct {
	Name        string
	Status      string
	Metric      string
	Table       string
	OptionName  string
	Count       int64
	CountValid  bool
	ValueSHA256 string
	ValueBytes  int
	Message     string
}

type DatabaseEntityObservation struct {
	Type            string
	Key             string
	Label           string
	Privileged      bool
	SourceCreatedAt time.Time
	SourceUpdatedAt time.Time
	Attributes      map[string]any
	Signature       string
}

type databaseCheckSpec struct {
	Name       string
	Kind       string
	Metric     string
	Table      string
	OptionName string
	Query      string
	Args       []any
}

const (
	databaseCheckCount  = "count"
	databaseCheckDigest = "digest"
)

var wordpressScriptDomainPattern = regexp.MustCompile(`(?i)(?:https?:)?//([a-z0-9][a-z0-9.-]*[a-z0-9])(?::[0-9]+)?`)

func (r *Runtime) CollectDatabaseSnapshot(ctx context.Context, input DatabaseCollectInput) (DatabaseCollectResult, error) {
	startedAt := time.Now().UTC()
	result := DatabaseCollectResult{
		StartedAt: startedAt,
		Name:      strings.TrimSpace(input.Name),
		Engine:    normalizeDatabaseEngine(input.Engine),
		Profile:   normalizeDatabaseProfile(input.Profile),
		Checks:    []DatabaseCheckResult{},
		Entities:  []DatabaseEntityObservation{},
		Warnings:  []string{},
	}
	if result.Name == "" {
		result.Name = "database"
	}
	if result.Engine == "" {
		result.Engine = "mysql"
	}

	var specs []databaseCheckSpec
	if !profileUsesDynamicDatabaseSpecs(result.Profile) {
		var warnings []string
		specs, warnings = databaseCheckSpecs(result.Profile, input.TablePrefix)
		result.Warnings = append(result.Warnings, warnings...)
	}
	if !databaseProfileSupportsEngine(result.Profile, result.Engine) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("database engine %q is configured but collector support is not implemented for profile %q yet", result.Engine, result.Profile))
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	dsn, err := normalizeDatabaseDSN(result.Engine, input.DSN)
	if err != nil {
		result.Warnings = append(result.Warnings, "database DSN is invalid; check the configured dsn_env value")
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	if strings.TrimSpace(dsn) == "" {
		result.Warnings = append(result.Warnings, "database DSN is empty")
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}

	timeout := input.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, err := sql.Open(databaseSQLDriver(result.Engine), dsn)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("database connection could not be opened: %v", err))
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	defer db.Close()
	if err := db.PingContext(queryCtx); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("database ping failed: %v", err))
		result.FinishedAt = time.Now().UTC()
		return result, nil
	}
	if result.Profile == "yii2-rbac" {
		var warnings []string
		specs, warnings = yii2RBACDatabaseCheckSpecs(queryCtx, db, result.Engine, input.TablePrefix)
		result.Warnings = append(result.Warnings, warnings...)
	}
	if result.Profile == "laravel" {
		var warnings []string
		specs, warnings = laravelDatabaseCheckSpecs(queryCtx, db, result.Engine, input.TablePrefix)
		result.Warnings = append(result.Warnings, warnings...)
	}

	for _, spec := range specs {
		check := DatabaseCheckResult{
			Name:       spec.Name,
			Status:     "ok",
			Metric:     spec.Metric,
			Table:      spec.Table,
			OptionName: spec.OptionName,
		}
		switch spec.Kind {
		case databaseCheckCount:
			count, err := queryDatabaseCount(queryCtx, db, spec)
			if err != nil {
				check.Status = "warning"
				check.Message = fmt.Sprintf("count query failed: %v", err)
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", spec.Name, check.Message))
			} else {
				check.Count = count
				check.CountValid = true
			}
		case databaseCheckDigest:
			value, found, err := queryDatabaseString(queryCtx, db, spec)
			if err != nil {
				check.Status = "warning"
				check.Message = fmt.Sprintf("value digest query failed: %v", err)
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", spec.Name, check.Message))
			} else if !found {
				check.Status = "missing"
				check.Message = "value was not present"
			} else {
				sum := sha256.Sum256([]byte(value))
				check.ValueSHA256 = hex.EncodeToString(sum[:])
				check.ValueBytes = len([]byte(value))
			}
		default:
			check.Status = "warning"
			check.Message = "unknown database check kind"
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", spec.Name, check.Message))
		}
		result.Checks = append(result.Checks, check)
	}
	entities, entityWarnings := collectDatabaseEntities(queryCtx, db, result.Profile, result.Engine, input.TablePrefix, newDatabasePIIProtector(input.PIIKey))
	result.Entities = append(result.Entities, entities...)
	result.Warnings = append(result.Warnings, entityWarnings...)

	result.FinishedAt = time.Now().UTC()
	return result, nil
}

func collectDatabaseEntities(ctx context.Context, db *sql.DB, profile string, engine string, tablePrefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	switch normalizeDatabaseProfile(profile) {
	case "wordpress":
		return collectWordPressDatabaseEntities(ctx, db, tablePrefix, pii)
	case "prestashop":
		return collectPrestaShopDatabaseEntities(ctx, db, tablePrefix, pii)
	case "mautic":
		return collectMauticDatabaseEntities(ctx, db, tablePrefix, pii)
	case "yii2-rbac":
		return collectYii2RBACDatabaseEntities(ctx, db, engine, tablePrefix, pii)
	case "laravel":
		return collectLaravelDatabaseEntities(ctx, db, engine, tablePrefix, pii)
	default:
		return nil, nil
	}
}

func collectWordPressDatabaseEntities(ctx context.Context, db *sql.DB, tablePrefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "wp_")
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	networkAdmins, networkAdminWarnings := collectWordPressNetworkAdminLogins(ctx, db, prefix)
	warnings = append(warnings, networkAdminWarnings...)

	userEntities, userWarnings := collectWordPressUserEntities(ctx, db, prefix, networkAdmins, pii)
	entities = append(entities, userEntities...)
	warnings = append(warnings, userWarnings...)

	optionEntities, optionWarnings := collectWordPressOptionEntities(ctx, db, prefix)
	entities = append(entities, optionEntities...)
	warnings = append(warnings, optionWarnings...)

	networkEntities, networkWarnings := collectWordPressNetworkOptionEntities(ctx, db, prefix)
	entities = append(entities, networkEntities...)
	warnings = append(warnings, networkWarnings...)

	contentEntities, contentWarnings := collectWordPressContentScriptEntities(ctx, db, prefix)
	entities = append(entities, contentEntities...)
	warnings = append(warnings, contentWarnings...)

	sortDatabaseEntities(entities)
	return entities, warnings
}

func collectWordPressUserEntities(ctx context.Context, db *sql.DB, prefix string, networkAdmins map[string]struct{}, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	users := quoteDatabaseIdentifier(prefix + "users")
	usermeta := quoteDatabaseIdentifier(prefix + "usermeta")
	query := "SELECT u.ID, COALESCE(u.user_login, ''), COALESCE(u.user_email, ''), " +
		"COALESCE(NULLIF(CAST(u.user_registered AS CHAR), '0000-00-00 00:00:00'), ''), " +
		"COALESCE(GROUP_CONCAT(COALESCE(um.meta_value, '') ORDER BY um.meta_key SEPARATOR '\n'), '') FROM " +
		users + " u LEFT JOIN " + usermeta + " um ON um.user_id = u.ID AND um.meta_key REGEXP ? " +
		"GROUP BY u.ID, u.user_login, u.user_email, u.user_registered ORDER BY u.ID LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, wordpressCapabilityMetaKeyRegexp(prefix))
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress user entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var login string
		var email string
		var registeredAt string
		var capabilities string
		if err := rows.Scan(&id, &login, &email, &registeredAt, &capabilities); err != nil {
			return entities, []string{fmt.Sprintf("wordpress user entity scan failed: %v", err)}
		}
		_, networkAdmin := networkAdmins[databaseNormalizeIdentifier(login)]
		entities = append(entities, wordpressUserEntityWithAccess(id, login, email, capabilities, networkAdmin, databaseSourceTime(registeredAt), time.Time{}, pii))
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress user entity rows failed: %v", err)}
	}
	return entities, nil
}

func wordpressUserEntity(id int64, login string, email string, capabilities string, pii databasePIIProtector) DatabaseEntityObservation {
	return wordpressUserEntityWithAccess(id, login, email, capabilities, false, time.Time{}, time.Time{}, pii)
}

func wordpressUserEntityWithAccess(id int64, login string, email string, capabilities string, networkSuperAdmin bool, sourceCreatedAt time.Time, sourceUpdatedAt time.Time, pii databasePIIProtector) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	login = strings.TrimSpace(login)
	email = strings.TrimSpace(email)
	admin := strings.Contains(strings.ToLower(capabilities), "administrator")
	accountDisplay := databaseAccountDisplay(login, email)
	attributes := map[string]any{
		"user_id_hash":        databaseSHA256Hex(idText),
		"capabilities_sha256": databaseSHA256Hex(capabilities),
		"administrator":       admin,
		"has_capabilities":    strings.TrimSpace(capabilities) != "",
	}
	if networkSuperAdmin {
		attributes["network_super_admin"] = true
	}
	if accountDisplay != "" {
		attributes["account_display"] = accountDisplay
	}
	if normalized := databaseNormalizeEmail(email); normalized != "" {
		attributes["email"] = normalized
	}
	if normalized := databaseNormalizeIdentifier(login); normalized != "" {
		attributes["login"] = normalized
	}
	if masked := databaseMaskEmail(email); masked != "" {
		attributes["email_masked"] = masked
	}
	if masked := databaseMaskIdentifier(login); masked != "" {
		attributes["login_masked"] = masked
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeEmail(email)); fingerprint != "" {
		attributes["email_hmac_sha256"] = fingerprint
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeIdentifier(login)); fingerprint != "" {
		attributes["login_hmac_sha256"] = fingerprint
	}
	entity := DatabaseEntityObservation{
		Type:            "wordpress_user",
		Key:             databaseEntityKey("wordpress_user", idText),
		Label:           databaseDisplayLabel("wordpress_user", accountDisplay, idText),
		Privileged:      admin || networkSuperAdmin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes:      attributes,
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectWordPressOptionEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	options := quoteDatabaseIdentifier(prefix + "options")
	names := wordpressTrackedSiteOptionNames(prefix)
	rows, err := db.QueryContext(ctx, "SELECT option_name, COALESCE(option_value, '') FROM "+options+" WHERE option_name IN ("+databasePlaceholders(len(names))+") ORDER BY option_name LIMIT 100", stringArgs(names)...)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress option entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var name string
		var value string
		if err := rows.Scan(&name, &value); err != nil {
			return entities, []string{fmt.Sprintf("wordpress option entity scan failed: %v", err)}
		}
		entities = append(entities, wordpressEntitiesFromOption("site", name, value)...)
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress option entity rows failed: %v", err)}
	}
	return entities, nil
}

func collectWordPressNetworkOptionEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := prefix + "sitemeta"
	exists, err := databaseTableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress network option table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}

	names := wordpressTrackedNetworkOptionNames()
	query := "SELECT meta_key, COALESCE(meta_value, '') FROM " + quoteDatabaseIdentifier(table) +
		" WHERE meta_key IN (" + databasePlaceholders(len(names)) + ") ORDER BY meta_key LIMIT 100"
	rows, err := db.QueryContext(ctx, query, stringArgs(names)...)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress network option entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var name string
		var value string
		if err := rows.Scan(&name, &value); err != nil {
			return entities, []string{fmt.Sprintf("wordpress network option entity scan failed: %v", err)}
		}
		entities = append(entities, wordpressEntitiesFromOption("network", name, value)...)
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress network option entity rows failed: %v", err)}
	}
	return entities, nil
}

func collectWordPressNetworkAdminLogins(ctx context.Context, db *sql.DB, prefix string) (map[string]struct{}, []string) {
	admins := map[string]struct{}{}
	table := prefix + "sitemeta"
	exists, err := databaseTableExists(ctx, db, table)
	if err != nil {
		return admins, []string{fmt.Sprintf("wordpress network admin table check failed: %v", err)}
	}
	if !exists {
		return admins, nil
	}

	rows, err := db.QueryContext(ctx, "SELECT COALESCE(meta_value, '') FROM "+quoteDatabaseIdentifier(table)+" WHERE meta_key = ? LIMIT 100", "site_admins")
	if err != nil {
		return admins, []string{fmt.Sprintf("wordpress network admin query failed: %v", err)}
	}
	defer rows.Close()

	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return admins, []string{fmt.Sprintf("wordpress network admin scan failed: %v", err)}
		}
		for _, login := range parseWordPressSiteAdmins(value) {
			admins[databaseNormalizeIdentifier(login)] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return admins, []string{fmt.Sprintf("wordpress network admin rows failed: %v", err)}
	}
	return admins, nil
}

func wordpressTrackedSiteOptionNames(prefix string) []string {
	return []string{
		"active_plugins",
		"admin_email",
		"blog_public",
		"cron",
		"default_role",
		"home",
		"permalink_structure",
		"siteurl",
		"stylesheet",
		"template",
		"users_can_register",
		prefix + "user_roles",
	}
}

func wordpressTrackedNetworkOptionNames() []string {
	return []string{
		"active_sitewide_plugins",
		"admin_email",
		"registration",
		"site_admins",
		"siteurl",
		"upload_space_check_disabled",
	}
}

func wordpressEntitiesFromOption(scope string, name string, value string) []DatabaseEntityObservation {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "site"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	entities := []DatabaseEntityObservation{wordpressOptionEntity(scope, name, value)}
	switch name {
	case "active_plugins":
		for _, plugin := range parseWordPressActivePlugins(value) {
			entities = append(entities, wordpressPluginEntity(scope, name, plugin))
		}
	case "active_sitewide_plugins":
		for _, plugin := range parseWordPressActivePlugins(value) {
			entities = append(entities, wordpressPluginEntity("network", name, plugin))
		}
	case "stylesheet", "template":
		if theme := strings.TrimSpace(value); theme != "" {
			entities = append(entities, wordpressThemeEntity(scope, name, theme))
		}
	case "cron":
		for _, hook := range parseWordPressCronHooks(value) {
			entities = append(entities, wordpressCronEntity(scope, name, hook))
		}
	}
	return entities
}

func wordpressOptionEntity(scope string, name string, value string) DatabaseEntityObservation {
	valueBytes := len([]byte(value))
	entity := DatabaseEntityObservation{
		Type:       "wordpress_option",
		Key:        databaseEntityKey("wordpress_option", scope+"\x00"+name),
		Label:      scope + ":" + name,
		Privileged: isWordPressSensitiveOption(name),
		Attributes: map[string]any{
			"scope":        scope,
			"option_name":  name,
			"value_sha256": databaseSHA256Hex(value),
			"value_bytes":  valueBytes,
			"empty":        strings.TrimSpace(value) == "",
			"sensitive":    isWordPressSensitiveOption(name),
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func wordpressPluginEntity(scope string, sourceOption string, pluginFile string) DatabaseEntityObservation {
	pluginFile = normalizeWordPressPluginFile(pluginFile)
	slug := wordpressPluginSlug(pluginFile)
	entity := DatabaseEntityObservation{
		Type:       "wordpress_plugin",
		Key:        databaseEntityKey("wordpress_plugin", scope+"\x00"+pluginFile),
		Label:      pluginFile,
		Privileged: false,
		Attributes: map[string]any{
			"scope":              scope,
			"source_option":      sourceOption,
			"plugin_file":        pluginFile,
			"plugin_slug":        slug,
			"plugin_file_sha256": databaseSHA256Hex(pluginFile),
			"active":             true,
			"network_active":     scope == "network",
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func wordpressThemeEntity(scope string, sourceOption string, theme string) DatabaseEntityObservation {
	theme = strings.Trim(strings.ReplaceAll(theme, "\\", "/"), "/")
	entity := DatabaseEntityObservation{
		Type:       "wordpress_theme",
		Key:        databaseEntityKey("wordpress_theme", scope+"\x00"+sourceOption+"\x00"+theme),
		Label:      theme,
		Privileged: false,
		Attributes: map[string]any{
			"scope":         scope,
			"source_option": sourceOption,
			"theme_slug":    theme,
			"theme_sha256":  databaseSHA256Hex(theme),
			"active":        true,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func wordpressCronEntity(scope string, sourceOption string, hook string) DatabaseEntityObservation {
	hook = normalizeWordPressCronHook(hook)
	suspicious, reasons := classifyWordPressCronHook(hook)
	entity := DatabaseEntityObservation{
		Type:       "wordpress_cron",
		Key:        databaseEntityKey("wordpress_cron", scope+"\x00"+hook),
		Label:      hook,
		Privileged: suspicious,
		Attributes: map[string]any{
			"scope":             scope,
			"source_option":     sourceOption,
			"hook_name":         hook,
			"hook_name_sha256":  databaseSHA256Hex(hook),
			"suspicious":        suspicious,
			"suspicious_reason": reasons,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func parseWordPressActivePlugins(value string) []string {
	plugins, ok := parsePHPSerializedStrings(value)
	if !ok {
		plugins = splitWordPressOptionList(value)
	}
	seen := map[string]bool{}
	normalized := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		plugin = normalizeWordPressPluginFile(plugin)
		if plugin == "" || seen[plugin] {
			continue
		}
		seen[plugin] = true
		normalized = append(normalized, plugin)
	}
	sort.Strings(normalized)
	return normalized
}

func parseWordPressCronHooks(value string) []string {
	values, ok := parsePHPSerializedStrings(value)
	if !ok {
		values = splitWordPressOptionList(value)
	}
	seen := map[string]bool{}
	hooks := make([]string, 0, len(values))
	for _, value := range values {
		hook := normalizeWordPressCronHook(value)
		if hook == "" || isWordPressCronMetadataString(hook) || seen[hook] {
			continue
		}
		seen[hook] = true
		hooks = append(hooks, hook)
	}
	sort.Strings(hooks)
	return hooks
}

func parseWordPressSiteAdmins(value string) []string {
	values, ok := parsePHPSerializedStrings(value)
	if !ok {
		values = splitWordPressOptionList(value)
	}
	seen := map[string]bool{}
	admins := make([]string, 0, len(values))
	for _, value := range values {
		login := databaseNormalizeIdentifier(value)
		if login == "" || seen[login] {
			continue
		}
		seen[login] = true
		admins = append(admins, login)
	}
	sort.Strings(admins)
	return admins
}

func normalizeWordPressCronHook(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 120 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':' {
			continue
		}
		return ""
	}
	return value
}

func isWordPressCronMetadataString(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch lower {
	case "schedule", "args", "interval", "timestamp", "hook", "hourly", "twicedaily", "daily", "weekly", "monthly":
		return true
	}
	if len(lower) >= 16 && isLowerHexString(lower) {
		return true
	}
	return false
}

func classifyWordPressCronHook(hook string) (bool, []string) {
	lower := strings.ToLower(strings.TrimSpace(hook))
	checks := map[string]string{
		"assert":         "assert reference",
		"backdoor":       "backdoor wording",
		"base64":         "base64 wording",
		"cmd":            "command wording",
		"eval":           "eval reference",
		"exec":           "exec reference",
		"malware":        "malware wording",
		"passthru":       "passthru reference",
		"shell":          "shell wording",
		"system":         "system reference",
		"wp_ajax_nopriv": "unauthenticated ajax wording",
	}
	var reasons []string
	for needle, reason := range checks {
		if strings.Contains(lower, needle) {
			reasons = append(reasons, reason)
		}
	}
	sort.Strings(reasons)
	return len(reasons) > 0, reasons
}

func isLowerHexString(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func parsePHPSerializedStrings(value string) ([]string, bool) {
	var items []string
	foundMarker := false
	for i := 0; i < len(value); i++ {
		if value[i] != 's' || i+2 >= len(value) || value[i+1] != ':' {
			continue
		}
		foundMarker = true
		lengthStart := i + 2
		lengthEnd := lengthStart
		for lengthEnd < len(value) && value[lengthEnd] >= '0' && value[lengthEnd] <= '9' {
			lengthEnd++
		}
		if lengthEnd == lengthStart || lengthEnd+2 >= len(value) || value[lengthEnd] != ':' || value[lengthEnd+1] != '"' {
			continue
		}
		length, err := strconv.Atoi(value[lengthStart:lengthEnd])
		if err != nil || length < 0 {
			continue
		}
		contentStart := lengthEnd + 2
		contentEnd := contentStart + length
		if contentEnd >= len(value) || value[contentEnd] != '"' {
			continue
		}
		items = append(items, value[contentStart:contentEnd])
		i = contentEnd
	}
	return items, foundMarker
}

func splitWordPressOptionList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	items := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			items = append(items, field)
		}
	}
	return items
}

func normalizeWordPressPluginFile(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.Trim(value, "/")
	if !strings.Contains(value, ".php") {
		return ""
	}
	return value
}

func wordpressPluginSlug(pluginFile string) string {
	pluginFile = normalizeWordPressPluginFile(pluginFile)
	if pluginFile == "" {
		return ""
	}
	parts := strings.Split(pluginFile, "/")
	if len(parts) == 0 {
		return pluginFile
	}
	return parts[0]
}

func isWordPressSensitiveOption(name string) bool {
	switch strings.TrimSpace(name) {
	case "active_plugins",
		"active_sitewide_plugins",
		"admin_email",
		"blog_public",
		"cron",
		"default_role",
		"home",
		"registration",
		"site_admins",
		"siteurl",
		"stylesheet",
		"template",
		"upload_space_check_disabled",
		"users_can_register":
		return true
	default:
		return strings.HasSuffix(name, "user_roles")
	}
}

func collectWordPressContentScriptEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	var entities []DatabaseEntityObservation
	var warnings []string

	postEntities, postWarnings := collectWordPressPostContentScriptEntities(ctx, db, prefix)
	entities = append(entities, postEntities...)
	warnings = append(warnings, postWarnings...)

	metaEntities, metaWarnings := collectWordPressPostMetaScriptEntities(ctx, db, prefix)
	entities = append(entities, metaEntities...)
	warnings = append(warnings, metaWarnings...)

	widgetEntities, widgetWarnings := collectWordPressWidgetScriptEntities(ctx, db, prefix)
	entities = append(entities, widgetEntities...)
	warnings = append(warnings, widgetWarnings...)

	return entities, warnings
}

func collectWordPressPostContentScriptEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := prefix + "posts"
	exists, err := databaseTableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress post content table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}

	where, args := wordpressScriptContentWhere("post_content")
	query := "SELECT ID, COALESCE(post_type, ''), COALESCE(post_status, ''), " +
		"COALESCE(NULLIF(CAST(post_date AS CHAR), '0000-00-00 00:00:00'), ''), " +
		"COALESCE(NULLIF(CAST(post_modified AS CHAR), '0000-00-00 00:00:00'), ''), COALESCE(post_content, '') FROM " + quoteDatabaseIdentifier(table) +
		" WHERE (" + where + ") AND COALESCE(post_status, '') NOT IN ('trash', 'auto-draft') ORDER BY ID LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress post content entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var postType string
		var postStatus string
		var postDate string
		var postModified string
		var content string
		if err := rows.Scan(&id, &postType, &postStatus, &postDate, &postModified, &content); err != nil {
			return entities, []string{fmt.Sprintf("wordpress post content entity scan failed: %v", err)}
		}
		idText := strconv.FormatInt(id, 10)
		entities = append(entities, wordpressScriptContentEntity("post_content", idText, "post:"+strings.TrimSpace(postType)+":"+databaseSHA256Short(idText), content, map[string]any{
			"post_id_hash": databaseSHA256Hex(idText),
			"post_type":    strings.TrimSpace(postType),
			"post_status":  strings.TrimSpace(postStatus),
		}, databaseSourceTime(postDate), databaseSourceTime(postModified)))
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress post content entity rows failed: %v", err)}
	}
	return entities, nil
}

func collectWordPressPostMetaScriptEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := prefix + "postmeta"
	exists, err := databaseTableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress builder content table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}

	keys := wordpressTrackedBuilderMetaKeys()
	where, args := wordpressScriptContentWhere("meta_value")
	queryArgs := append(stringArgs(keys), args...)
	query := "SELECT meta_id, post_id, meta_key, COALESCE(meta_value, '') FROM " + quoteDatabaseIdentifier(table) +
		" WHERE meta_key IN (" + databasePlaceholders(len(keys)) + ") AND (" + where + ") ORDER BY meta_id LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress builder content entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var metaID int64
		var postID int64
		var metaKey string
		var value string
		if err := rows.Scan(&metaID, &postID, &metaKey, &value); err != nil {
			return entities, []string{fmt.Sprintf("wordpress builder content entity scan failed: %v", err)}
		}
		metaIDText := strconv.FormatInt(metaID, 10)
		postIDText := strconv.FormatInt(postID, 10)
		metaKey = strings.TrimSpace(metaKey)
		entities = append(entities, wordpressScriptContentEntity("postmeta:"+metaKey, metaIDText, "postmeta:"+metaKey+":"+databaseSHA256Short(metaIDText), value, map[string]any{
			"meta_id_hash": databaseSHA256Hex(metaIDText),
			"post_id_hash": databaseSHA256Hex(postIDText),
			"meta_key":     metaKey,
			"builder_data": true,
		}))
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress builder content entity rows failed: %v", err)}
	}
	return entities, nil
}

func collectWordPressWidgetScriptEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := prefix + "options"
	where, args := wordpressScriptContentWhere("option_value")
	queryArgs := append([]any{"widget_%"}, args...)
	query := "SELECT option_name, COALESCE(option_value, '') FROM " + quoteDatabaseIdentifier(table) +
		" WHERE option_name LIKE ? AND (" + where + ") ORDER BY option_name LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress widget content entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var optionName string
		var value string
		if err := rows.Scan(&optionName, &value); err != nil {
			return entities, []string{fmt.Sprintf("wordpress widget content entity scan failed: %v", err)}
		}
		optionName = strings.TrimSpace(optionName)
		entities = append(entities, wordpressScriptContentEntity("widget_option", optionName, "widget:"+optionName, value, map[string]any{
			"option_name":    optionName,
			"widget_content": true,
		}))
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress widget content entity rows failed: %v", err)}
	}
	return entities, nil
}

func wordpressScriptContentWhere(column string) (string, []any) {
	column = strings.TrimSpace(column)
	patterns := []string{"%<script%", "%<iframe%", "%javascript:%", "%onerror=%", "%onload=%", "%document.write%", "%eval(%", "%atob(%"}
	parts := make([]string, 0, len(patterns))
	args := make([]any, 0, len(patterns))
	for _, pattern := range patterns {
		parts = append(parts, column+" LIKE ?")
		args = append(args, pattern)
	}
	return strings.Join(parts, " OR "), args
}

func wordpressTrackedBuilderMetaKeys() []string {
	return []string{
		"_elementor_data",
		"_elementor_css",
		"_et_pb_custom_css",
		"_fl_builder_data",
		"_oxygen_builder_shortcodes",
		"_wpb_shortcodes_custom_css",
	}
}

func wordpressScriptContentEntity(source string, identifier string, label string, content string, extra map[string]any, sourceCreatedAt ...time.Time) DatabaseEntityObservation {
	indicators := wordpressScriptContentIndicators(content)
	domains := wordpressScriptContentDomains(content)
	source = strings.TrimSpace(source)
	identifier = strings.TrimSpace(identifier)
	label = strings.TrimSpace(label)
	attributes := map[string]any{
		"source":                 source,
		"content_sha256":         databaseSHA256Hex(content),
		"content_bytes":          len([]byte(content)),
		"indicators":             indicators,
		"indicator_count":        len(indicators),
		"external_domains":       domains,
		"external_domains_count": len(domains),
		"suspicious":             len(indicators) > 0,
	}
	for key, value := range extra {
		key = strings.TrimSpace(key)
		if key != "" {
			attributes[key] = value
		}
	}
	entity := DatabaseEntityObservation{
		Type:       "wordpress_content_script",
		Key:        databaseEntityKey("wordpress_content_script", source+"\x00"+identifier),
		Label:      label,
		Privileged: false,
		Attributes: attributes,
	}
	if len(sourceCreatedAt) > 0 {
		entity.SourceCreatedAt = sourceCreatedAt[0]
	}
	if len(sourceCreatedAt) > 1 {
		entity.SourceUpdatedAt = sourceCreatedAt[1]
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func wordpressScriptContentIndicators(content string) []string {
	lower := strings.ToLower(content)
	checks := map[string]string{
		"<iframe":        "iframe",
		"<script":        "script_tag",
		"atob(":          "atob_decode",
		"document.write": "document_write",
		"eval(":          "eval_call",
		"javascript:":    "javascript_url",
		"onerror=":       "inline_error_handler",
		"onload=":        "inline_load_handler",
	}
	var indicators []string
	for needle, indicator := range checks {
		if strings.Contains(lower, needle) {
			indicators = append(indicators, indicator)
		}
	}
	sort.Strings(indicators)
	return indicators
}

func wordpressScriptContentDomains(content string) []string {
	matches := wordpressScriptDomainPattern.FindAllStringSubmatch(content, -1)
	seen := map[string]bool{}
	domains := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(match[1]), "."))
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func collectPrestaShopDatabaseEntities(ctx context.Context, db *sql.DB, tablePrefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "ps_")
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	employeeEntities, employeeWarnings := collectPrestaShopEmployeeEntities(ctx, db, prefix, pii)
	entities = append(entities, employeeEntities...)
	warnings = append(warnings, employeeWarnings...)

	moduleEntities, moduleWarnings := collectPrestaShopModuleEntities(ctx, db, prefix)
	entities = append(entities, moduleEntities...)
	warnings = append(warnings, moduleWarnings...)

	configurationEntities, configurationWarnings := collectPrestaShopConfigurationEntities(ctx, db, prefix)
	entities = append(entities, configurationEntities...)
	warnings = append(warnings, configurationWarnings...)

	sortDatabaseEntities(entities)
	return entities, warnings
}

func collectPrestaShopEmployeeEntities(ctx context.Context, db *sql.DB, prefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "employee"
	table := quoteDatabaseIdentifier(tableName)
	createdExpr, updatedExpr, warnings := databaseOptionalTimestampExpressions(ctx, db, tableName, "date_add", "date_upd")
	rows, err := db.QueryContext(ctx, "SELECT id_employee, COALESCE(email, ''), active, id_profile, "+createdExpr+", "+updatedExpr+" FROM "+table+" ORDER BY id_employee LIMIT 1000")
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("prestashop employee entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var email string
		var active int64
		var profileID int64
		var dateAdd string
		var dateUpd string
		if err := rows.Scan(&id, &email, &active, &profileID, &dateAdd, &dateUpd); err != nil {
			return entities, append(warnings, fmt.Sprintf("prestashop employee entity scan failed: %v", err))
		}
		entities = append(entities, prestashopEmployeeEntity(id, email, active != 0, profileID, databaseSourceTime(dateAdd), databaseSourceTime(dateUpd), pii))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("prestashop employee entity rows failed: %v", err))
	}
	return entities, warnings
}

func prestashopEmployeeEntity(id int64, email string, active bool, profileID int64, sourceCreatedAt time.Time, sourceUpdatedAt time.Time, pii databasePIIProtector) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	email = strings.TrimSpace(email)
	superAdmin := profileID == 1
	accountDisplay := databaseAccountDisplay("", email)
	attributes := map[string]any{
		"employee_id_hash": databaseSHA256Hex(idText),
		"profile_id":       profileID,
		"active":           active,
		"super_admin":      superAdmin,
	}
	if accountDisplay != "" {
		attributes["account_display"] = accountDisplay
	}
	if normalized := databaseNormalizeEmail(email); normalized != "" {
		attributes["email"] = normalized
	}
	if masked := databaseMaskEmail(email); masked != "" {
		attributes["email_masked"] = masked
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeEmail(email)); fingerprint != "" {
		attributes["email_hmac_sha256"] = fingerprint
	}
	entity := DatabaseEntityObservation{
		Type:            "prestashop_employee",
		Key:             databaseEntityKey("prestashop_employee", idText),
		Label:           databaseDisplayLabel("prestashop_employee", accountDisplay, idText),
		Privileged:      superAdmin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes:      attributes,
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectPrestaShopModuleEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "module"
	table := quoteDatabaseIdentifier(tableName)
	createdExpr, updatedExpr, warnings := databaseOptionalTimestampExpressions(ctx, db, tableName, "date_add", "date_upd")
	rows, err := db.QueryContext(ctx, "SELECT id_module, COALESCE(name, ''), active, COALESCE(version, ''), "+createdExpr+", "+updatedExpr+" FROM "+table+" ORDER BY id_module LIMIT 2000")
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("prestashop module entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var name string
		var active int64
		var version string
		var dateAdd string
		var dateUpd string
		if err := rows.Scan(&id, &name, &active, &version, &dateAdd, &dateUpd); err != nil {
			return entities, append(warnings, fmt.Sprintf("prestashop module entity scan failed: %v", err))
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		isActive := active != 0
		entity := DatabaseEntityObservation{
			Type:            "prestashop_module",
			Key:             databaseEntityKey("prestashop_module", strconv.FormatInt(id, 10)),
			Label:           name,
			Privileged:      false,
			SourceCreatedAt: databaseSourceTime(dateAdd),
			SourceUpdatedAt: databaseSourceTime(dateUpd),
			Attributes: map[string]any{
				"module_id_hash": databaseSHA256Hex(strconv.FormatInt(id, 10)),
				"module_name":    name,
				"name_sha256":    databaseSHA256Hex(name),
				"version":        version,
				"active":         isActive,
			},
		}
		if entity.Label == "" {
			entity.Label = "prestashop_module:" + databaseSHA256Short(strconv.FormatInt(id, 10))
		}
		entity.Signature = databaseEntitySignature(entity)
		entities = append(entities, entity)
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("prestashop module entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectPrestaShopConfigurationEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "configuration"
	table := quoteDatabaseIdentifier(tableName)
	createdExpr, updatedExpr, warnings := databaseOptionalTimestampExpressions(ctx, db, tableName, "date_add", "date_upd")
	names := prestashopTrackedConfigurationNames()
	patterns := prestashopTrackedConfigurationPatterns()
	whereParts := []string{"name IN (" + databasePlaceholders(len(names)) + ")"}
	args := stringArgs(names)
	for _, pattern := range patterns {
		whereParts = append(whereParts, "name LIKE ?")
		args = append(args, pattern)
	}
	query := "SELECT name, COALESCE(value, ''), " + createdExpr + ", " + updatedExpr + " FROM " + table +
		" WHERE " + strings.Join(whereParts, " OR ") + " ORDER BY name LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("prestashop configuration entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var name string
		var value string
		var dateAdd string
		var dateUpd string
		if err := rows.Scan(&name, &value, &dateAdd, &dateUpd); err != nil {
			return entities, append(warnings, fmt.Sprintf("prestashop configuration entity scan failed: %v", err))
		}
		if entity, ok := prestashopConfigurationEntity(name, value); ok {
			entity.SourceCreatedAt = databaseSourceTime(dateAdd)
			entity.SourceUpdatedAt = databaseSourceTime(dateUpd)
			entity.Signature = databaseEntitySignature(entity)
			entities = append(entities, entity)
		}
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("prestashop configuration entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectMauticDatabaseEntities(ctx context.Context, db *sql.DB, tablePrefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "")
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	userEntities, userWarnings := collectMauticUserEntities(ctx, db, prefix, pii)
	entities = append(entities, userEntities...)
	warnings = append(warnings, userWarnings...)

	roleEntities, roleWarnings := collectMauticRoleEntities(ctx, db, prefix)
	entities = append(entities, roleEntities...)
	warnings = append(warnings, roleWarnings...)

	pluginEntities, pluginWarnings := collectMauticPluginEntities(ctx, db, prefix)
	entities = append(entities, pluginEntities...)
	warnings = append(warnings, pluginWarnings...)

	integrationEntities, integrationWarnings := collectMauticIntegrationEntities(ctx, db, prefix)
	entities = append(entities, integrationEntities...)
	warnings = append(warnings, integrationWarnings...)

	oauthEntities, oauthWarnings := collectMauticOAuthClientEntities(ctx, db, prefix)
	entities = append(entities, oauthEntities...)
	warnings = append(warnings, oauthWarnings...)

	webhookEntities, webhookWarnings := collectMauticWebhookEntities(ctx, db, prefix)
	entities = append(entities, webhookEntities...)
	warnings = append(warnings, webhookWarnings...)

	sortDatabaseEntities(entities)
	return entities, warnings
}

func collectMauticUserEntities(ctx context.Context, db *sql.DB, prefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "users"
	exists, err := databaseTableExists(ctx, db, tableName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic user table check failed: %v", err)}
	}
	if !exists {
		return nil, []string{"mautic users table was not found"}
	}
	rolesName := prefix + "roles"
	rolesExist, err := databaseTableExists(ctx, db, rolesName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic role table check failed: %v", err)}
	}

	createdExpr, updatedExpr, warnings := databaseOptionalAliasedTimestampExpressions(ctx, db, tableName, "u", "date_added", "date_modified")
	publishedExpr, publishedWarnings := databaseOptionalColumnExpression(ctx, db, tableName, "is_published", "COALESCE(CAST(u."+quoteDatabaseIdentifier("is_published")+" AS SIGNED), 0)", "1")
	warnings = append(warnings, publishedWarnings...)

	roleNameExpr := "''"
	roleAdminExpr := "0"
	join := ""
	if rolesExist {
		join = " LEFT JOIN " + quoteDatabaseIdentifier(rolesName) + " r ON r." + quoteDatabaseIdentifier("id") + " = u." + quoteDatabaseIdentifier("role_id")
		roleNameExpr = "COALESCE(r." + quoteDatabaseIdentifier("name") + ", '')"
		roleAdminExpr = "COALESCE(CAST(r." + quoteDatabaseIdentifier("is_admin") + " AS SIGNED), 0)"
	}
	query := "SELECT u." + quoteDatabaseIdentifier("id") +
		", COALESCE(u." + quoteDatabaseIdentifier("username") + ", '')" +
		", COALESCE(u." + quoteDatabaseIdentifier("email") + ", '')" +
		", COALESCE(u." + quoteDatabaseIdentifier("role_id") + ", 0)" +
		", " + roleNameExpr +
		", " + roleAdminExpr +
		", " + publishedExpr +
		", " + createdExpr +
		", " + updatedExpr +
		" FROM " + quoteDatabaseIdentifier(tableName) + " u" + join +
		" ORDER BY u." + quoteDatabaseIdentifier("id") + " LIMIT 1000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("mautic user entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var username string
		var email string
		var roleID int64
		var roleName string
		var adminRole int64
		var published int64
		var dateAdded string
		var dateModified string
		if err := rows.Scan(&id, &username, &email, &roleID, &roleName, &adminRole, &published, &dateAdded, &dateModified); err != nil {
			return entities, append(warnings, fmt.Sprintf("mautic user entity scan failed: %v", err))
		}
		entities = append(entities, mauticUserEntity(id, username, email, roleID, roleName, adminRole != 0, published != 0, databaseSourceTime(dateAdded), databaseSourceTime(dateModified), pii))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("mautic user entity rows failed: %v", err))
	}
	return entities, warnings
}

func mauticUserEntity(id int64, username string, email string, roleID int64, roleName string, adminRole bool, published bool, sourceCreatedAt time.Time, sourceUpdatedAt time.Time, pii databasePIIProtector) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	roleIDText := strconv.FormatInt(roleID, 10)
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	roleName = strings.TrimSpace(roleName)
	accountDisplay := databaseAccountDisplay(username, email)
	attributes := map[string]any{
		"user_id_hash": databaseSHA256Hex(idText),
		"role_id_hash": databaseSHA256Hex(roleIDText),
		"role_name":    roleName,
		"admin_role":   adminRole,
		"published":    published,
	}
	if accountDisplay != "" {
		attributes["account_display"] = accountDisplay
	}
	if normalized := databaseNormalizeEmail(email); normalized != "" {
		attributes["email"] = normalized
	}
	if normalized := databaseNormalizeIdentifier(username); normalized != "" {
		attributes["login"] = normalized
	}
	if masked := databaseMaskEmail(email); masked != "" {
		attributes["email_masked"] = masked
	}
	if masked := databaseMaskIdentifier(username); masked != "" {
		attributes["login_masked"] = masked
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeEmail(email)); fingerprint != "" {
		attributes["email_hmac_sha256"] = fingerprint
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeIdentifier(username)); fingerprint != "" {
		attributes["login_hmac_sha256"] = fingerprint
	}
	entity := DatabaseEntityObservation{
		Type:            "mautic_user",
		Key:             databaseEntityKey("mautic_user", idText),
		Label:           databaseDisplayLabel("mautic_user", accountDisplay, idText),
		Privileged:      adminRole,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes:      attributes,
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectMauticRoleEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "roles"
	exists, err := databaseTableExists(ctx, db, tableName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic role table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	createdExpr, updatedExpr, warnings := databaseOptionalAliasedTimestampExpressions(ctx, db, tableName, "r", "date_added", "date_modified")
	query := "SELECT r." + quoteDatabaseIdentifier("id") +
		", COALESCE(r." + quoteDatabaseIdentifier("name") + ", '')" +
		", COALESCE(CAST(r." + quoteDatabaseIdentifier("is_admin") + " AS SIGNED), 0)" +
		", COALESCE(r." + quoteDatabaseIdentifier("readable_permissions") + ", '')" +
		", " + createdExpr +
		", " + updatedExpr +
		" FROM " + quoteDatabaseIdentifier(tableName) + " r ORDER BY r." + quoteDatabaseIdentifier("id") + " LIMIT 200"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("mautic role entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var name string
		var isAdmin int64
		var permissions string
		var dateAdded string
		var dateModified string
		if err := rows.Scan(&id, &name, &isAdmin, &permissions, &dateAdded, &dateModified); err != nil {
			return entities, append(warnings, fmt.Sprintf("mautic role entity scan failed: %v", err))
		}
		entities = append(entities, mauticRoleEntity(id, name, isAdmin != 0, permissions, databaseSourceTime(dateAdded), databaseSourceTime(dateModified)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("mautic role entity rows failed: %v", err))
	}
	return entities, warnings
}

func mauticRoleEntity(id int64, name string, isAdmin bool, permissions string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	name = strings.TrimSpace(name)
	entity := DatabaseEntityObservation{
		Type:            "mautic_role",
		Key:             databaseEntityKey("mautic_role", idText),
		Label:           databaseDisplayLabel("mautic_role", name, idText),
		Privileged:      isAdmin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"role_id_hash":       databaseSHA256Hex(idText),
			"role_name":          name,
			"admin_role":         isAdmin,
			"permissions_sha256": databaseSHA256Hex(permissions),
			"permissions_bytes":  len([]byte(permissions)),
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectMauticPluginEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "plugins"
	exists, err := databaseTableExists(ctx, db, tableName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic plugin table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	createdExpr, updatedExpr, warnings := databaseOptionalAliasedTimestampExpressions(ctx, db, tableName, "p", "date_added", "date_modified")
	query := "SELECT p." + quoteDatabaseIdentifier("id") +
		", COALESCE(p." + quoteDatabaseIdentifier("name") + ", '')" +
		", COALESCE(p." + quoteDatabaseIdentifier("bundle") + ", '')" +
		", COALESCE(p." + quoteDatabaseIdentifier("version") + ", '')" +
		", COALESCE(CAST(p." + quoteDatabaseIdentifier("is_missing") + " AS SIGNED), 0)" +
		", " + createdExpr +
		", " + updatedExpr +
		" FROM " + quoteDatabaseIdentifier(tableName) + " p ORDER BY p." + quoteDatabaseIdentifier("id") + " LIMIT 1000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("mautic plugin entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var name string
		var bundle string
		var version string
		var missing int64
		var dateAdded string
		var dateModified string
		if err := rows.Scan(&id, &name, &bundle, &version, &missing, &dateAdded, &dateModified); err != nil {
			return entities, append(warnings, fmt.Sprintf("mautic plugin entity scan failed: %v", err))
		}
		entities = append(entities, mauticPluginEntity(id, name, bundle, version, missing != 0, databaseSourceTime(dateAdded), databaseSourceTime(dateModified)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("mautic plugin entity rows failed: %v", err))
	}
	return entities, warnings
}

func mauticPluginEntity(id int64, name string, bundle string, version string, missing bool, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	name = strings.TrimSpace(name)
	bundle = strings.TrimSpace(bundle)
	version = strings.TrimSpace(version)
	label := firstNonEmptyString(bundle, name, idText)
	entity := DatabaseEntityObservation{
		Type:            "mautic_plugin",
		Key:             databaseEntityKey("mautic_plugin", idText),
		Label:           label,
		Privileged:      false,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"plugin_id_hash": databaseSHA256Hex(idText),
			"plugin_name":    name,
			"bundle":         bundle,
			"version":        version,
			"missing":        missing,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectMauticIntegrationEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "plugin_integration_settings"
	exists, err := databaseTableExists(ctx, db, tableName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic integration table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	createdExpr, updatedExpr, warnings := databaseOptionalAliasedTimestampExpressions(ctx, db, tableName, "i", "date_added", "date_modified")
	query := "SELECT i." + quoteDatabaseIdentifier("id") +
		", COALESCE(i." + quoteDatabaseIdentifier("plugin_id") + ", 0)" +
		", COALESCE(i." + quoteDatabaseIdentifier("name") + ", '')" +
		", COALESCE(CAST(i." + quoteDatabaseIdentifier("is_published") + " AS SIGNED), 0)" +
		", COALESCE(i." + quoteDatabaseIdentifier("supported_features") + ", '')" +
		", COALESCE(i." + quoteDatabaseIdentifier("api_keys") + ", '')" +
		", COALESCE(i." + quoteDatabaseIdentifier("feature_settings") + ", '')" +
		", " + createdExpr +
		", " + updatedExpr +
		" FROM " + quoteDatabaseIdentifier(tableName) + " i ORDER BY i." + quoteDatabaseIdentifier("id") + " LIMIT 1000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("mautic integration entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var pluginID int64
		var name string
		var published int64
		var supportedFeatures string
		var apiKeys string
		var featureSettings string
		var dateAdded string
		var dateModified string
		if err := rows.Scan(&id, &pluginID, &name, &published, &supportedFeatures, &apiKeys, &featureSettings, &dateAdded, &dateModified); err != nil {
			return entities, append(warnings, fmt.Sprintf("mautic integration entity scan failed: %v", err))
		}
		entities = append(entities, mauticIntegrationEntity(id, pluginID, name, published != 0, supportedFeatures, apiKeys, featureSettings, databaseSourceTime(dateAdded), databaseSourceTime(dateModified)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("mautic integration entity rows failed: %v", err))
	}
	return entities, warnings
}

func mauticIntegrationEntity(id int64, pluginID int64, name string, published bool, supportedFeatures string, apiKeys string, featureSettings string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	pluginIDText := strconv.FormatInt(pluginID, 10)
	name = strings.TrimSpace(name)
	keysPresent := strings.TrimSpace(apiKeys) != ""
	entity := DatabaseEntityObservation{
		Type:            "mautic_integration",
		Key:             databaseEntityKey("mautic_integration", idText),
		Label:           databaseDisplayLabel("mautic_integration", name, idText),
		Privileged:      published && keysPresent,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"integration_id_hash":     databaseSHA256Hex(idText),
			"plugin_id_hash":          databaseSHA256Hex(pluginIDText),
			"integration_name":        name,
			"published":               published,
			"api_keys_present":        keysPresent,
			"api_keys_sha256":         databaseSHA256Hex(apiKeys),
			"api_keys_bytes":          len([]byte(apiKeys)),
			"features_sha256":         databaseSHA256Hex(supportedFeatures),
			"features_bytes":          len([]byte(supportedFeatures)),
			"feature_settings_sha256": databaseSHA256Hex(featureSettings),
			"feature_settings_bytes":  len([]byte(featureSettings)),
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectMauticOAuthClientEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "oauth2_clients"
	exists, err := databaseTableExists(ctx, db, tableName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic oauth client table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	createdExpr, updatedExpr, warnings := databaseOptionalAliasedTimestampExpressions(ctx, db, tableName, "c", "date_added", "date_modified")
	roleExpr, roleWarnings := databaseOptionalColumnExpression(ctx, db, tableName, "role_id", "COALESCE(c."+quoteDatabaseIdentifier("role_id")+", 0)", "0")
	warnings = append(warnings, roleWarnings...)
	query := "SELECT c." + quoteDatabaseIdentifier("id") +
		", COALESCE(c." + quoteDatabaseIdentifier("name") + ", '')" +
		", COALESCE(c." + quoteDatabaseIdentifier("random_id") + ", '')" +
		", COALESCE(c." + quoteDatabaseIdentifier("secret") + ", '')" +
		", COALESCE(c." + quoteDatabaseIdentifier("redirect_uris") + ", '')" +
		", COALESCE(c." + quoteDatabaseIdentifier("allowed_grant_types") + ", '')" +
		", " + roleExpr +
		", " + createdExpr +
		", " + updatedExpr +
		" FROM " + quoteDatabaseIdentifier(tableName) + " c ORDER BY c." + quoteDatabaseIdentifier("id") + " LIMIT 500"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("mautic oauth client entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var name string
		var randomID string
		var secret string
		var redirectURIs string
		var grantTypes string
		var roleID int64
		var dateAdded string
		var dateModified string
		if err := rows.Scan(&id, &name, &randomID, &secret, &redirectURIs, &grantTypes, &roleID, &dateAdded, &dateModified); err != nil {
			return entities, append(warnings, fmt.Sprintf("mautic oauth client entity scan failed: %v", err))
		}
		entities = append(entities, mauticOAuthClientEntity(id, name, randomID, secret, redirectURIs, grantTypes, roleID, databaseSourceTime(dateAdded), databaseSourceTime(dateModified)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("mautic oauth client entity rows failed: %v", err))
	}
	return entities, warnings
}

func mauticOAuthClientEntity(id int64, name string, randomID string, secret string, redirectURIs string, grantTypes string, roleID int64, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	roleIDText := strconv.FormatInt(roleID, 10)
	name = strings.TrimSpace(name)
	randomID = strings.TrimSpace(randomID)
	secretPresent := strings.TrimSpace(secret) != ""
	entity := DatabaseEntityObservation{
		Type:            "mautic_oauth_client",
		Key:             databaseEntityKey("mautic_oauth_client", idText),
		Label:           databaseDisplayLabel("mautic_oauth_client", name, randomID),
		Privileged:      true,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"client_id_hash":       databaseSHA256Hex(idText),
			"client_name":          name,
			"random_id_sha256":     databaseSHA256Hex(randomID),
			"secret_present":       secretPresent,
			"secret_sha256":        databaseSHA256Hex(secret),
			"secret_bytes":         len([]byte(secret)),
			"redirect_uris_sha256": databaseSHA256Hex(redirectURIs),
			"redirect_uris_bytes":  len([]byte(redirectURIs)),
			"grant_types_sha256":   databaseSHA256Hex(grantTypes),
			"grant_types_bytes":    len([]byte(grantTypes)),
			"role_id_hash":         databaseSHA256Hex(roleIDText),
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func collectMauticWebhookEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	tableName := prefix + "webhooks"
	exists, err := databaseTableExists(ctx, db, tableName)
	if err != nil {
		return nil, []string{fmt.Sprintf("mautic webhook table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	createdExpr, updatedExpr, warnings := databaseOptionalAliasedTimestampExpressions(ctx, db, tableName, "w", "date_added", "date_modified")
	query := "SELECT w." + quoteDatabaseIdentifier("id") +
		", COALESCE(w." + quoteDatabaseIdentifier("name") + ", '')" +
		", COALESCE(w." + quoteDatabaseIdentifier("webhook_url") + ", '')" +
		", COALESCE(w." + quoteDatabaseIdentifier("secret") + ", '')" +
		", COALESCE(CAST(w." + quoteDatabaseIdentifier("is_published") + " AS SIGNED), 0)" +
		", " + createdExpr +
		", " + updatedExpr +
		" FROM " + quoteDatabaseIdentifier(tableName) + " w ORDER BY w." + quoteDatabaseIdentifier("id") + " LIMIT 500"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("mautic webhook entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var name string
		var webhookURL string
		var secret string
		var published int64
		var dateAdded string
		var dateModified string
		if err := rows.Scan(&id, &name, &webhookURL, &secret, &published, &dateAdded, &dateModified); err != nil {
			return entities, append(warnings, fmt.Sprintf("mautic webhook entity scan failed: %v", err))
		}
		entities = append(entities, mauticWebhookEntity(id, name, webhookURL, secret, published != 0, databaseSourceTime(dateAdded), databaseSourceTime(dateModified)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("mautic webhook entity rows failed: %v", err))
	}
	return entities, warnings
}

func mauticWebhookEntity(id int64, name string, webhookURL string, secret string, published bool, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	idText := strconv.FormatInt(id, 10)
	name = strings.TrimSpace(name)
	secretPresent := strings.TrimSpace(secret) != ""
	entity := DatabaseEntityObservation{
		Type:            "mautic_webhook",
		Key:             databaseEntityKey("mautic_webhook", idText),
		Label:           databaseDisplayLabel("mautic_webhook", name, idText),
		Privileged:      published || secretPresent,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"webhook_id_hash":    databaseSHA256Hex(idText),
			"webhook_name":       name,
			"published":          published,
			"webhook_url_host":   mauticURLHost(webhookURL),
			"webhook_url_sha256": databaseSHA256Hex(webhookURL),
			"secret_present":     secretPresent,
			"secret_sha256":      databaseSHA256Hex(secret),
			"secret_bytes":       len([]byte(secret)),
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func prestashopConfigurationEntity(name string, value string) (DatabaseEntityObservation, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return DatabaseEntityObservation{}, false
	}
	category, sensitive, suspicious, reasons := classifyPrestaShopConfiguration(name, value)
	attributes := map[string]any{
		"config_name":       name,
		"category":          category,
		"value_sha256":      databaseSHA256Hex(value),
		"value_bytes":       len([]byte(value)),
		"empty":             strings.TrimSpace(value) == "",
		"sensitive":         sensitive,
		"suspicious":        suspicious,
		"suspicious_reason": reasons,
	}
	if boolValue, ok := parsePrestaShopBool(value); ok {
		attributes["value_bool"] = boolValue
	}
	entity := DatabaseEntityObservation{
		Type:       "prestashop_configuration",
		Key:        databaseEntityKey("prestashop_configuration", name),
		Label:      name,
		Privileged: suspicious,
		Attributes: attributes,
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity, true
}

func prestashopTrackedConfigurationNames() []string {
	return []string{
		"ADYEN_API_KEY",
		"ADYEN_MERCHANT_ACCOUNT",
		"AMAZON_PAY_CLIENT_ID",
		"AMAZON_PAY_CLIENT_SECRET",
		"AUTHORIZE_AIM_LOGIN_ID",
		"AUTHORIZE_AIM_KEY",
		"BRAINTREE_MERCHANT_ID",
		"BRAINTREE_PRIVATE_KEY",
		"BREVO_API_KEY",
		"MAILCHIMP_API_KEY",
		"MOLLIE_API_KEY",
		"PAYPAL_API_PASSWORD",
		"PAYPAL_API_SIGNATURE",
		"PAYPAL_API_USER",
		"PAYPLUG_LIVE_MODE",
		"PAYPLUG_SECRET_KEY",
		"PS_CANONICAL_REDIRECT",
		"PS_CHECKOUT_CLIENT_ID",
		"PS_CHECKOUT_CLIENT_SECRET",
		"PS_CHECKOUT_ENVIRONMENT",
		"PS_COOKIE_CHECKIP",
		"PS_COOKIE_SAMESITE",
		"PS_CURRENCY_DEFAULT",
		"PS_DEBUG_PROFILING",
		"PS_DEV_MODE",
		"PS_DISABLE_NON_NATIVE_MODULE",
		"PS_DISABLE_OVERRIDES",
		"PS_DISPLAY_ERRORS",
		"PS_MAIL_METHOD",
		"PS_MAIL_PASSWD",
		"PS_MAIL_SERVER",
		"PS_MAIL_SMTP_ENCRYPTION",
		"PS_MAIL_SMTP_PORT",
		"PS_MAIL_USER",
		"PS_MAINTENANCE_IP",
		"PS_MODE_DEV",
		"PS_REWRITING_SETTINGS",
		"PS_SHOP_DOMAIN",
		"PS_SHOP_DOMAIN_SSL",
		"PS_SHOP_ENABLE",
		"PS_SSL_ENABLED",
		"PS_SSL_ENABLED_EVERYWHERE",
		"PS_TOKEN_ENABLE",
		"PS_WEBSERVICE",
		"PS_WEBSERVICE_CGI_HOST",
		"REDSYS_SECRET_KEY",
		"SENDINBLUE_API_KEY",
		"STRIPE_PUBLIC_KEY",
		"STRIPE_SECRET_KEY",
	}
}

func prestashopTrackedConfigurationPatterns() []string {
	return []string{
		"%ADYEN%",
		"%AMAZONPAY%",
		"%AMAZON_PAY%",
		"%AUTHORIZE%",
		"%BRAINTREE%",
		"%BREVO%",
		"%CHECKOUT%",
		"%HIPAY%",
		"%KLARNA%",
		"%MAILCHIMP%",
		"%MOLLIE%",
		"%PAYMENT%",
		"%PAYPAL%",
		"%PAYPLUG%",
		"%REDSYS%",
		"%SENDINBLUE%",
		"%SQUARE%",
		"%STRIPE%",
		"%VIVA%",
		"%WEBHOOK%",
		"EMAIL%",
		"PS_DEBUG%",
		"PS_DEV%",
		"PS_DISPLAY%",
		"PS_MAIL_%",
		"PS_MAINTENANCE%",
		"PS_MODE_%",
		"PS_SHOP_%",
		"PS_SSL%",
		"PS_WEBSERVICE%",
		"SMTP%",
	}
}

func classifyPrestaShopConfiguration(name string, value string) (string, bool, bool, []string) {
	upper := strings.ToUpper(strings.TrimSpace(name))
	category := prestashopConfigurationCategory(upper)
	sensitive := isPrestaShopSensitiveConfiguration(upper)
	boolValue, boolOK := parsePrestaShopBool(value)
	var reasons []string

	switch upper {
	case "PS_MODE_DEV", "PS_DEV_MODE", "PS_DISPLAY_ERRORS", "PS_DEBUG_PROFILING":
		if boolOK && boolValue {
			reasons = append(reasons, "debug mode enabled")
		}
	case "PS_SSL_ENABLED", "PS_SSL_ENABLED_EVERYWHERE", "PS_COOKIE_CHECKIP", "PS_TOKEN_ENABLE":
		if boolOK && !boolValue {
			reasons = append(reasons, "security setting disabled")
		}
	case "PS_WEBSERVICE", "PS_WEBSERVICE_CGI_HOST":
		if boolOK && boolValue {
			reasons = append(reasons, "webservice enabled")
		}
	case "PS_SHOP_ENABLE":
		if boolOK && !boolValue {
			reasons = append(reasons, "shop disabled or maintenance mode active")
		}
	}
	if category == "payment" && sensitive {
		reasons = append(reasons, "payment secret tracked")
	}
	sort.Strings(reasons)
	return category, sensitive, len(reasons) > 0, reasons
}

func prestashopConfigurationCategory(upperName string) string {
	switch {
	case strings.Contains(upperName, "PAYMENT") ||
		strings.Contains(upperName, "PAYPAL") ||
		strings.Contains(upperName, "STRIPE") ||
		strings.Contains(upperName, "CHECKOUT") ||
		strings.Contains(upperName, "PAYPLUG") ||
		strings.Contains(upperName, "MOLLIE") ||
		strings.Contains(upperName, "KLARNA") ||
		strings.Contains(upperName, "ADYEN") ||
		strings.Contains(upperName, "BRAINTREE") ||
		strings.Contains(upperName, "AUTHORIZE") ||
		strings.Contains(upperName, "AMAZONPAY") ||
		strings.Contains(upperName, "AMAZON_PAY") ||
		strings.Contains(upperName, "REDSYS") ||
		strings.Contains(upperName, "SQUARE") ||
		strings.Contains(upperName, "VIVA") ||
		strings.Contains(upperName, "HIPAY"):
		return "payment"
	case strings.HasPrefix(upperName, "PS_MAIL_") ||
		strings.Contains(upperName, "SMTP") ||
		strings.Contains(upperName, "MAILCHIMP") ||
		strings.Contains(upperName, "SENDINBLUE") ||
		strings.Contains(upperName, "BREVO"):
		return "mail"
	case strings.Contains(upperName, "SSL") || strings.Contains(upperName, "COOKIE") || strings.Contains(upperName, "TOKEN"):
		return "security"
	case strings.Contains(upperName, "DEBUG") || strings.Contains(upperName, "DEV") || strings.Contains(upperName, "DISPLAY_ERRORS") || strings.Contains(upperName, "MODE_DEV"):
		return "debug"
	case strings.Contains(upperName, "WEBSERVICE") || strings.Contains(upperName, "API"):
		return "api"
	case strings.Contains(upperName, "DOMAIN") || strings.Contains(upperName, "SHOP_URL") || strings.Contains(upperName, "CANONICAL") || strings.Contains(upperName, "REWRITING"):
		return "shop_url"
	case strings.Contains(upperName, "MAINTENANCE") || upperName == "PS_SHOP_ENABLE":
		return "maintenance"
	default:
		return "configuration"
	}
}

func isPrestaShopSensitiveConfiguration(upperName string) bool {
	for _, marker := range []string{"API", "KEY", "PASSWD", "PASSWORD", "PRIVATE", "SECRET", "TOKEN", "WEBHOOK"} {
		if strings.Contains(upperName, marker) {
			return true
		}
	}
	return false
}

func yii2RBACDatabaseCheckSpecs(ctx context.Context, db *sql.DB, engine string, tablePrefix string) ([]databaseCheckSpec, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "")
	dialect := newDatabaseDialect(engine)
	var specs []databaseCheckSpec
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	usersTable := prefix + "users"
	if exists, err := dialect.tableExists(ctx, db, usersTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac users table check failed: %v", err))
	} else if exists {
		specs = append(specs, yii2RBACCountSpec(dialect, usersTable, "users", "yii2-rbac.users.count", ""))
		if hasStatus, err := dialect.columnExists(ctx, db, usersTable, "status"); err != nil {
			warnings = append(warnings, fmt.Sprintf("yii2-rbac users.status check failed: %v", err))
		} else if hasStatus {
			specs = append(specs, yii2RBACCountSpec(dialect, usersTable, "active_users", "yii2-rbac.active_users.count", "WHERE "+dialect.quote("status")+" = 10"))
		}
	}

	rolesTable := prefix + "roles"
	if exists, err := dialect.tableExists(ctx, db, rolesTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac roles table check failed: %v", err))
	} else if exists {
		specs = append(specs, yii2RBACCountSpec(dialect, rolesTable, "roles", "yii2-rbac.roles.count", ""))
		specs = append(specs, yii2RBACCountSpec(dialect, rolesTable, "admin_roles", "yii2-rbac.admin_roles.count", yii2RBACRoleWhere(dialect, "role")))
	}

	authAssignmentTable := prefix + "auth_assignment"
	if exists, err := dialect.tableExists(ctx, db, authAssignmentTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac auth_assignment table check failed: %v", err))
	} else if exists {
		specs = append(specs, yii2RBACCountSpec(dialect, authAssignmentTable, "auth_assignments", "yii2-rbac.auth_assignments.count", ""))
		specs = append(specs, yii2RBACCountSpec(dialect, authAssignmentTable, "admin_auth_assignments", "yii2-rbac.admin_auth_assignments.count", yii2RBACRoleWhere(dialect, "item_name")))
	}

	authItemTable := prefix + "auth_item"
	if exists, err := dialect.tableExists(ctx, db, authItemTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac auth_item table check failed: %v", err))
	} else if exists {
		specs = append(specs, yii2RBACCountSpec(dialect, authItemTable, "rbac_roles", "yii2-rbac.rbac_roles.count", "WHERE "+dialect.quote("type")+" = 1"))
		specs = append(specs, yii2RBACCountSpec(dialect, authItemTable, "rbac_permissions", "yii2-rbac.rbac_permissions.count", "WHERE "+dialect.quote("type")+" = 2"))
	}

	migrationTable := prefix + "migration"
	if exists, err := dialect.tableExists(ctx, db, migrationTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac migration table check failed: %v", err))
	} else if exists {
		specs = append(specs, yii2RBACCountSpec(dialect, migrationTable, "migrations", "yii2-rbac.migrations.count", ""))
	}

	if len(specs) == 0 {
		warnings = append(warnings, "yii2-rbac users, roles, auth_assignment, auth_item, and migration tables were not found")
	}
	return specs, warnings
}

func yii2RBACCountSpec(dialect databaseDialect, table string, metric string, name string, where string) databaseCheckSpec {
	query := "SELECT COUNT(*) FROM " + dialect.quote(table)
	if strings.TrimSpace(where) != "" {
		query += " " + strings.TrimSpace(where)
	}
	return databaseCheckSpec{
		Name:   name,
		Kind:   databaseCheckCount,
		Metric: metric,
		Table:  table,
		Query:  query,
	}
}

func yii2RBACRoleWhere(dialect databaseDialect, column string) string {
	expression := "LOWER(" + dialect.coalesceText(dialect.quote(column)) + ")"
	return "WHERE " + expression + " IN ('admin', 'administrator', 'superadmin', 'super_admin', 'owner') OR " + expression + " LIKE '%admin%'"
}

func collectYii2RBACDatabaseEntities(ctx context.Context, db *sql.DB, engine string, tablePrefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "")
	dialect := newDatabaseDialect(engine)
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	roleAssignments, roleEntities, roleWarnings := collectYii2RBACRoleAssignments(ctx, db, dialect, prefix)
	entities = append(entities, roleEntities...)
	warnings = append(warnings, roleWarnings...)

	userEntities, userWarnings := collectYii2RBACUserEntities(ctx, db, dialect, prefix, roleAssignments, pii)
	entities = append(entities, userEntities...)
	warnings = append(warnings, userWarnings...)

	rbacEntities, rbacWarnings := collectYii2RBACRBACEntities(ctx, db, dialect, prefix)
	entities = append(entities, rbacEntities...)
	warnings = append(warnings, rbacWarnings...)

	sortDatabaseEntities(entities)
	return entities, warnings
}

func collectYii2RBACUserEntities(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string, roleAssignments map[string][]string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	table := prefix + "users"
	exists, err := dialect.tableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("yii2-rbac users table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	if idExists, err := dialect.columnExists(ctx, db, table, "id"); err != nil {
		return nil, []string{fmt.Sprintf("yii2-rbac users.id check failed: %v", err)}
	} else if !idExists {
		return nil, []string{"yii2-rbac users table has no id column"}
	}

	emailExpr, emailWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "email", "u."+dialect.quote("email"))
	loginExpr, loginWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "username", "u."+dialect.quote("username"))
	statusExpr, statusWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "status", "u."+dialect.quote("status"))
	createdExpr, createdWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", "u."+dialect.quote("created_at"))
	updatedExpr, updatedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "updated_at", "u."+dialect.quote("updated_at"))
	warnings := append(emailWarnings, loginWarnings...)
	warnings = append(warnings, statusWarnings...)
	warnings = append(warnings, createdWarnings...)
	warnings = append(warnings, updatedWarnings...)

	query := "SELECT " + dialect.coalesceText("u."+dialect.quote("id")) + ", " +
		dialect.coalesceText(loginExpr) + ", " +
		dialect.coalesceText(emailExpr) + ", " +
		dialect.coalesceText(statusExpr) + ", " +
		dialect.coalesceText(createdExpr) + ", " +
		dialect.coalesceText(updatedExpr) +
		" FROM " + dialect.quote(table) + " u ORDER BY u." + dialect.quote("id") + " LIMIT 1000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("yii2-rbac user entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id string
		var login string
		var email string
		var status string
		var createdAt string
		var updatedAt string
		if err := rows.Scan(&id, &login, &email, &status, &createdAt, &updatedAt); err != nil {
			return entities, append(warnings, fmt.Sprintf("yii2-rbac user entity scan failed: %v", err))
		}
		roles := roleAssignments[strings.TrimSpace(id)]
		entities = append(entities, yii2RBACUserEntity(id, login, email, status, roles, databaseSourceTime(createdAt), databaseSourceTime(updatedAt), pii))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("yii2-rbac user entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectYii2RBACRoleAssignments(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) (map[string][]string, []DatabaseEntityObservation, []string) {
	assignments := map[string][]string{}
	table := prefix + "roles"
	exists, err := dialect.tableExists(ctx, db, table)
	if err != nil {
		return assignments, nil, []string{fmt.Sprintf("yii2-rbac roles table check failed: %v", err)}
	}
	if !exists {
		return assignments, nil, nil
	}
	for _, column := range []string{"id", "user_id", "role"} {
		exists, err := dialect.columnExists(ctx, db, table, column)
		if err != nil {
			return assignments, nil, []string{fmt.Sprintf("yii2-rbac roles.%s check failed: %v", column, err)}
		}
		if !exists {
			return assignments, nil, []string{fmt.Sprintf("yii2-rbac roles table has no %s column", column)}
		}
	}
	createdExpr, createdWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", dialect.quote("created_at"))
	updatedExpr, updatedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "updated_at", dialect.quote("updated_at"))
	warnings := append(createdWarnings, updatedWarnings...)
	query := "SELECT " + dialect.coalesceText(dialect.quote("id")) + ", " +
		dialect.coalesceText(dialect.quote("user_id")) + ", " +
		dialect.coalesceText(dialect.quote("role")) + ", " +
		dialect.coalesceText(createdExpr) + ", " +
		dialect.coalesceText(updatedExpr) +
		" FROM " + dialect.quote(table) + " ORDER BY " + dialect.quote("id") + " LIMIT 2000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return assignments, nil, append(warnings, fmt.Sprintf("yii2-rbac role entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id string
		var userID string
		var role string
		var createdAt string
		var updatedAt string
		if err := rows.Scan(&id, &userID, &role, &createdAt, &updatedAt); err != nil {
			return assignments, entities, append(warnings, fmt.Sprintf("yii2-rbac role entity scan failed: %v", err))
		}
		userID = strings.TrimSpace(userID)
		role = strings.TrimSpace(role)
		if userID != "" && role != "" {
			assignments[userID] = append(assignments[userID], role)
		}
		entities = append(entities, yii2RBACRoleAssignmentEntity(id, userID, role, databaseSourceTime(createdAt), databaseSourceTime(updatedAt)))
	}
	if err := rows.Err(); err != nil {
		return assignments, entities, append(warnings, fmt.Sprintf("yii2-rbac role entity rows failed: %v", err))
	}
	for userID := range assignments {
		sort.Strings(assignments[userID])
	}
	return assignments, entities, warnings
}

func collectYii2RBACRBACEntities(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) ([]DatabaseEntityObservation, []string) {
	var entities []DatabaseEntityObservation
	var warnings []string
	authItemTable := prefix + "auth_item"
	if exists, err := dialect.tableExists(ctx, db, authItemTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac auth_item table check failed: %v", err))
	} else if exists {
		itemEntities, itemWarnings := collectYii2RBACAuthItems(ctx, db, dialect, authItemTable)
		entities = append(entities, itemEntities...)
		warnings = append(warnings, itemWarnings...)
	}
	authAssignmentTable := prefix + "auth_assignment"
	if exists, err := dialect.tableExists(ctx, db, authAssignmentTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("yii2-rbac auth_assignment table check failed: %v", err))
	} else if exists {
		assignmentEntities, assignmentWarnings := collectYii2RBACAuthAssignments(ctx, db, dialect, authAssignmentTable)
		entities = append(entities, assignmentEntities...)
		warnings = append(warnings, assignmentWarnings...)
	}
	return entities, warnings
}

func collectYii2RBACAuthItems(ctx context.Context, db *sql.DB, dialect databaseDialect, table string) ([]DatabaseEntityObservation, []string) {
	for _, column := range []string{"name", "type"} {
		exists, err := dialect.columnExists(ctx, db, table, column)
		if err != nil {
			return nil, []string{fmt.Sprintf("yii2-rbac auth_item.%s check failed: %v", column, err)}
		}
		if !exists {
			return nil, []string{fmt.Sprintf("yii2-rbac auth_item table has no %s column", column)}
		}
	}
	createdExpr, createdWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", dialect.quote("created_at"))
	updatedExpr, updatedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "updated_at", dialect.quote("updated_at"))
	warnings := append(createdWarnings, updatedWarnings...)
	query := "SELECT " + dialect.coalesceText(dialect.quote("name")) + ", " +
		dialect.coalesceText(dialect.quote("type")) + ", " +
		dialect.coalesceText(createdExpr) + ", " +
		dialect.coalesceText(updatedExpr) +
		" FROM " + dialect.quote(table) + " ORDER BY " + dialect.quote("name") + " LIMIT 2000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("yii2-rbac auth_item entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var name string
		var itemType string
		var createdAt string
		var updatedAt string
		if err := rows.Scan(&name, &itemType, &createdAt, &updatedAt); err != nil {
			return entities, append(warnings, fmt.Sprintf("yii2-rbac auth_item entity scan failed: %v", err))
		}
		entities = append(entities, yii2RBACRBACItemEntity(name, itemType, databaseSourceTime(createdAt), databaseSourceTime(updatedAt)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("yii2-rbac auth_item entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectYii2RBACAuthAssignments(ctx context.Context, db *sql.DB, dialect databaseDialect, table string) ([]DatabaseEntityObservation, []string) {
	for _, column := range []string{"item_name", "user_id"} {
		exists, err := dialect.columnExists(ctx, db, table, column)
		if err != nil {
			return nil, []string{fmt.Sprintf("yii2-rbac auth_assignment.%s check failed: %v", column, err)}
		}
		if !exists {
			return nil, []string{fmt.Sprintf("yii2-rbac auth_assignment table has no %s column", column)}
		}
	}
	createdExpr, warnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", dialect.quote("created_at"))
	query := "SELECT " + dialect.coalesceText(dialect.quote("item_name")) + ", " +
		dialect.coalesceText(dialect.quote("user_id")) + ", " +
		dialect.coalesceText(createdExpr) +
		" FROM " + dialect.quote(table) + " ORDER BY " + dialect.quote("item_name") + ", " + dialect.quote("user_id") + " LIMIT 2000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("yii2-rbac auth_assignment entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var itemName string
		var userID string
		var createdAt string
		if err := rows.Scan(&itemName, &userID, &createdAt); err != nil {
			return entities, append(warnings, fmt.Sprintf("yii2-rbac auth_assignment entity scan failed: %v", err))
		}
		entities = append(entities, yii2RBACRBACAssignmentEntity(itemName, userID, databaseSourceTime(createdAt)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("yii2-rbac auth_assignment entity rows failed: %v", err))
	}
	return entities, warnings
}

func yii2RBACOptionalColumnExpression(ctx context.Context, db *sql.DB, dialect databaseDialect, table string, column string, expression string) (string, []string) {
	exists, err := dialect.columnExists(ctx, db, table, column)
	switch {
	case err != nil:
		return "''", []string{fmt.Sprintf("%s.%s column check failed: %v", table, column, err)}
	case exists:
		return expression, nil
	default:
		return "''", nil
	}
}

func yii2RBACUserEntity(id string, login string, email string, status string, roles []string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time, pii databasePIIProtector) DatabaseEntityObservation {
	id = strings.TrimSpace(id)
	login = strings.TrimSpace(login)
	email = strings.TrimSpace(email)
	status = strings.TrimSpace(status)
	roles = normalizeRoleList(roles)
	admin := yii2RBACRolesPrivileged(roles)
	accountDisplay := databaseAccountDisplay(login, email)
	attributes := map[string]any{
		"user_id_hash": databaseSHA256Hex(id),
		"role_count":   len(roles),
		"roles_sha256": databaseSHA256Hex(strings.Join(roles, "\n")),
		"admin_role":   admin,
	}
	if len(roles) > 0 {
		attributes["roles"] = roles
	}
	if status != "" {
		attributes["status"] = status
		attributes["active"] = status == "10"
	}
	if accountDisplay != "" {
		attributes["account_display"] = accountDisplay
	}
	if normalized := databaseNormalizeEmail(email); normalized != "" {
		attributes["email"] = normalized
	}
	if normalized := databaseNormalizeIdentifier(login); normalized != "" {
		attributes["login"] = normalized
	}
	if masked := databaseMaskEmail(email); masked != "" {
		attributes["email_masked"] = masked
	}
	if masked := databaseMaskIdentifier(login); masked != "" {
		attributes["login_masked"] = masked
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeEmail(email)); fingerprint != "" {
		attributes["email_hmac_sha256"] = fingerprint
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeIdentifier(login)); fingerprint != "" {
		attributes["login_hmac_sha256"] = fingerprint
	}
	entity := DatabaseEntityObservation{
		Type:            "yii2_rbac_user",
		Key:             databaseEntityKey("yii2_rbac_user", id),
		Label:           databaseDisplayLabel("yii2_rbac_user", accountDisplay, id),
		Privileged:      admin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes:      attributes,
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func yii2RBACRoleAssignmentEntity(id string, userID string, role string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	role = strings.TrimSpace(role)
	userID = strings.TrimSpace(userID)
	admin := yii2RBACRolePrivileged(role)
	entity := DatabaseEntityObservation{
		Type:            "yii2_rbac_role_assignment",
		Key:             databaseEntityKey("yii2_rbac_role_assignment", id+"\x00"+userID+"\x00"+role),
		Label:           databaseDisplayLabel("yii2_rbac_role_assignment", role, id),
		Privileged:      admin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"user_id_hash": databaseSHA256Hex(userID),
			"role":         role,
			"role_sha256":  databaseSHA256Hex(role),
			"admin_role":   admin,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func yii2RBACRBACItemEntity(name string, itemType string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	name = strings.TrimSpace(name)
	itemType = strings.TrimSpace(itemType)
	admin := yii2RBACRolePrivileged(name)
	entity := DatabaseEntityObservation{
		Type:            "yii2_rbac_item",
		Key:             databaseEntityKey("yii2_rbac_item", itemType+"\x00"+name),
		Label:           databaseDisplayLabel("yii2_rbac_item", name, itemType),
		Privileged:      admin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"name":        name,
			"name_sha256": databaseSHA256Hex(name),
			"item_type":   itemType,
			"admin_like":  admin,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func yii2RBACRBACAssignmentEntity(itemName string, userID string, sourceCreatedAt time.Time) DatabaseEntityObservation {
	itemName = strings.TrimSpace(itemName)
	userID = strings.TrimSpace(userID)
	admin := yii2RBACRolePrivileged(itemName)
	entity := DatabaseEntityObservation{
		Type:            "yii2_rbac_assignment",
		Key:             databaseEntityKey("yii2_rbac_assignment", itemName+"\x00"+userID),
		Label:           databaseDisplayLabel("yii2_rbac_assignment", itemName, userID),
		Privileged:      admin,
		SourceCreatedAt: sourceCreatedAt,
		Attributes: map[string]any{
			"user_id_hash": databaseSHA256Hex(userID),
			"item_name":    itemName,
			"item_sha256":  databaseSHA256Hex(itemName),
			"admin_role":   admin,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func normalizeRoleList(values []string) []string {
	seen := map[string]struct{}{}
	roles := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roles = append(roles, value)
	}
	sort.Strings(roles)
	return roles
}

func yii2RBACRolesPrivileged(roles []string) bool {
	for _, role := range roles {
		if yii2RBACRolePrivileged(role) {
			return true
		}
	}
	return false
}

func yii2RBACRolePrivileged(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case "admin", "administrator", "superadmin", "super_admin", "owner":
		return true
	default:
		return strings.Contains(role, "admin")
	}
}

func laravelDatabaseCheckSpecs(ctx context.Context, db *sql.DB, engine string, tablePrefix string) ([]databaseCheckSpec, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "")
	dialect := newDatabaseDialect(engine)
	var specs []databaseCheckSpec
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	usersTable := prefix + "users"
	if exists, err := dialect.tableExists(ctx, db, usersTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("laravel users table check failed: %v", err))
	} else if exists {
		specs = append(specs, laravelCountSpec(dialect, usersTable, "users", "laravel.users.count", ""))
		if hasActive, err := dialect.columnExists(ctx, db, usersTable, "active"); err != nil {
			warnings = append(warnings, fmt.Sprintf("laravel users.active check failed: %v", err))
		} else if hasActive {
			specs = append(specs, laravelCountSpec(dialect, usersTable, "active_users", "laravel.active_users.count", "WHERE "+dialect.quote("active")+" = TRUE"))
		}
		if hasVerified, err := dialect.columnExists(ctx, db, usersTable, "email_verified_at"); err != nil {
			warnings = append(warnings, fmt.Sprintf("laravel users.email_verified_at check failed: %v", err))
		} else if hasVerified {
			specs = append(specs, laravelCountSpec(dialect, usersTable, "verified_users", "laravel.verified_users.count", "WHERE "+dialect.quote("email_verified_at")+" IS NOT NULL"))
		}
	}

	rolesTable := prefix + "roles"
	if exists, err := dialect.tableExists(ctx, db, rolesTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("laravel roles table check failed: %v", err))
	} else if exists {
		specs = append(specs, laravelCountSpec(dialect, rolesTable, "roles", "laravel.roles.count", ""))
		specs = append(specs, laravelCountSpec(dialect, rolesTable, "admin_roles", "laravel.admin_roles.count", laravelNameWhere(dialect, "name")))
	}

	permissionsTable := prefix + "permissions"
	if exists, err := dialect.tableExists(ctx, db, permissionsTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("laravel permissions table check failed: %v", err))
	} else if exists {
		specs = append(specs, laravelCountSpec(dialect, permissionsTable, "permissions", "laravel.permissions.count", ""))
		specs = append(specs, laravelCountSpec(dialect, permissionsTable, "sensitive_permissions", "laravel.sensitive_permissions.count", laravelSensitivePermissionWhere(dialect, "name")))
	}

	modelRolesTable := prefix + "model_has_roles"
	if exists, err := dialect.tableExists(ctx, db, modelRolesTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("laravel model_has_roles table check failed: %v", err))
	} else if exists {
		specs = append(specs, laravelCountSpec(dialect, modelRolesTable, "role_assignments", "laravel.role_assignments.count", ""))
		if rolesExists, err := dialect.tableExists(ctx, db, rolesTable); err != nil {
			warnings = append(warnings, fmt.Sprintf("laravel roles table check failed: %v", err))
		} else if rolesExists {
			query := "SELECT COUNT(*) FROM " + dialect.quote(modelRolesTable) + " mr JOIN " + dialect.quote(rolesTable) + " r ON r." + dialect.quote("id") + " = mr." + dialect.quote("role_id") + " " + laravelNameWhereWithExpression(dialect.coalesceText("r."+dialect.quote("name")))
			specs = append(specs, databaseCheckSpec{Name: "laravel.admin_role_assignments.count", Kind: databaseCheckCount, Metric: "admin_role_assignments", Table: modelRolesTable, Query: query})
		}
	}

	modelPermissionsTable := prefix + "model_has_permissions"
	if exists, err := dialect.tableExists(ctx, db, modelPermissionsTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("laravel model_has_permissions table check failed: %v", err))
	} else if exists {
		specs = append(specs, laravelCountSpec(dialect, modelPermissionsTable, "direct_permission_assignments", "laravel.direct_permission_assignments.count", ""))
	}

	rolePermissionsTable := prefix + "role_has_permissions"
	if exists, err := dialect.tableExists(ctx, db, rolePermissionsTable); err != nil {
		warnings = append(warnings, fmt.Sprintf("laravel role_has_permissions table check failed: %v", err))
	} else if exists {
		specs = append(specs, laravelCountSpec(dialect, rolePermissionsTable, "role_permissions", "laravel.role_permissions.count", ""))
	}

	for _, tableSpec := range []struct {
		table  string
		metric string
		name   string
	}{
		{prefix + "migrations", "migrations", "laravel.migrations.count"},
		{prefix + "password_reset_tokens", "password_reset_tokens", "laravel.password_reset_tokens.count"},
		{prefix + "sessions", "sessions", "laravel.sessions.count"},
		{prefix + "failed_jobs", "failed_jobs", "laravel.failed_jobs.count"},
		{prefix + "activity_log", "activity_log", "laravel.activity_log.count"},
	} {
		if exists, err := dialect.tableExists(ctx, db, tableSpec.table); err != nil {
			warnings = append(warnings, fmt.Sprintf("laravel %s table check failed: %v", tableSpec.table, err))
		} else if exists {
			specs = append(specs, laravelCountSpec(dialect, tableSpec.table, tableSpec.metric, tableSpec.name, ""))
		}
	}

	if len(specs) == 0 {
		warnings = append(warnings, "laravel users, roles, permissions, model_has_roles, role_has_permissions, and migrations tables were not found")
	}
	return specs, warnings
}

func laravelCountSpec(dialect databaseDialect, table string, metric string, name string, where string) databaseCheckSpec {
	query := "SELECT COUNT(*) FROM " + dialect.quote(table)
	if strings.TrimSpace(where) != "" {
		query += " " + strings.TrimSpace(where)
	}
	return databaseCheckSpec{Name: name, Kind: databaseCheckCount, Metric: metric, Table: table, Query: query}
}

func laravelNameWhere(dialect databaseDialect, column string) string {
	return laravelNameWhereWithExpression(dialect.coalesceText(dialect.quote(column)))
}

func laravelNameWhereWithExpression(expression string) string {
	lowered := "LOWER(" + expression + ")"
	return "WHERE " + lowered + " IN ('admin', 'administrator', 'superadmin', 'super_admin', 'super-admin', 'owner') OR " + lowered + " LIKE '%admin%'"
}

func laravelSensitivePermissionWhere(dialect databaseDialect, column string) string {
	lowered := "LOWER(" + dialect.coalesceText(dialect.quote(column)) + ")"
	return "WHERE " + lowered + " LIKE '%permission%' OR " + lowered + " LIKE '%role%' OR " + lowered + " LIKE '%user%' OR " + lowered + " LIKE '%admin%'"
}

func collectLaravelDatabaseEntities(ctx context.Context, db *sql.DB, engine string, tablePrefix string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "")
	dialect := newDatabaseDialect(engine)
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	roleAssignments, assignmentEntities, assignmentWarnings := collectLaravelRoleAssignments(ctx, db, dialect, prefix)
	entities = append(entities, assignmentEntities...)
	warnings = append(warnings, assignmentWarnings...)

	userEntities, userWarnings := collectLaravelUserEntities(ctx, db, dialect, prefix, roleAssignments, pii)
	entities = append(entities, userEntities...)
	warnings = append(warnings, userWarnings...)

	roleEntities, roleWarnings := collectLaravelRoleEntities(ctx, db, dialect, prefix)
	entities = append(entities, roleEntities...)
	warnings = append(warnings, roleWarnings...)

	permissionEntities, permissionWarnings := collectLaravelPermissionEntities(ctx, db, dialect, prefix)
	entities = append(entities, permissionEntities...)
	warnings = append(warnings, permissionWarnings...)

	rolePermissionEntities, rolePermissionWarnings := collectLaravelRolePermissionEntities(ctx, db, dialect, prefix)
	entities = append(entities, rolePermissionEntities...)
	warnings = append(warnings, rolePermissionWarnings...)

	directPermissionEntities, directPermissionWarnings := collectLaravelDirectPermissionAssignments(ctx, db, dialect, prefix)
	entities = append(entities, directPermissionEntities...)
	warnings = append(warnings, directPermissionWarnings...)

	sortDatabaseEntities(entities)
	return entities, warnings
}

func collectLaravelUserEntities(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string, roleAssignments map[string][]string, pii databasePIIProtector) ([]DatabaseEntityObservation, []string) {
	table := prefix + "users"
	exists, err := dialect.tableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("laravel users table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	if idExists, err := dialect.columnExists(ctx, db, table, "id"); err != nil {
		return nil, []string{fmt.Sprintf("laravel users.id check failed: %v", err)}
	} else if !idExists {
		return nil, []string{"laravel users table has no id column"}
	}

	nameExpr, nameWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "name", "u."+dialect.quote("name"))
	emailExpr, emailWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "email", "u."+dialect.quote("email"))
	activeExpr, activeWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "active", "u."+dialect.quote("active"))
	verifiedExpr, verifiedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "email_verified_at", "u."+dialect.quote("email_verified_at"))
	lastLoginExpr, lastLoginWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "last_login_at", "u."+dialect.quote("last_login_at"))
	lastLoginIPExpr, lastLoginIPWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "last_login_ip", "u."+dialect.quote("last_login_ip"))
	createdExpr, createdWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", "u."+dialect.quote("created_at"))
	updatedExpr, updatedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "updated_at", "u."+dialect.quote("updated_at"))
	warnings := append(nameWarnings, emailWarnings...)
	warnings = append(warnings, activeWarnings...)
	warnings = append(warnings, verifiedWarnings...)
	warnings = append(warnings, lastLoginWarnings...)
	warnings = append(warnings, lastLoginIPWarnings...)
	warnings = append(warnings, createdWarnings...)
	warnings = append(warnings, updatedWarnings...)

	query := "SELECT " + dialect.coalesceText("u."+dialect.quote("id")) + ", " +
		dialect.coalesceText(nameExpr) + ", " +
		dialect.coalesceText(emailExpr) + ", " +
		dialect.coalesceText(activeExpr) + ", " +
		dialect.coalesceText(verifiedExpr) + ", " +
		dialect.coalesceText(lastLoginExpr) + ", " +
		dialect.coalesceText(lastLoginIPExpr) + ", " +
		dialect.coalesceText(createdExpr) + ", " +
		dialect.coalesceText(updatedExpr) +
		" FROM " + dialect.quote(table) + " u ORDER BY u." + dialect.quote("id") + " LIMIT 1000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("laravel user entity query failed: %v", err))
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id, name, email, active, verifiedAt, lastLoginAt, lastLoginIP, createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &email, &active, &verifiedAt, &lastLoginAt, &lastLoginIP, &createdAt, &updatedAt); err != nil {
			return entities, append(warnings, fmt.Sprintf("laravel user entity scan failed: %v", err))
		}
		roles := roleAssignments[strings.TrimSpace(id)]
		entities = append(entities, laravelUserEntity(id, name, email, active, verifiedAt, lastLoginAt, lastLoginIP, roles, databaseSourceTime(createdAt), databaseSourceTime(updatedAt), pii))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("laravel user entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectLaravelRoleAssignments(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) (map[string][]string, []DatabaseEntityObservation, []string) {
	assignments := map[string][]string{}
	rolesTable := prefix + "roles"
	modelRolesTable := prefix + "model_has_roles"
	for _, table := range []string{rolesTable, modelRolesTable} {
		exists, err := dialect.tableExists(ctx, db, table)
		if err != nil {
			return assignments, nil, []string{fmt.Sprintf("laravel %s table check failed: %v", table, err)}
		}
		if !exists {
			return assignments, nil, nil
		}
	}
	for table, columns := range map[string][]string{
		rolesTable:      {"id", "name"},
		modelRolesTable: {"role_id", "model_id", "model_type"},
	} {
		for _, column := range columns {
			exists, err := dialect.columnExists(ctx, db, table, column)
			if err != nil {
				return assignments, nil, []string{fmt.Sprintf("laravel %s.%s check failed: %v", table, column, err)}
			}
			if !exists {
				return assignments, nil, []string{fmt.Sprintf("laravel %s table has no %s column", table, column)}
			}
		}
	}
	query := "SELECT " + dialect.coalesceText("mr."+dialect.quote("model_id")) + ", " +
		dialect.coalesceText("mr."+dialect.quote("model_type")) + ", " +
		dialect.coalesceText("r."+dialect.quote("name")) + ", " +
		dialect.coalesceText("r."+dialect.quote("id")) +
		" FROM " + dialect.quote(modelRolesTable) + " mr JOIN " + dialect.quote(rolesTable) + " r ON r." + dialect.quote("id") + " = mr." + dialect.quote("role_id") +
		" WHERE LOWER(" + dialect.coalesceText("mr."+dialect.quote("model_type")) + ") LIKE '%user%' ORDER BY mr." + dialect.quote("model_id") + ", r." + dialect.quote("name") + " LIMIT 5000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return assignments, nil, []string{fmt.Sprintf("laravel role assignment query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var userID, modelType, role, roleID string
		if err := rows.Scan(&userID, &modelType, &role, &roleID); err != nil {
			return assignments, entities, []string{fmt.Sprintf("laravel role assignment scan failed: %v", err)}
		}
		userID = strings.TrimSpace(userID)
		role = strings.TrimSpace(role)
		if userID != "" && role != "" {
			assignments[userID] = append(assignments[userID], role)
		}
		entities = append(entities, laravelRoleAssignmentEntity(userID, roleID, role, modelType))
	}
	if err := rows.Err(); err != nil {
		return assignments, entities, []string{fmt.Sprintf("laravel role assignment rows failed: %v", err)}
	}
	for userID := range assignments {
		sort.Strings(assignments[userID])
	}
	return assignments, entities, nil
}

func collectLaravelRoleEntities(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) ([]DatabaseEntityObservation, []string) {
	table := prefix + "roles"
	exists, err := dialect.tableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("laravel roles table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	for _, column := range []string{"id", "name"} {
		exists, err := dialect.columnExists(ctx, db, table, column)
		if err != nil {
			return nil, []string{fmt.Sprintf("laravel roles.%s check failed: %v", column, err)}
		}
		if !exists {
			return nil, []string{fmt.Sprintf("laravel roles table has no %s column", column)}
		}
	}
	guardExpr, guardWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "guard_name", dialect.quote("guard_name"))
	createdExpr, createdWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", dialect.quote("created_at"))
	updatedExpr, updatedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "updated_at", dialect.quote("updated_at"))
	warnings := append(guardWarnings, createdWarnings...)
	warnings = append(warnings, updatedWarnings...)
	query := "SELECT " + dialect.coalesceText(dialect.quote("id")) + ", " +
		dialect.coalesceText(dialect.quote("name")) + ", " +
		dialect.coalesceText(guardExpr) + ", " +
		dialect.coalesceText(createdExpr) + ", " +
		dialect.coalesceText(updatedExpr) +
		" FROM " + dialect.quote(table) + " ORDER BY " + dialect.quote("name") + " LIMIT 2000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("laravel role entity query failed: %v", err))
	}
	defer rows.Close()
	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id, name, guard, createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &guard, &createdAt, &updatedAt); err != nil {
			return entities, append(warnings, fmt.Sprintf("laravel role entity scan failed: %v", err))
		}
		entities = append(entities, laravelRoleEntity(id, name, guard, databaseSourceTime(createdAt), databaseSourceTime(updatedAt)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("laravel role entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectLaravelPermissionEntities(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) ([]DatabaseEntityObservation, []string) {
	table := prefix + "permissions"
	exists, err := dialect.tableExists(ctx, db, table)
	if err != nil {
		return nil, []string{fmt.Sprintf("laravel permissions table check failed: %v", err)}
	}
	if !exists {
		return nil, nil
	}
	for _, column := range []string{"id", "name"} {
		exists, err := dialect.columnExists(ctx, db, table, column)
		if err != nil {
			return nil, []string{fmt.Sprintf("laravel permissions.%s check failed: %v", column, err)}
		}
		if !exists {
			return nil, []string{fmt.Sprintf("laravel permissions table has no %s column", column)}
		}
	}
	guardExpr, guardWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "guard_name", dialect.quote("guard_name"))
	createdExpr, createdWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "created_at", dialect.quote("created_at"))
	updatedExpr, updatedWarnings := yii2RBACOptionalColumnExpression(ctx, db, dialect, table, "updated_at", dialect.quote("updated_at"))
	warnings := append(guardWarnings, createdWarnings...)
	warnings = append(warnings, updatedWarnings...)
	query := "SELECT " + dialect.coalesceText(dialect.quote("id")) + ", " +
		dialect.coalesceText(dialect.quote("name")) + ", " +
		dialect.coalesceText(guardExpr) + ", " +
		dialect.coalesceText(createdExpr) + ", " +
		dialect.coalesceText(updatedExpr) +
		" FROM " + dialect.quote(table) + " ORDER BY " + dialect.quote("name") + " LIMIT 5000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, append(warnings, fmt.Sprintf("laravel permission entity query failed: %v", err))
	}
	defer rows.Close()
	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id, name, guard, createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &guard, &createdAt, &updatedAt); err != nil {
			return entities, append(warnings, fmt.Sprintf("laravel permission entity scan failed: %v", err))
		}
		entities = append(entities, laravelPermissionEntity(id, name, guard, databaseSourceTime(createdAt), databaseSourceTime(updatedAt)))
	}
	if err := rows.Err(); err != nil {
		return entities, append(warnings, fmt.Sprintf("laravel permission entity rows failed: %v", err))
	}
	return entities, warnings
}

func collectLaravelRolePermissionEntities(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) ([]DatabaseEntityObservation, []string) {
	rolesTable := prefix + "roles"
	permissionsTable := prefix + "permissions"
	rolePermissionsTable := prefix + "role_has_permissions"
	for _, table := range []string{rolesTable, permissionsTable, rolePermissionsTable} {
		exists, err := dialect.tableExists(ctx, db, table)
		if err != nil {
			return nil, []string{fmt.Sprintf("laravel %s table check failed: %v", table, err)}
		}
		if !exists {
			return nil, nil
		}
	}
	query := "SELECT " + dialect.coalesceText("r."+dialect.quote("id")) + ", " +
		dialect.coalesceText("r."+dialect.quote("name")) + ", " +
		dialect.coalesceText("p."+dialect.quote("id")) + ", " +
		dialect.coalesceText("p."+dialect.quote("name")) +
		" FROM " + dialect.quote(rolePermissionsTable) + " rp JOIN " + dialect.quote(rolesTable) + " r ON r." + dialect.quote("id") + " = rp." + dialect.quote("role_id") +
		" JOIN " + dialect.quote(permissionsTable) + " p ON p." + dialect.quote("id") + " = rp." + dialect.quote("permission_id") +
		" ORDER BY r." + dialect.quote("name") + ", p." + dialect.quote("name") + " LIMIT 10000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, []string{fmt.Sprintf("laravel role permission query failed: %v", err)}
	}
	defer rows.Close()
	var entities []DatabaseEntityObservation
	for rows.Next() {
		var roleID, role, permissionID, permission string
		if err := rows.Scan(&roleID, &role, &permissionID, &permission); err != nil {
			return entities, []string{fmt.Sprintf("laravel role permission scan failed: %v", err)}
		}
		entities = append(entities, laravelRolePermissionEntity(roleID, role, permissionID, permission))
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("laravel role permission rows failed: %v", err)}
	}
	return entities, nil
}

func collectLaravelDirectPermissionAssignments(ctx context.Context, db *sql.DB, dialect databaseDialect, prefix string) ([]DatabaseEntityObservation, []string) {
	permissionsTable := prefix + "permissions"
	modelPermissionsTable := prefix + "model_has_permissions"
	for _, table := range []string{permissionsTable, modelPermissionsTable} {
		exists, err := dialect.tableExists(ctx, db, table)
		if err != nil {
			return nil, []string{fmt.Sprintf("laravel %s table check failed: %v", table, err)}
		}
		if !exists {
			return nil, nil
		}
	}
	query := "SELECT " + dialect.coalesceText("mp."+dialect.quote("model_id")) + ", " +
		dialect.coalesceText("mp."+dialect.quote("model_type")) + ", " +
		dialect.coalesceText("p."+dialect.quote("id")) + ", " +
		dialect.coalesceText("p."+dialect.quote("name")) +
		" FROM " + dialect.quote(modelPermissionsTable) + " mp JOIN " + dialect.quote(permissionsTable) + " p ON p." + dialect.quote("id") + " = mp." + dialect.quote("permission_id") +
		" WHERE LOWER(" + dialect.coalesceText("mp."+dialect.quote("model_type")) + ") LIKE '%user%' ORDER BY mp." + dialect.quote("model_id") + ", p." + dialect.quote("name") + " LIMIT 5000"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, []string{fmt.Sprintf("laravel direct permission query failed: %v", err)}
	}
	defer rows.Close()
	var entities []DatabaseEntityObservation
	for rows.Next() {
		var userID, modelType, permissionID, permission string
		if err := rows.Scan(&userID, &modelType, &permissionID, &permission); err != nil {
			return entities, []string{fmt.Sprintf("laravel direct permission scan failed: %v", err)}
		}
		entities = append(entities, laravelPermissionAssignmentEntity(userID, modelType, permissionID, permission))
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("laravel direct permission rows failed: %v", err)}
	}
	return entities, nil
}

func laravelUserEntity(id string, name string, email string, active string, verifiedAt string, lastLoginAt string, lastLoginIP string, roles []string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time, pii databasePIIProtector) DatabaseEntityObservation {
	id = strings.TrimSpace(id)
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	roles = normalizeRoleList(roles)
	admin := yii2RBACRolesPrivileged(roles)
	accountDisplay := databaseAccountDisplay(name, email)
	attributes := map[string]any{
		"user_id_hash": databaseSHA256Hex(id),
		"role_count":   len(roles),
		"roles_sha256": databaseSHA256Hex(strings.Join(roles, "\n")),
		"admin_role":   admin,
	}
	if len(roles) > 0 {
		attributes["roles"] = roles
	}
	if parsed, ok := parsePrestaShopBool(active); ok {
		attributes["active"] = parsed
	}
	if !databaseSourceTime(verifiedAt).IsZero() {
		attributes["email_verified"] = true
	}
	if !databaseSourceTime(lastLoginAt).IsZero() {
		attributes["last_login_at"] = databaseSourceTime(lastLoginAt).Format(time.RFC3339)
	}
	if lastLoginIP = strings.TrimSpace(lastLoginIP); lastLoginIP != "" {
		attributes["last_login_ip_sha256"] = databaseSHA256Hex(lastLoginIP)
	}
	if fingerprint := pii.Fingerprint(lastLoginIP); fingerprint != "" {
		attributes["last_login_ip_hmac_sha256"] = fingerprint
	}
	if accountDisplay != "" {
		attributes["account_display"] = accountDisplay
	}
	if normalized := databaseNormalizeEmail(email); normalized != "" {
		attributes["email"] = normalized
	}
	if normalized := databaseNormalizeIdentifier(name); normalized != "" {
		attributes["name"] = normalized
	}
	if masked := databaseMaskEmail(email); masked != "" {
		attributes["email_masked"] = masked
	}
	if fingerprint := pii.Fingerprint(databaseNormalizeEmail(email)); fingerprint != "" {
		attributes["email_hmac_sha256"] = fingerprint
	}
	entity := DatabaseEntityObservation{
		Type:            "laravel_user",
		Key:             databaseEntityKey("laravel_user", id),
		Label:           databaseDisplayLabel("laravel_user", accountDisplay, id),
		Privileged:      admin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes:      attributes,
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func laravelRoleEntity(id string, name string, guard string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	name = strings.TrimSpace(name)
	admin := yii2RBACRolePrivileged(name)
	entity := DatabaseEntityObservation{
		Type:            "laravel_role",
		Key:             databaseEntityKey("laravel_role", id),
		Label:           databaseDisplayLabel("laravel_role", name, id),
		Privileged:      admin,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"name":        name,
			"name_sha256": databaseSHA256Hex(name),
			"guard":       strings.TrimSpace(guard),
			"admin_role":  admin,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func laravelPermissionEntity(id string, name string, guard string, sourceCreatedAt time.Time, sourceUpdatedAt time.Time) DatabaseEntityObservation {
	name = strings.TrimSpace(name)
	sensitive := laravelPermissionPrivileged(name)
	entity := DatabaseEntityObservation{
		Type:            "laravel_permission",
		Key:             databaseEntityKey("laravel_permission", id),
		Label:           databaseDisplayLabel("laravel_permission", name, id),
		Privileged:      sensitive,
		SourceCreatedAt: sourceCreatedAt,
		SourceUpdatedAt: sourceUpdatedAt,
		Attributes: map[string]any{
			"name":         name,
			"name_sha256":  databaseSHA256Hex(name),
			"guard":        strings.TrimSpace(guard),
			"sensitive":    sensitive,
			"access_scope": laravelPermissionScope(name),
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func laravelRoleAssignmentEntity(userID string, roleID string, role string, modelType string) DatabaseEntityObservation {
	role = strings.TrimSpace(role)
	admin := yii2RBACRolePrivileged(role)
	entity := DatabaseEntityObservation{
		Type:       "laravel_role_assignment",
		Key:        databaseEntityKey("laravel_role_assignment", strings.TrimSpace(userID)+"\x00"+strings.TrimSpace(roleID)+"\x00"+role),
		Label:      databaseDisplayLabel("laravel_role_assignment", role, userID),
		Privileged: admin,
		Attributes: map[string]any{
			"user_id_hash": databaseSHA256Hex(userID),
			"role_id_hash": databaseSHA256Hex(roleID),
			"role":         role,
			"role_sha256":  databaseSHA256Hex(role),
			"model_type":   strings.TrimSpace(modelType),
			"admin_role":   admin,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func laravelRolePermissionEntity(roleID string, role string, permissionID string, permission string) DatabaseEntityObservation {
	role = strings.TrimSpace(role)
	permission = strings.TrimSpace(permission)
	privileged := yii2RBACRolePrivileged(role) || laravelPermissionPrivileged(permission)
	entity := DatabaseEntityObservation{
		Type:       "laravel_role_permission",
		Key:        databaseEntityKey("laravel_role_permission", strings.TrimSpace(roleID)+"\x00"+strings.TrimSpace(permissionID)),
		Label:      databaseDisplayLabel("laravel_role_permission", role+" -> "+permission, roleID),
		Privileged: privileged,
		Attributes: map[string]any{
			"role_id_hash":       databaseSHA256Hex(roleID),
			"permission_id_hash": databaseSHA256Hex(permissionID),
			"role":               role,
			"role_sha256":        databaseSHA256Hex(role),
			"permission":         permission,
			"permission_sha256":  databaseSHA256Hex(permission),
			"privileged":         privileged,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func laravelPermissionAssignmentEntity(userID string, modelType string, permissionID string, permission string) DatabaseEntityObservation {
	permission = strings.TrimSpace(permission)
	privileged := laravelPermissionPrivileged(permission)
	entity := DatabaseEntityObservation{
		Type:       "laravel_permission_assignment",
		Key:        databaseEntityKey("laravel_permission_assignment", strings.TrimSpace(userID)+"\x00"+strings.TrimSpace(permissionID)),
		Label:      databaseDisplayLabel("laravel_permission_assignment", permission, userID),
		Privileged: privileged,
		Attributes: map[string]any{
			"user_id_hash":       databaseSHA256Hex(userID),
			"permission_id_hash": databaseSHA256Hex(permissionID),
			"permission":         permission,
			"permission_sha256":  databaseSHA256Hex(permission),
			"model_type":         strings.TrimSpace(modelType),
			"privileged":         privileged,
		},
	}
	entity.Signature = databaseEntitySignature(entity)
	return entity
}

func laravelPermissionPrivileged(permission string) bool {
	scope := laravelPermissionScope(permission)
	return scope == "admin" || scope == "users" || scope == "roles" || scope == "permissions"
}

func laravelPermissionScope(permission string) string {
	value := strings.ToLower(strings.TrimSpace(permission))
	switch {
	case strings.Contains(value, "permission"):
		return "permissions"
	case strings.Contains(value, "role"):
		return "roles"
	case strings.Contains(value, "user"):
		return "users"
	case strings.Contains(value, "admin"):
		return "admin"
	case strings.Contains(value, "report"):
		return "reports"
	case strings.Contains(value, "import"):
		return "imports"
	default:
		return "application"
	}
}

func parsePrestaShopBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true, true
	case "0", "false", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func queryDatabaseCount(ctx context.Context, db *sql.DB, spec databaseCheckSpec) (int64, error) {
	var count int64
	if err := db.QueryRowContext(ctx, spec.Query, spec.Args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func queryDatabaseString(ctx context.Context, db *sql.DB, spec databaseCheckSpec) (string, bool, error) {
	var value sql.NullString
	err := db.QueryRowContext(ctx, spec.Query, spec.Args...).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !value.Valid {
		return "", true, nil
	}
	return value.String, true, nil
}

func databaseTableExists(ctx context.Context, db *sql.DB, table string) (bool, error) {
	var count int64
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", table).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

type databaseDialect struct {
	engine string
}

func newDatabaseDialect(engine string) databaseDialect {
	return databaseDialect{engine: normalizeDatabaseEngine(engine)}
}

func (d databaseDialect) postgres() bool {
	return isPostgresFamily(d.engine)
}

func (d databaseDialect) quote(value string) string {
	value = strings.TrimSpace(value)
	if d.postgres() {
		return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	}
	return quoteDatabaseIdentifier(value)
}

func (d databaseDialect) placeholder(index int) string {
	if d.postgres() {
		return "$" + strconv.Itoa(index)
	}
	return "?"
}

func (d databaseDialect) castText(expression string) string {
	if d.postgres() {
		return "CAST(" + expression + " AS TEXT)"
	}
	return "CAST(" + expression + " AS CHAR)"
}

func (d databaseDialect) coalesceText(expression string) string {
	return "COALESCE(" + d.castText(expression) + ", '')"
}

func (d databaseDialect) tableExists(ctx context.Context, db *sql.DB, table string) (bool, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		return false, nil
	}
	var count int64
	var err error
	if d.postgres() {
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1", table).Scan(&count)
	} else {
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", table).Scan(&count)
	}
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (d databaseDialect) columnExists(ctx context.Context, db *sql.DB, table string, column string) (bool, error) {
	table = strings.TrimSpace(table)
	column = strings.TrimSpace(column)
	if table == "" || column == "" {
		return false, nil
	}
	var count int64
	var err error
	if d.postgres() {
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2", table, column).Scan(&count)
	} else {
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?", table, column).Scan(&count)
	}
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func databaseColumnExists(ctx context.Context, db *sql.DB, table string, column string) (bool, error) {
	var count int64
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?", table, column).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func databaseOptionalTimestampExpressions(ctx context.Context, db *sql.DB, table string, createdColumn string, updatedColumn string) (string, string, []string) {
	created := "''"
	updated := "''"
	var warnings []string
	if strings.TrimSpace(createdColumn) != "" {
		exists, err := databaseColumnExists(ctx, db, table, createdColumn)
		switch {
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("%s.%s timestamp check failed: %v", table, createdColumn, err))
		case exists:
			created = "COALESCE(NULLIF(CAST(" + quoteDatabaseIdentifier(createdColumn) + " AS CHAR), '0000-00-00 00:00:00'), '')"
		}
	}
	if strings.TrimSpace(updatedColumn) != "" {
		exists, err := databaseColumnExists(ctx, db, table, updatedColumn)
		switch {
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("%s.%s timestamp check failed: %v", table, updatedColumn, err))
		case exists:
			updated = "COALESCE(NULLIF(CAST(" + quoteDatabaseIdentifier(updatedColumn) + " AS CHAR), '0000-00-00 00:00:00'), '')"
		}
	}
	return created, updated, warnings
}

func databaseOptionalAliasedTimestampExpressions(ctx context.Context, db *sql.DB, table string, alias string, createdColumn string, updatedColumn string) (string, string, []string) {
	created := "''"
	updated := "''"
	var warnings []string
	if strings.TrimSpace(createdColumn) != "" {
		exists, err := databaseColumnExists(ctx, db, table, createdColumn)
		switch {
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("%s.%s timestamp check failed: %v", table, createdColumn, err))
		case exists:
			created = "COALESCE(NULLIF(CAST(" + alias + "." + quoteDatabaseIdentifier(createdColumn) + " AS CHAR), '0000-00-00 00:00:00'), '')"
		}
	}
	if strings.TrimSpace(updatedColumn) != "" {
		exists, err := databaseColumnExists(ctx, db, table, updatedColumn)
		switch {
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("%s.%s timestamp check failed: %v", table, updatedColumn, err))
		case exists:
			updated = "COALESCE(NULLIF(CAST(" + alias + "." + quoteDatabaseIdentifier(updatedColumn) + " AS CHAR), '0000-00-00 00:00:00'), '')"
		}
	}
	return created, updated, warnings
}

func databaseOptionalColumnExpression(ctx context.Context, db *sql.DB, table string, column string, expression string, fallback string) (string, []string) {
	expression = strings.TrimSpace(expression)
	fallback = strings.TrimSpace(fallback)
	if fallback == "" {
		fallback = "''"
	}
	if strings.TrimSpace(column) == "" || expression == "" {
		return fallback, nil
	}
	exists, err := databaseColumnExists(ctx, db, table, column)
	switch {
	case err != nil:
		return fallback, []string{fmt.Sprintf("%s.%s column check failed: %v", table, column, err)}
	case exists:
		return expression, nil
	default:
		return fallback, nil
	}
}

func databaseSourceTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "0000-00-00") {
		return time.Time{}
	}
	if unix, ok := parseDatabaseUnixTimestamp(value); ok {
		return unix
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, value, time.UTC)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func parseDatabaseUnixTimestamp(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return time.Time{}, false
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return time.Time{}, false
	}
	if len(value) >= 13 {
		return time.UnixMilli(parsed).UTC(), true
	}
	return time.Unix(parsed, 0).UTC(), true
}

func databaseCheckSpecs(profile string, tablePrefix string) ([]databaseCheckSpec, []string) {
	switch normalizeDatabaseProfile(profile) {
	case "wordpress":
		return wordpressDatabaseCheckSpecs(tablePrefix)
	case "prestashop":
		return prestashopDatabaseCheckSpecs(tablePrefix)
	case "mautic":
		return mauticDatabaseCheckSpecs(tablePrefix)
	case "yii2-rbac":
		return nil, nil
	default:
		return nil, []string{fmt.Sprintf("database profile %q does not have checks yet", profile)}
	}
}

func profileUsesDynamicDatabaseSpecs(profile string) bool {
	switch normalizeDatabaseProfile(profile) {
	case "yii2-rbac", "laravel":
		return true
	default:
		return false
	}
}

func wordpressDatabaseCheckSpecs(tablePrefix string) ([]databaseCheckSpec, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "wp_")
	users := quoteDatabaseIdentifier(prefix + "users")
	usermeta := quoteDatabaseIdentifier(prefix + "usermeta")
	options := quoteDatabaseIdentifier(prefix + "options")
	specs := []databaseCheckSpec{
		{
			Name:   "wordpress.users.count",
			Kind:   databaseCheckCount,
			Metric: "users",
			Table:  prefix + "users",
			Query:  "SELECT COUNT(*) FROM " + users,
		},
		{
			Name:   "wordpress.admin_users.count",
			Kind:   databaseCheckCount,
			Metric: "admin_users",
			Table:  prefix + "usermeta",
			Query:  "SELECT COUNT(DISTINCT user_id) FROM " + usermeta + " WHERE meta_key REGEXP ? AND meta_value LIKE ?",
			Args:   []any{wordpressCapabilityMetaKeyRegexp(prefix), "%administrator%"},
		},
		{
			Name:   "wordpress.options.count",
			Kind:   databaseCheckCount,
			Metric: "options",
			Table:  prefix + "options",
			Query:  "SELECT COUNT(*) FROM " + options,
		},
		wordpressOptionDigestSpec(prefix, "active_plugins", "wordpress.active_plugins.digest"),
		wordpressOptionDigestSpec(prefix, "cron", "wordpress.cron.digest"),
		wordpressOptionDigestSpec(prefix, "stylesheet", "wordpress.theme_stylesheet.digest"),
		wordpressOptionDigestSpec(prefix, "template", "wordpress.theme_template.digest"),
	}
	return specs, optionalWarning(warning)
}

func wordpressCapabilityMetaKeyRegexp(prefix string) string {
	return "^" + regexp.QuoteMeta(prefix) + "([0-9]+_)?capabilities$"
}

func wordpressOptionDigestSpec(prefix string, optionName string, name string) databaseCheckSpec {
	options := quoteDatabaseIdentifier(prefix + "options")
	return databaseCheckSpec{
		Name:       name,
		Kind:       databaseCheckDigest,
		Metric:     optionName,
		Table:      prefix + "options",
		OptionName: optionName,
		Query:      "SELECT option_value FROM " + options + " WHERE option_name = ? LIMIT 1",
		Args:       []any{optionName},
	}
}

func prestashopDatabaseCheckSpecs(tablePrefix string) ([]databaseCheckSpec, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "ps_")
	specs := []databaseCheckSpec{
		prestashopCountSpec(prefix, "employee", "employees", "prestashop.employees.count", ""),
		prestashopCountSpec(prefix, "employee", "active_employees", "prestashop.active_employees.count", "WHERE active = 1"),
		prestashopCountSpec(prefix, "module", "modules", "prestashop.modules.count", ""),
		prestashopCountSpec(prefix, "module", "active_modules", "prestashop.active_modules.count", "WHERE active = 1"),
		prestashopCountSpec(prefix, "configuration", "configuration", "prestashop.configuration.count", ""),
		prestashopCountSpec(prefix, "hook", "hooks", "prestashop.hooks.count", ""),
		prestashopCountSpec(prefix, "tab", "tabs", "prestashop.tabs.count", ""),
		prestashopCountSpec(prefix, "access", "access_rules", "prestashop.access_rules.count", ""),
	}
	return specs, optionalWarning(warning)
}

func prestashopCountSpec(prefix string, tableSuffix string, metric string, name string, where string) databaseCheckSpec {
	table := prefix + tableSuffix
	query := "SELECT COUNT(*) FROM " + quoteDatabaseIdentifier(table)
	if strings.TrimSpace(where) != "" {
		query += " " + strings.TrimSpace(where)
	}
	return databaseCheckSpec{
		Name:   name,
		Kind:   databaseCheckCount,
		Metric: metric,
		Table:  table,
		Query:  query,
	}
}

func mauticDatabaseCheckSpecs(tablePrefix string) ([]databaseCheckSpec, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "")
	specs := []databaseCheckSpec{
		mauticCountSpec(prefix, "users", "users", "mautic.users.count", ""),
		mauticCountSpec(prefix, "users", "published_users", "mautic.published_users.count", "WHERE is_published = 1"),
		mauticCountSpec(prefix, "roles", "roles", "mautic.roles.count", ""),
		mauticCountSpec(prefix, "roles", "admin_roles", "mautic.admin_roles.count", "WHERE is_admin = 1"),
		mauticCountSpec(prefix, "plugins", "plugins", "mautic.plugins.count", ""),
		mauticCountSpec(prefix, "plugins", "missing_plugins", "mautic.missing_plugins.count", "WHERE is_missing = 1"),
		mauticCountSpec(prefix, "plugin_integration_settings", "published_integrations", "mautic.published_integrations.count", "WHERE is_published = 1"),
		mauticCountSpec(prefix, "oauth2_clients", "oauth_clients", "mautic.oauth_clients.count", ""),
		mauticCountSpec(prefix, "webhooks", "webhooks", "mautic.webhooks.count", ""),
	}
	return specs, optionalWarning(warning)
}

func mauticCountSpec(prefix string, tableSuffix string, metric string, name string, where string) databaseCheckSpec {
	table := prefix + tableSuffix
	query := "SELECT COUNT(*) FROM " + quoteDatabaseIdentifier(table)
	if strings.TrimSpace(where) != "" {
		query += " " + strings.TrimSpace(where)
	}
	return databaseCheckSpec{
		Name:   name,
		Kind:   databaseCheckCount,
		Metric: metric,
		Table:  table,
		Query:  query,
	}
}

func normalizeDatabaseDSN(engine string, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	engine = normalizeDatabaseEngine(engine)
	if raw == "" || !strings.Contains(raw, "://") {
		if isPostgresFamily(engine) && strings.HasPrefix(strings.ToLower(raw), "pgsql:") {
			return normalizePostgresPDODSN(raw), nil
		}
		return raw, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if isPostgresFamily(engine) {
		if parsed.Scheme == "postgres" || parsed.Scheme == "postgresql" {
			return raw, nil
		}
		return "", fmt.Errorf("unsupported DSN scheme %q for %s", parsed.Scheme, engine)
	}
	if !isMySQLFamily(parsed.Scheme) {
		return "", fmt.Errorf("unsupported DSN scheme %q for %s", parsed.Scheme, engine)
	}
	cfg := mysql.NewConfig()
	cfg.User = parsed.User.Username()
	cfg.Passwd, _ = parsed.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = parsed.Host
	cfg.DBName = strings.TrimPrefix(parsed.Path, "/")
	cfg.ParseTime = true
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	for key, values := range parsed.Query() {
		if len(values) > 0 {
			cfg.Params[key] = values[len(values)-1]
		}
	}
	return cfg.FormatDSN(), nil
}

func normalizePostgresPDODSN(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "pgsql:"))
	parts := strings.Split(raw, ";")
	values := map[string]string{}
	for _, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			values[key] = value
		}
	}
	host := firstNonEmptyString(values["host"], "localhost")
	if port := strings.TrimSpace(values["port"]); port != "" {
		host += ":" + port
	}
	parsed := url.URL{
		Scheme: "postgres",
		Host:   host,
		Path:   "/" + strings.TrimLeft(values["dbname"], "/"),
	}
	if values["user"] != "" {
		if values["password"] != "" {
			parsed.User = url.UserPassword(values["user"], values["password"])
		} else {
			parsed.User = url.User(values["user"])
		}
	}
	query := url.Values{}
	if sslmode := strings.TrimSpace(values["sslmode"]); sslmode != "" {
		query.Set("sslmode", sslmode)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func normalizeDatabaseEngine(engine string) string {
	return strings.ToLower(strings.TrimSpace(engine))
}

func normalizeDatabaseProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "wp", "wordpress-multisite", "woocommerce":
		return "wordpress"
	case "ps":
		return "prestashop"
	case "yii2_rbac":
		return "yii2-rbac"
	case "laravel":
		return "laravel"
	default:
		return strings.ToLower(strings.TrimSpace(profile))
	}
}

func databaseProfileSupportsEngine(profile string, engine string) bool {
	profile = normalizeDatabaseProfile(profile)
	if profile == "yii2-rbac" || profile == "laravel" {
		return isMySQLFamily(engine) || isPostgresFamily(engine)
	}
	return isMySQLFamily(engine)
}

func databaseSQLDriver(engine string) string {
	if isPostgresFamily(engine) {
		return "pgx"
	}
	return "mysql"
}

func isMySQLFamily(engine string) bool {
	switch normalizeDatabaseEngine(engine) {
	case "mysql", "mariadb":
		return true
	default:
		return false
	}
}

func isPostgresFamily(engine string) bool {
	switch normalizeDatabaseEngine(engine) {
	case "postgres", "postgresql", "pgx":
		return true
	default:
		return false
	}
}

func sanitizeDatabasePrefix(value string, fallback string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return fallback, fmt.Sprintf("table prefix %q contains unsupported characters; using %q", value, fallback)
	}
	return value, ""
}

func quoteDatabaseIdentifier(value string) string {
	return "`" + value + "`"
}

func databasePlaceholders(count int) string {
	if count <= 0 {
		return "NULL"
	}
	values := make([]string, count)
	for i := range values {
		values[i] = "?"
	}
	return strings.Join(values, ", ")
}

func stringArgs(values []string) []any {
	args := make([]any, 0, len(values))
	for _, value := range values {
		args = append(args, value)
	}
	return args
}

func optionalWarning(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return []string{value}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func databaseEntityKey(kind string, value string) string {
	return strings.TrimSpace(kind) + ":" + databaseSHA256Short(value)
}

func databaseDisplayLabel(kind string, display string, fallback string) string {
	display = strings.TrimSpace(display)
	if display != "" {
		return strings.TrimSpace(kind) + ":" + display
	}
	return strings.TrimSpace(kind) + ":" + databaseSHA256Short(fallback)
}

func databaseEntitySignature(entity DatabaseEntityObservation) string {
	var parts []string
	parts = append(parts, strings.TrimSpace(entity.Type), strings.TrimSpace(entity.Label), fmt.Sprintf("privileged:%t", entity.Privileged))
	if !entity.SourceCreatedAt.IsZero() {
		parts = append(parts, "source_created_at="+entity.SourceCreatedAt.UTC().Format(time.RFC3339Nano))
	}
	if !entity.SourceUpdatedAt.IsZero() {
		parts = append(parts, "source_updated_at="+entity.SourceUpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	keys := make([]string, 0, len(entity.Attributes))
	for key := range entity.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+fmt.Sprint(entity.Attributes[key]))
	}
	return databaseSHA256Hex(strings.Join(parts, "\n"))
}

func sortDatabaseEntities(entities []DatabaseEntityObservation) {
	sort.Slice(entities, func(i int, j int) bool {
		if entities[i].Type == entities[j].Type {
			return entities[i].Key < entities[j].Key
		}
		return entities[i].Type < entities[j].Type
	})
}

func databaseSHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func databaseSHA256Short(value string) string {
	hash := databaseSHA256Hex(value)
	if len(hash) <= 24 {
		return hash
	}
	return hash[:24]
}

type databasePIIProtector struct {
	key []byte
}

func newDatabasePIIProtector(key string) databasePIIProtector {
	key = strings.TrimSpace(key)
	if key == "" {
		return databasePIIProtector{}
	}
	return databasePIIProtector{key: []byte(key)}
}

func (p databasePIIProtector) Fingerprint(value string) string {
	value = strings.TrimSpace(value)
	if len(p.key) == 0 || value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func databaseNormalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func databaseNormalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func databaseAccountDisplay(login string, email string) string {
	if normalized := databaseNormalizeEmail(email); normalized != "" {
		return normalized
	}
	return databaseNormalizeIdentifier(login)
}

func databaseMaskEmail(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "@")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return databaseMaskIdentifier(value)
	}
	return databaseMaskIdentifier(parts[0]) + "@" + parts[1]
}

func databaseMaskIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	runes := []rune(value)
	switch len(runes) {
	case 0:
		return ""
	case 1:
		return "*"
	case 2:
		return string(runes[0]) + "*"
	default:
		return string(runes[0]) + "***" + string(runes[len(runes)-1])
	}
}

func mauticURLHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		parsed, err = url.Parse("https://" + strings.TrimLeft(value, "/"))
	}
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Host)
}
