package collector

import (
	"context"
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
)

type DatabaseCollectInput struct {
	Name        string
	Engine      string
	DSN         string
	Profile     string
	TablePrefix string
	Timeout     time.Duration
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
	Type       string
	Key        string
	Label      string
	Privileged bool
	Attributes map[string]any
	Signature  string
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

	specs, warnings := databaseCheckSpecs(result.Profile, input.TablePrefix)
	result.Warnings = append(result.Warnings, warnings...)
	if !isMySQLFamily(result.Engine) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("database engine %q is configured but collector support is not implemented yet", result.Engine))
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

	db, err := sql.Open("mysql", dsn)
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
	entities, entityWarnings := collectDatabaseEntities(queryCtx, db, result.Profile, input.TablePrefix)
	result.Entities = append(result.Entities, entities...)
	result.Warnings = append(result.Warnings, entityWarnings...)

	result.FinishedAt = time.Now().UTC()
	return result, nil
}

func collectDatabaseEntities(ctx context.Context, db *sql.DB, profile string, tablePrefix string) ([]DatabaseEntityObservation, []string) {
	switch normalizeDatabaseProfile(profile) {
	case "wordpress":
		return collectWordPressDatabaseEntities(ctx, db, tablePrefix)
	case "prestashop":
		return collectPrestaShopDatabaseEntities(ctx, db, tablePrefix)
	default:
		return nil, nil
	}
}

func collectWordPressDatabaseEntities(ctx context.Context, db *sql.DB, tablePrefix string) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "wp_")
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	userEntities, userWarnings := collectWordPressUserEntities(ctx, db, prefix)
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

func collectWordPressUserEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	users := quoteDatabaseIdentifier(prefix + "users")
	usermeta := quoteDatabaseIdentifier(prefix + "usermeta")
	query := "SELECT u.ID, COALESCE(u.user_login, ''), COALESCE(u.user_email, ''), COALESCE(um.meta_value, '') FROM " +
		users + " u LEFT JOIN " + usermeta + " um ON um.user_id = u.ID AND um.meta_key = ? ORDER BY u.ID LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, prefix+"capabilities")
	if err != nil {
		return nil, []string{fmt.Sprintf("wordpress user entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var login string
		var email string
		var capabilities string
		if err := rows.Scan(&id, &login, &email, &capabilities); err != nil {
			return entities, []string{fmt.Sprintf("wordpress user entity scan failed: %v", err)}
		}
		admin := strings.Contains(strings.ToLower(capabilities), "administrator")
		capabilitiesHash := databaseSHA256Hex(capabilities)
		emailHash := databaseSHA256Hex(strings.ToLower(strings.TrimSpace(email)))
		loginHash := databaseSHA256Hex(strings.TrimSpace(login))
		entity := DatabaseEntityObservation{
			Type:       "wordpress_user",
			Key:        databaseEntityKey("wordpress_user", strconv.FormatInt(id, 10)),
			Label:      "wordpress_user:" + databaseSHA256Short(strconv.FormatInt(id, 10)),
			Privileged: admin,
			Attributes: map[string]any{
				"user_id_hash":        databaseSHA256Hex(strconv.FormatInt(id, 10)),
				"login_sha256":        loginHash,
				"email_sha256":        emailHash,
				"capabilities_sha256": capabilitiesHash,
				"administrator":       admin,
				"has_capabilities":    strings.TrimSpace(capabilities) != "",
			},
		}
		entity.Signature = databaseEntitySignature(entity)
		entities = append(entities, entity)
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("wordpress user entity rows failed: %v", err)}
	}
	return entities, nil
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
	query := "SELECT ID, COALESCE(post_type, ''), COALESCE(post_status, ''), COALESCE(post_content, '') FROM " + quoteDatabaseIdentifier(table) +
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
		var content string
		if err := rows.Scan(&id, &postType, &postStatus, &content); err != nil {
			return entities, []string{fmt.Sprintf("wordpress post content entity scan failed: %v", err)}
		}
		idText := strconv.FormatInt(id, 10)
		entities = append(entities, wordpressScriptContentEntity("post_content", idText, "post:"+strings.TrimSpace(postType)+":"+databaseSHA256Short(idText), content, map[string]any{
			"post_id_hash": databaseSHA256Hex(idText),
			"post_type":    strings.TrimSpace(postType),
			"post_status":  strings.TrimSpace(postStatus),
		}))
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

func wordpressScriptContentEntity(source string, identifier string, label string, content string, extra map[string]any) DatabaseEntityObservation {
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

func collectPrestaShopDatabaseEntities(ctx context.Context, db *sql.DB, tablePrefix string) ([]DatabaseEntityObservation, []string) {
	prefix, warning := sanitizeDatabasePrefix(tablePrefix, "ps_")
	var entities []DatabaseEntityObservation
	var warnings []string
	warnings = append(warnings, optionalWarning(warning)...)

	employeeEntities, employeeWarnings := collectPrestaShopEmployeeEntities(ctx, db, prefix)
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

func collectPrestaShopEmployeeEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := quoteDatabaseIdentifier(prefix + "employee")
	rows, err := db.QueryContext(ctx, "SELECT id_employee, COALESCE(email, ''), active, id_profile FROM "+table+" ORDER BY id_employee LIMIT 1000")
	if err != nil {
		return nil, []string{fmt.Sprintf("prestashop employee entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var email string
		var active int64
		var profileID int64
		if err := rows.Scan(&id, &email, &active, &profileID); err != nil {
			return entities, []string{fmt.Sprintf("prestashop employee entity scan failed: %v", err)}
		}
		superAdmin := profileID == 1
		isActive := active != 0
		entity := DatabaseEntityObservation{
			Type:       "prestashop_employee",
			Key:        databaseEntityKey("prestashop_employee", strconv.FormatInt(id, 10)),
			Label:      "prestashop_employee:" + databaseSHA256Short(strconv.FormatInt(id, 10)),
			Privileged: superAdmin,
			Attributes: map[string]any{
				"employee_id_hash": databaseSHA256Hex(strconv.FormatInt(id, 10)),
				"email_sha256":     databaseSHA256Hex(strings.ToLower(strings.TrimSpace(email))),
				"profile_id":       profileID,
				"active":           isActive,
				"super_admin":      superAdmin,
			},
		}
		entity.Signature = databaseEntitySignature(entity)
		entities = append(entities, entity)
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("prestashop employee entity rows failed: %v", err)}
	}
	return entities, nil
}

func collectPrestaShopModuleEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := quoteDatabaseIdentifier(prefix + "module")
	rows, err := db.QueryContext(ctx, "SELECT id_module, COALESCE(name, ''), active, COALESCE(version, '') FROM "+table+" ORDER BY id_module LIMIT 2000")
	if err != nil {
		return nil, []string{fmt.Sprintf("prestashop module entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var id int64
		var name string
		var active int64
		var version string
		if err := rows.Scan(&id, &name, &active, &version); err != nil {
			return entities, []string{fmt.Sprintf("prestashop module entity scan failed: %v", err)}
		}
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		isActive := active != 0
		entity := DatabaseEntityObservation{
			Type:       "prestashop_module",
			Key:        databaseEntityKey("prestashop_module", strconv.FormatInt(id, 10)),
			Label:      name,
			Privileged: false,
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
		return entities, []string{fmt.Sprintf("prestashop module entity rows failed: %v", err)}
	}
	return entities, nil
}

func collectPrestaShopConfigurationEntities(ctx context.Context, db *sql.DB, prefix string) ([]DatabaseEntityObservation, []string) {
	table := quoteDatabaseIdentifier(prefix + "configuration")
	names := prestashopTrackedConfigurationNames()
	patterns := prestashopTrackedConfigurationPatterns()
	whereParts := []string{"name IN (" + databasePlaceholders(len(names)) + ")"}
	args := stringArgs(names)
	for _, pattern := range patterns {
		whereParts = append(whereParts, "name LIKE ?")
		args = append(args, pattern)
	}
	query := "SELECT name, COALESCE(value, '') FROM " + table +
		" WHERE " + strings.Join(whereParts, " OR ") + " ORDER BY name LIMIT 1000"
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, []string{fmt.Sprintf("prestashop configuration entity query failed: %v", err)}
	}
	defer rows.Close()

	var entities []DatabaseEntityObservation
	for rows.Next() {
		var name string
		var value string
		if err := rows.Scan(&name, &value); err != nil {
			return entities, []string{fmt.Sprintf("prestashop configuration entity scan failed: %v", err)}
		}
		if entity, ok := prestashopConfigurationEntity(name, value); ok {
			entities = append(entities, entity)
		}
	}
	if err := rows.Err(); err != nil {
		return entities, []string{fmt.Sprintf("prestashop configuration entity rows failed: %v", err)}
	}
	return entities, nil
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

func databaseCheckSpecs(profile string, tablePrefix string) ([]databaseCheckSpec, []string) {
	switch normalizeDatabaseProfile(profile) {
	case "wordpress":
		return wordpressDatabaseCheckSpecs(tablePrefix)
	case "prestashop":
		return prestashopDatabaseCheckSpecs(tablePrefix)
	default:
		return nil, []string{fmt.Sprintf("database profile %q does not have checks yet", profile)}
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
			Query:  "SELECT COUNT(*) FROM " + usermeta + " WHERE meta_key = ? AND meta_value LIKE ?",
			Args:   []any{prefix + "capabilities", "%administrator%"},
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

func normalizeDatabaseDSN(engine string, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "://") {
		return raw, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
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

func normalizeDatabaseEngine(engine string) string {
	return strings.ToLower(strings.TrimSpace(engine))
}

func normalizeDatabaseProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "wp":
		return "wordpress"
	case "ps":
		return "prestashop"
	default:
		return strings.ToLower(strings.TrimSpace(profile))
	}
}

func isMySQLFamily(engine string) bool {
	switch normalizeDatabaseEngine(engine) {
	case "mysql", "mariadb":
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

func databaseEntityKey(kind string, value string) string {
	return strings.TrimSpace(kind) + ":" + databaseSHA256Short(value)
}

func databaseEntitySignature(entity DatabaseEntityObservation) string {
	var parts []string
	parts = append(parts, strings.TrimSpace(entity.Type), strings.TrimSpace(entity.Label), fmt.Sprintf("privileged:%t", entity.Privileged))
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
