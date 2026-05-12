package collector

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
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

func (r *Runtime) CollectDatabaseSnapshot(ctx context.Context, input DatabaseCollectInput) (DatabaseCollectResult, error) {
	startedAt := time.Now().UTC()
	result := DatabaseCollectResult{
		StartedAt: startedAt,
		Name:      strings.TrimSpace(input.Name),
		Engine:    normalizeDatabaseEngine(input.Engine),
		Profile:   normalizeDatabaseProfile(input.Profile),
		Checks:    []DatabaseCheckResult{},
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

	result.FinishedAt = time.Now().UTC()
	return result, nil
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

func optionalWarning(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return []string{value}
}
