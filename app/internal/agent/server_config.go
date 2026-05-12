package agent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ServerConfigSchema = "aegrail.agent.server_config.v1"

type ServerConfig struct {
	Schema   string               `yaml:"schema"`
	Hub      ServerHubConfig      `yaml:"hub"`
	Identity ServerIdentityConfig `yaml:"identity"`
	Runtime  ServerRuntimeConfig  `yaml:"runtime"`
	Sites    []ServerSiteConfig   `yaml:"sites"`
}

type ServerHubConfig struct {
	URL             string `yaml:"url"`
	IngestSecretEnv string `yaml:"ingest_secret_env"`
	SendLimit       int    `yaml:"send_limit"`
}

type ServerIdentityConfig struct {
	Org         string            `yaml:"org"`
	Project     string            `yaml:"project"`
	Environment string            `yaml:"environment"`
	Host        string            `yaml:"host"`
	AgentID     string            `yaml:"agent_id"`
	Region      string            `yaml:"region"`
	Labels      map[string]string `yaml:"labels"`
}

type ServerRuntimeConfig struct {
	QueueDir string `yaml:"queue_dir"`
	StateDir string `yaml:"state_dir"`
	Interval string `yaml:"interval"`
	Timezone string `yaml:"timezone"`
}

type ServerSiteConfig struct {
	Slug         string                   `yaml:"slug"`
	Name         string                   `yaml:"name"`
	Domain       string                   `yaml:"domain"`
	Kind         string                   `yaml:"kind"`
	App          string                   `yaml:"app"`
	Service      string                   `yaml:"service"`
	Root         string                   `yaml:"root"`
	Labels       map[string]string        `yaml:"labels"`
	Files        ServerFileWatchConfig    `yaml:"files"`
	Logs         []ServerLogConfig        `yaml:"logs"`
	Databases    []ServerDatabaseConfig   `yaml:"databases"`
	BrowserCrawl ServerBrowserCrawlConfig `yaml:"browser_crawl"`
	WordPress    ServerWordPressConfig    `yaml:"wordpress"`
}

type ServerFileWatchConfig struct {
	Profiles   []string `yaml:"profiles"`
	ExtraPaths []string `yaml:"extra_paths"`
	Exclude    []string `yaml:"exclude"`
}

type ServerLogConfig struct {
	Path string `yaml:"path"`
	Kind string `yaml:"kind"`
}

type ServerDatabaseConfig struct {
	Name        string `yaml:"name"`
	Engine      string `yaml:"engine"`
	DSN         string `yaml:"dsn"`
	DSNEnv      string `yaml:"dsn_env"`
	Profile     string `yaml:"profile"`
	TablePrefix string `yaml:"table_prefix"`
	Timeout     string `yaml:"timeout"`
	Schedule    string `yaml:"schedule"`
}

type ServerBrowserCrawlConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Rendered       bool     `yaml:"rendered"`
	WaitTagManager bool     `yaml:"wait_tag_manager"`
	MaxPages       int      `yaml:"max_pages"`
	Timeout        string   `yaml:"timeout"`
	URLs           []string `yaml:"urls"`
}

type ServerWordPressConfig struct {
	Multisite    bool                        `yaml:"multisite"`
	NetworkSites []ServerWordPressSiteConfig `yaml:"network_sites"`
}

type ServerWordPressSiteConfig struct {
	BlogID int    `yaml:"blog_id"`
	Domain string `yaml:"domain"`
}

type ServerConfigValidationError struct {
	Issues []string
}

func (e ServerConfigValidationError) Error() string {
	return "invalid agent config: " + strings.Join(e.Issues, "; ")
}

type ServerRunResult struct {
	Sites   []ServerRunSiteResult
	Queued  int
	Sent    int
	Failed  int
	Pending int
}

type ServerRunSiteResult struct {
	Slug          string
	App           string
	Service       string
	FilesWatched  int
	LogsWatched   int
	Queued        int
	FileBaselined bool
	LogBaselined  bool
	StateDir      string
}

func LoadServerConfig(path string) (ServerConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, err
	}
	var config ServerConfig
	if err := yaml.Unmarshal(content, &config); err != nil {
		return ServerConfig{}, err
	}
	config = NormalizeServerConfig(config)
	if err := ValidateServerConfig(config); err != nil {
		return ServerConfig{}, err
	}
	return config, nil
}

func NormalizeServerConfig(config ServerConfig) ServerConfig {
	config.Schema = strings.TrimSpace(config.Schema)
	config.Hub.URL = strings.TrimSpace(config.Hub.URL)
	config.Hub.IngestSecretEnv = strings.TrimSpace(config.Hub.IngestSecretEnv)
	config.Identity.Org = strings.TrimSpace(config.Identity.Org)
	config.Identity.Project = strings.TrimSpace(config.Identity.Project)
	config.Identity.Environment = strings.TrimSpace(config.Identity.Environment)
	config.Identity.Host = strings.TrimSpace(config.Identity.Host)
	config.Identity.AgentID = strings.TrimSpace(config.Identity.AgentID)
	config.Identity.Region = strings.TrimSpace(config.Identity.Region)
	config.Identity.Labels = cloneStringMap(config.Identity.Labels)
	config.Runtime.QueueDir = strings.TrimSpace(config.Runtime.QueueDir)
	if config.Runtime.QueueDir == "" {
		config.Runtime.QueueDir = ".aegrail/queue"
	}
	config.Runtime.StateDir = strings.TrimSpace(config.Runtime.StateDir)
	if config.Runtime.StateDir == "" {
		config.Runtime.StateDir = filepath.Join(filepath.Dir(config.Runtime.QueueDir), "state")
	}
	config.Runtime.Interval = strings.TrimSpace(config.Runtime.Interval)
	if config.Runtime.Interval == "" {
		config.Runtime.Interval = "30s"
	}
	config.Runtime.Timezone = strings.TrimSpace(config.Runtime.Timezone)
	for index := range config.Sites {
		site := &config.Sites[index]
		site.Slug = strings.TrimSpace(site.Slug)
		site.Name = strings.TrimSpace(site.Name)
		site.Domain = strings.TrimSpace(site.Domain)
		site.Kind = strings.ToLower(strings.TrimSpace(site.Kind))
		site.App = strings.TrimSpace(site.App)
		if site.App == "" {
			site.App = site.Slug
		}
		site.Service = strings.TrimSpace(site.Service)
		if site.Service == "" {
			site.Service = "frontend"
		}
		site.Root = strings.TrimSpace(site.Root)
		site.Labels = cloneStringMap(site.Labels)
		site.Files.Profiles = normalizeStringSlice(site.Files.Profiles, true)
		site.Files.ExtraPaths = normalizeStringSlice(site.Files.ExtraPaths, false)
		site.Files.Exclude = normalizeStringSlice(site.Files.Exclude, false)
		for logIndex := range site.Logs {
			site.Logs[logIndex].Path = strings.TrimSpace(site.Logs[logIndex].Path)
			site.Logs[logIndex].Kind = strings.ToLower(strings.TrimSpace(site.Logs[logIndex].Kind))
		}
		for dbIndex := range site.Databases {
			db := &site.Databases[dbIndex]
			db.Name = strings.TrimSpace(db.Name)
			db.Engine = strings.ToLower(strings.TrimSpace(db.Engine))
			db.DSN = strings.TrimSpace(db.DSN)
			db.DSNEnv = strings.TrimSpace(db.DSNEnv)
			db.Profile = strings.ToLower(strings.TrimSpace(db.Profile))
			db.TablePrefix = strings.TrimSpace(db.TablePrefix)
			db.Timeout = strings.TrimSpace(db.Timeout)
			db.Schedule = strings.TrimSpace(db.Schedule)
		}
		site.BrowserCrawl.Timeout = strings.TrimSpace(site.BrowserCrawl.Timeout)
		site.BrowserCrawl.URLs = normalizeStringSlice(site.BrowserCrawl.URLs, false)
		for wpIndex := range site.WordPress.NetworkSites {
			site.WordPress.NetworkSites[wpIndex].Domain = strings.TrimSpace(site.WordPress.NetworkSites[wpIndex].Domain)
		}
	}
	return config
}

func ValidateServerConfig(config ServerConfig) error {
	var issues []string
	if config.Schema != ServerConfigSchema {
		issues = append(issues, fmt.Sprintf("schema must be %q", ServerConfigSchema))
	}
	if !isHTTPURL(config.Hub.URL) {
		issues = append(issues, "hub.url must be an absolute http or https URL")
	}
	if config.Identity.Org == "" {
		issues = append(issues, "identity.org is required")
	}
	if config.Identity.Project == "" {
		issues = append(issues, "identity.project is required")
	}
	if config.Identity.Environment == "" {
		issues = append(issues, "identity.environment is required")
	}
	if config.Identity.Host == "" {
		issues = append(issues, "identity.host is required")
	}
	if config.Identity.AgentID == "" {
		issues = append(issues, "identity.agent_id is required")
	}
	if !isAbsoluteConfigPath(config.Runtime.QueueDir) {
		issues = append(issues, "runtime.queue_dir must be an absolute path")
	}
	if !isAbsoluteConfigPath(config.Runtime.StateDir) {
		issues = append(issues, "runtime.state_dir must be an absolute path")
	}
	if _, err := config.RuntimeInterval(); err != nil {
		issues = append(issues, "runtime.interval must be a valid duration")
	}
	if len(config.Sites) == 0 {
		issues = append(issues, "at least one site is required")
	}
	seenSites := map[string]struct{}{}
	for index, site := range config.Sites {
		prefix := fmt.Sprintf("sites[%d]", index)
		if site.Slug == "" {
			issues = append(issues, prefix+".slug is required")
		} else if _, ok := seenSites[site.Slug]; ok {
			issues = append(issues, prefix+".slug must be unique")
		} else {
			seenSites[site.Slug] = struct{}{}
		}
		if !isKnownSiteKind(site.Kind) {
			issues = append(issues, prefix+".kind is unknown")
		}
		if site.App == "" {
			issues = append(issues, prefix+".app is required")
		}
		if site.Service == "" {
			issues = append(issues, prefix+".service is required")
		}
		if site.Root == "" {
			issues = append(issues, prefix+".root is required")
		} else if !isAbsoluteConfigPath(site.Root) {
			issues = append(issues, prefix+".root must be an absolute path")
		}
		for _, profile := range site.Files.Profiles {
			if !isKnownWatchProfile(profile) {
				issues = append(issues, prefix+".files.profiles contains unknown profile "+profile)
			}
		}
		for _, path := range site.Files.ExtraPaths {
			if !isAbsoluteConfigPath(path) {
				issues = append(issues, prefix+".files.extra_paths must contain only absolute paths")
			}
		}
		for _, path := range site.Files.Exclude {
			if !isAbsoluteConfigPath(path) {
				issues = append(issues, prefix+".files.exclude must contain only absolute paths")
			}
		}
		for logIndex, log := range site.Logs {
			logPrefix := fmt.Sprintf("%s.logs[%d]", prefix, logIndex)
			if log.Path == "" {
				issues = append(issues, logPrefix+".path is required")
			} else if !isAbsoluteConfigPath(log.Path) {
				issues = append(issues, logPrefix+".path must be an absolute path")
			}
			if log.Kind != "" && !isKnownLogKind(log.Kind) {
				issues = append(issues, logPrefix+".kind is unknown")
			}
		}
		for dbIndex, db := range site.Databases {
			dbPrefix := fmt.Sprintf("%s.databases[%d]", prefix, dbIndex)
			if db.Engine != "" && !isKnownDBEngine(db.Engine) {
				issues = append(issues, dbPrefix+".engine is unknown")
			}
			if db.DSN != "" {
				issues = append(issues, dbPrefix+".dsn must not contain literal credentials; use dsn_env")
			}
			if db.DSNEnv == "" {
				issues = append(issues, dbPrefix+".dsn_env is required")
			}
			if db.Profile != "" && !isKnownWatchProfile(db.Profile) {
				issues = append(issues, dbPrefix+".profile is unknown")
			}
			if db.TablePrefix != "" && !isSafeDBTablePrefix(db.TablePrefix) {
				issues = append(issues, dbPrefix+".table_prefix may contain only letters, numbers, and underscores")
			}
			if db.Timeout != "" {
				if _, err := time.ParseDuration(db.Timeout); err != nil {
					issues = append(issues, dbPrefix+".timeout must be a valid duration")
				}
			}
			if db.Schedule != "" {
				if _, err := time.ParseDuration(db.Schedule); err != nil {
					issues = append(issues, dbPrefix+".schedule must be a valid duration")
				}
			}
		}
		if site.BrowserCrawl.Enabled && len(site.BrowserCrawl.URLs) == 0 {
			issues = append(issues, prefix+".browser_crawl.urls is required when browser_crawl.enabled is true")
		}
		if site.BrowserCrawl.Timeout != "" {
			if _, err := time.ParseDuration(site.BrowserCrawl.Timeout); err != nil {
				issues = append(issues, prefix+".browser_crawl.timeout must be a valid duration")
			}
		}
		for urlIndex, rawURL := range site.BrowserCrawl.URLs {
			if !isHTTPURL(rawURL) {
				issues = append(issues, fmt.Sprintf("%s.browser_crawl.urls[%d] must be an absolute http or https URL", prefix, urlIndex))
			}
		}
	}
	if len(issues) > 0 {
		return ServerConfigValidationError{Issues: issues}
	}
	return nil
}

func (config ServerConfig) RuntimeInterval() (time.Duration, error) {
	return time.ParseDuration(config.Runtime.Interval)
}

func (config ServerConfig) AgentIdentity() Identity {
	return Identity{
		Schema:      ConfigSchema,
		HubURL:      config.Hub.URL,
		QueueDir:    config.Runtime.QueueDir,
		Org:         config.Identity.Org,
		Project:     config.Identity.Project,
		Environment: config.Identity.Environment,
		Host:        config.Identity.Host,
		AgentID:     config.Identity.AgentID,
		Region:      config.Identity.Region,
		Labels:      cloneStringMap(config.Identity.Labels),
	}
}

func ResolveServerConfigSecret(config ServerConfig, override string) string {
	override = strings.TrimSpace(override)
	if override != "" {
		return override
	}
	if config.Hub.IngestSecretEnv == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(config.Hub.IngestSecretEnv))
}

func (r *Runtime) RunServerConfigOnce(ctx context.Context, config ServerConfig, secret string, sendLimit int) (ServerRunResult, error) {
	config = NormalizeServerConfig(config)
	if err := ValidateServerConfig(config); err != nil {
		return ServerRunResult{}, err
	}
	identity := config.AgentIdentity()
	r.Config.Identity = &identity
	r.Config.QueueDir = identity.QueueDir
	if err := ensureQueueDirs(identity.QueueDir); err != nil {
		return ServerRunResult{}, err
	}

	result := ServerRunResult{}
	for _, site := range config.Sites {
		siteResult := ServerRunSiteResult{
			Slug:     site.Slug,
			App:      site.App,
			Service:  site.Service,
			StateDir: siteStateDir(config, site),
		}
		labels := siteEventLabels(site)
		if len(site.Files.Profiles) > 0 || len(site.Files.ExtraPaths) > 0 {
			watchResult, err := r.ScanWatchedPaths(ctx, WatchOptions{
				Paths:     site.Files.ExtraPaths,
				Root:      site.Root,
				Profiles:  site.Files.Profiles,
				Exclude:   site.Files.Exclude,
				StatePath: siteStatePath(config, site, "file-watch.json"),
				App:       site.App,
				Service:   site.Service,
				Region:    config.Identity.Region,
				Labels:    labels,
			})
			if err != nil {
				return ServerRunResult{}, fmt.Errorf("site %s file watch: %w", site.Slug, err)
			}
			siteResult.FilesWatched = watchResult.WatchedFiles
			siteResult.FileBaselined = watchResult.Baselined
			siteResult.Queued += watchResult.Queued
		}
		if len(site.Logs) > 0 {
			logPaths := make([]string, 0, len(site.Logs))
			for _, log := range site.Logs {
				logPaths = append(logPaths, log.Path)
			}
			logResult, err := r.ScanLogPaths(ctx, LogWatchOptions{
				Paths:     logPaths,
				StatePath: siteStatePath(config, site, "log-tail.json"),
				App:       site.App,
				Service:   site.Service,
				Region:    config.Identity.Region,
				Labels:    labels,
			})
			if err != nil {
				return ServerRunResult{}, fmt.Errorf("site %s log watch: %w", site.Slug, err)
			}
			siteResult.LogsWatched = logResult.WatchedLogs
			siteResult.LogBaselined = logResult.Baselined
			siteResult.Queued += logResult.Queued
		}
		result.Queued += siteResult.Queued
		result.Sites = append(result.Sites, siteResult)
	}

	if strings.TrimSpace(secret) != "" {
		sendResult, err := r.SendQueued(ctx, secret, sendLimit)
		if err != nil {
			return result, err
		}
		result.Sent = sendResult.Sent
		result.Failed = sendResult.Failed
		result.Pending = sendResult.PendingAfter
	} else {
		status, err := r.Status(ctx)
		if err != nil {
			return result, err
		}
		result.Pending = status.Pending
	}
	return result, nil
}

func siteEventLabels(site ServerSiteConfig) map[string]string {
	labels := cloneStringMap(site.Labels)
	labels["site"] = site.Slug
	labels["site_slug"] = site.Slug
	if site.Domain != "" {
		labels["domain"] = site.Domain
	}
	if site.Kind != "" {
		labels["site_kind"] = site.Kind
	}
	return labels
}

func SiteEventLabels(site ServerSiteConfig) map[string]string {
	return siteEventLabels(NormalizeServerConfig(ServerConfig{Sites: []ServerSiteConfig{site}}).Sites[0])
}

func SiteStatePath(config ServerConfig, site ServerSiteConfig, name string) string {
	return siteStatePath(config, site, name)
}

func siteStateDir(config ServerConfig, site ServerSiteConfig) string {
	return filepath.Join(config.Runtime.StateDir, "sites", safeFilename(site.Slug))
}

func siteStatePath(config ServerConfig, site ServerSiteConfig, name string) string {
	return filepath.Join(siteStateDir(config, site), name)
}

func normalizeStringSlice(values []string, lower bool) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func isHTTPURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && parsed.IsAbs() && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func isAbsoluteConfigPath(value string) bool {
	value = strings.TrimSpace(value)
	return filepath.IsAbs(value) || strings.HasPrefix(filepath.ToSlash(value), "/")
}

func isKnownSiteKind(kind string) bool {
	switch kind {
	case "wordpress", "wordpress-multisite", "prestashop", "generic-php", "mautic", "yii2", "laravel":
		return true
	default:
		return false
	}
}

func isKnownWatchProfile(profile string) bool {
	switch profile {
	case "wordpress", "wp", "woocommerce", "prestashop", "ps":
		return true
	default:
		return false
	}
}

func isKnownLogKind(kind string) bool {
	switch kind {
	case "nginx_access", "apache_access", "php_error", "generic":
		return true
	default:
		return false
	}
}

func isKnownDBEngine(engine string) bool {
	switch engine {
	case "mysql", "mariadb", "postgres", "postgresql":
		return true
	default:
		return false
	}
}

func isSafeDBTablePrefix(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func IsServerConfigValidationError(err error) bool {
	var validationError ServerConfigValidationError
	return errors.As(err, &validationError)
}
