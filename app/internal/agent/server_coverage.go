package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ServerConfigCoverageSchema      = "aegrail.agent.config_coverage.v1"
	ServerConfigCoverageStateSchema = "aegrail.agent.config_coverage_state.v1"
)

type ServerConfigCoverageRunResult struct {
	Sites  int
	Queued int
}

type ServerConfigCoverageReport struct {
	Schema      string                     `json:"schema"`
	ReportedAt  time.Time                  `json:"reported_at"`
	Org         string                     `json:"org"`
	Project     string                     `json:"project"`
	Environment string                     `json:"environment"`
	Host        string                     `json:"host"`
	AgentID     string                     `json:"agent_id"`
	Region      string                     `json:"region,omitempty"`
	Site        ServerConfigCoverageSite   `json:"site"`
	Coverage    ServerConfigCoverageDetail `json:"coverage"`
	Signature   string                     `json:"signature"`
}

type ServerConfigCoverageSite struct {
	Slug    string            `json:"slug"`
	Name    string            `json:"name,omitempty"`
	Domain  string            `json:"domain,omitempty"`
	Kind    string            `json:"kind"`
	App     string            `json:"app"`
	Service string            `json:"service"`
	Root    string            `json:"root,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

type ServerConfigCoverageDetail struct {
	Level      string                        `json:"level"`
	Files      ServerConfigCoverageFiles     `json:"files"`
	Logs       ServerConfigCoverageLogs      `json:"logs"`
	Databases  ServerConfigCoverageDatabases `json:"databases"`
	Browser    ServerConfigCoverageBrowser   `json:"browser"`
	WordPress  ServerConfigCoverageWordPress `json:"wordpress,omitempty"`
	Collectors []string                      `json:"collectors"`
}

type ServerConfigCoverageFiles struct {
	Enabled         bool     `json:"enabled"`
	Profiles        []string `json:"profiles,omitempty"`
	ExtraPaths      int      `json:"extra_paths"`
	ExcludePatterns int      `json:"exclude_patterns"`
}

type ServerConfigCoverageLogs struct {
	Enabled bool     `json:"enabled"`
	Count   int      `json:"count"`
	Kinds   []string `json:"kinds,omitempty"`
}

type ServerConfigCoverageDatabases struct {
	Enabled             bool     `json:"enabled"`
	Count               int      `json:"count"`
	Names               []string `json:"names,omitempty"`
	Engines             []string `json:"engines,omitempty"`
	Profiles            []string `json:"profiles,omitempty"`
	AllDSNEnvConfigured bool     `json:"all_dsn_env_configured"`
}

type ServerConfigCoverageBrowser struct {
	Enabled        bool `json:"enabled"`
	Rendered       bool `json:"rendered"`
	WaitTagManager bool `json:"wait_tag_manager"`
	MaxPages       int  `json:"max_pages"`
	URLs           int  `json:"urls"`
}

type ServerConfigCoverageWordPress struct {
	Multisite    bool `json:"multisite"`
	NetworkSites int  `json:"network_sites"`
}

type serverConfigCoverageState struct {
	Schema    string            `json:"schema"`
	UpdatedAt time.Time         `json:"updated_at"`
	Sites     map[string]string `json:"sites"`
}

func BuildServerConfigCoverageReports(config ServerConfig, reportedAt time.Time) []ServerConfigCoverageReport {
	config = NormalizeServerConfig(config)
	if reportedAt.IsZero() {
		reportedAt = time.Now().UTC()
	}
	reports := make([]ServerConfigCoverageReport, 0, len(config.Sites))
	for _, site := range config.Sites {
		report := ServerConfigCoverageReport{
			Schema:      ServerConfigCoverageSchema,
			ReportedAt:  reportedAt.UTC(),
			Org:         config.Identity.Org,
			Project:     config.Identity.Project,
			Environment: config.Identity.Environment,
			Host:        config.Identity.Host,
			AgentID:     config.Identity.AgentID,
			Region:      config.Identity.Region,
			Site: ServerConfigCoverageSite{
				Slug:    site.Slug,
				Name:    site.Name,
				Domain:  site.Domain,
				Kind:    site.Kind,
				App:     site.App,
				Service: site.Service,
				Root:    site.Root,
				Labels:  cloneStringMap(site.Labels),
			},
			Coverage: serverConfigCoverageDetail(site),
		}
		report.Signature = serverConfigCoverageSignature(report)
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i int, j int) bool {
		return reports[i].Site.Slug < reports[j].Site.Slug
	})
	return reports
}

func (r *Runtime) QueueServerConfigCoverage(ctx context.Context, config ServerConfig) (ServerConfigCoverageRunResult, error) {
	config = NormalizeServerConfig(config)
	if err := ValidateServerConfig(config); err != nil {
		return ServerConfigCoverageRunResult{}, err
	}
	identity := config.AgentIdentity()
	r.Config.Identity = &identity
	r.Config.QueueDir = identity.QueueDir
	if err := ensureQueueDirs(identity.QueueDir); err != nil {
		return ServerConfigCoverageRunResult{}, err
	}

	now := r.now().UTC()
	reports := BuildServerConfigCoverageReports(config, now)
	statePath := filepath.Join(config.Runtime.StateDir, "config-coverage.json")
	previous, _, err := loadServerConfigCoverageState(statePath)
	if err != nil {
		return ServerConfigCoverageRunResult{}, err
	}
	nextState := serverConfigCoverageState{
		Schema:    ServerConfigCoverageStateSchema,
		UpdatedAt: now,
		Sites:     map[string]string{},
	}

	result := ServerConfigCoverageRunResult{Sites: len(reports)}
	for _, report := range reports {
		nextState.Sites[report.Site.Slug] = report.Signature
		if previous.Sites[report.Site.Slug] == report.Signature {
			continue
		}
		labels := siteEventLabels(ServerSiteConfig{
			Slug:   report.Site.Slug,
			Domain: report.Site.Domain,
			Kind:   report.Site.Kind,
			Labels: report.Site.Labels,
		})
		labels["coverage_level"] = report.Coverage.Level
		if _, _, err := r.EnqueueEvents(ctx, EnqueueEventsInput{
			BatchID: "coverage-" + safeFilename(report.Site.Slug) + "-" + now.Format("20060102T150405.000000000Z"),
			App:     report.Site.App,
			Service: report.Site.Service,
			Source:  "agent.coverage",
			Region:  config.Identity.Region,
			Labels:  labels,
			Events: []EnqueueEventInput{
				{
					EventTime: report.ReportedAt,
					Type:      "agent.config.coverage",
					Target:    report.Site.Slug,
					Severity:  coverageLevelSeverity(report.Coverage.Level),
					Message:   "Agent config coverage reported for " + report.Site.Slug + " (" + report.Coverage.Level + ")",
					Labels:    labels,
					Payload:   serverConfigCoveragePayload(report),
				},
			},
		}); err != nil {
			return ServerConfigCoverageRunResult{}, err
		}
		result.Queued++
	}
	if err := saveServerConfigCoverageState(statePath, nextState); err != nil {
		return ServerConfigCoverageRunResult{}, err
	}
	return result, nil
}

func serverConfigCoverageDetail(site ServerSiteConfig) ServerConfigCoverageDetail {
	files := ServerConfigCoverageFiles{
		Enabled:         len(site.Files.Profiles) > 0 || len(site.Files.ExtraPaths) > 0,
		Profiles:        append([]string(nil), site.Files.Profiles...),
		ExtraPaths:      len(site.Files.ExtraPaths),
		ExcludePatterns: len(site.Files.Exclude),
	}
	logs := ServerConfigCoverageLogs{
		Enabled: len(site.Logs) > 0,
		Count:   len(site.Logs),
		Kinds:   serverLogKinds(site.Logs),
	}
	databases := ServerConfigCoverageDatabases{
		Enabled:             len(site.Databases) > 0,
		Count:               len(site.Databases),
		Names:               serverDatabaseNames(site),
		Engines:             serverDatabaseEngines(site.Databases),
		Profiles:            serverDatabaseProfiles(site),
		AllDSNEnvConfigured: serverDatabasesHaveDSNEnv(site.Databases),
	}
	browser := ServerConfigCoverageBrowser{
		Enabled:        site.BrowserCrawl.Enabled,
		Rendered:       site.BrowserCrawl.Rendered,
		WaitTagManager: site.BrowserCrawl.WaitTagManager,
		MaxPages:       site.BrowserCrawl.MaxPages,
		URLs:           len(site.BrowserCrawl.URLs),
	}
	collectors := enabledCoverageCollectors(files, logs, databases, browser)
	return ServerConfigCoverageDetail{
		Level:      coverageLevel(files.Enabled, logs.Enabled, databases.Enabled, browser.Enabled),
		Files:      files,
		Logs:       logs,
		Databases:  databases,
		Browser:    browser,
		WordPress:  ServerConfigCoverageWordPress{Multisite: site.WordPress.Multisite, NetworkSites: len(site.WordPress.NetworkSites)},
		Collectors: collectors,
	}
}

func enabledCoverageCollectors(files ServerConfigCoverageFiles, logs ServerConfigCoverageLogs, databases ServerConfigCoverageDatabases, browser ServerConfigCoverageBrowser) []string {
	var collectors []string
	if files.Enabled {
		collectors = append(collectors, "files")
	}
	if logs.Enabled {
		collectors = append(collectors, "logs")
	}
	if databases.Enabled {
		collectors = append(collectors, "databases")
	}
	if browser.Enabled {
		collectors = append(collectors, "browser")
	}
	return collectors
}

func coverageLevel(files bool, logs bool, databases bool, browser bool) string {
	count := 0
	for _, enabled := range []bool{files, logs, databases, browser} {
		if enabled {
			count++
		}
	}
	switch {
	case count == 0:
		return "none"
	case files && logs && databases && browser:
		return "complete"
	case files && databases:
		return "strong"
	default:
		return "partial"
	}
}

func coverageLevelSeverity(level string) string {
	switch level {
	case "none":
		return "medium"
	case "partial":
		return "low"
	default:
		return "info"
	}
}

func serverLogKinds(logs []ServerLogConfig) []string {
	seen := map[string]struct{}{}
	for _, log := range logs {
		kind := strings.TrimSpace(log.Kind)
		if kind == "" {
			kind = "generic"
		}
		seen[kind] = struct{}{}
	}
	return sortedStringKeys(seen)
}

func serverDatabaseNames(site ServerSiteConfig) []string {
	seen := map[string]struct{}{}
	for _, database := range site.Databases {
		name := strings.TrimSpace(database.Name)
		if name == "" {
			name = coverageDatabaseProfile(site, database)
		}
		if name == "" {
			name = "database"
		}
		seen[name] = struct{}{}
	}
	return sortedStringKeys(seen)
}

func serverDatabaseEngines(databases []ServerDatabaseConfig) []string {
	seen := map[string]struct{}{}
	for _, database := range databases {
		engine := strings.TrimSpace(database.Engine)
		if engine == "" {
			engine = "mysql"
		}
		seen[engine] = struct{}{}
	}
	return sortedStringKeys(seen)
}

func serverDatabaseProfiles(site ServerSiteConfig) []string {
	seen := map[string]struct{}{}
	for _, database := range site.Databases {
		profile := coverageDatabaseProfile(site, database)
		if profile != "" {
			seen[profile] = struct{}{}
		}
	}
	return sortedStringKeys(seen)
}

func coverageDatabaseProfile(site ServerSiteConfig, database ServerDatabaseConfig) string {
	profile := strings.TrimSpace(database.Profile)
	if profile == "" {
		profile = site.Kind
	}
	switch strings.ToLower(profile) {
	case "wp", "woocommerce", "wordpress-multisite":
		return "wordpress"
	case "ps":
		return "prestashop"
	default:
		return strings.ToLower(profile)
	}
}

func serverDatabasesHaveDSNEnv(databases []ServerDatabaseConfig) bool {
	if len(databases) == 0 {
		return false
	}
	for _, database := range databases {
		if strings.TrimSpace(database.DSNEnv) == "" {
			return false
		}
	}
	return true
}

func sortedStringKeys(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			items = append(items, value)
		}
	}
	sort.Strings(items)
	return items
}

func serverConfigCoverageSignature(report ServerConfigCoverageReport) string {
	fingerprint := struct {
		Site     ServerConfigCoverageSite   `json:"site"`
		Coverage ServerConfigCoverageDetail `json:"coverage"`
	}{
		Site:     report.Site,
		Coverage: report.Coverage,
	}
	content, _ := json.Marshal(fingerprint)
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func serverConfigCoveragePayload(report ServerConfigCoverageReport) map[string]any {
	content, _ := json.Marshal(report)
	var payload map[string]any
	_ = json.Unmarshal(content, &payload)
	if payload == nil {
		return map[string]any{}
	}
	return payload
}

func loadServerConfigCoverageState(path string) (serverConfigCoverageState, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return serverConfigCoverageState{Sites: map[string]string{}}, false, nil
	}
	if err != nil {
		return serverConfigCoverageState{}, false, err
	}
	var state serverConfigCoverageState
	if err := json.Unmarshal(content, &state); err != nil {
		return serverConfigCoverageState{}, false, err
	}
	if state.Schema != ServerConfigCoverageStateSchema {
		return serverConfigCoverageState{}, false, errors.New("unsupported config coverage state schema")
	}
	if state.Sites == nil {
		state.Sites = map[string]string{}
	}
	return state, true, nil
}

func saveServerConfigCoverageState(path string, state serverConfigCoverageState) error {
	state.Schema = ServerConfigCoverageStateSchema
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	if state.Sites == nil {
		state.Sites = map[string]string{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}
