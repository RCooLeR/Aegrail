package hub

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type filePathRule struct {
	RuleID     string
	Title      string
	Severity   domain.Severity
	Confidence domain.Confidence
	Reason     string
}

const filePathGroupListLimit = 25

type filePathGroupInfo struct {
	Key   string
	Kind  string
	Name  string
	Root  string
	Label string
}

type filePathEventGroup struct {
	Key         string
	Bucket      string
	Rule        filePathRule
	Info        filePathGroupInfo
	Events      []domain.TimelineEvent
	Paths       []string
	EventCounts map[string]int
	Severity    domain.Severity
}

func buildSuspiciousFilePathChain(event domain.TimelineEvent) (CorrelationChain, bool) {
	rule, ok := suspiciousFilePathRuleForEvent(event)
	if !ok {
		return CorrelationChain{}, false
	}
	chainEvent := CorrelationEvent{
		EventID:   event.ID,
		EventTime: event.EventTime,
		HostSlug:  event.HostSlug,
		EventType: event.EventType,
		Target:    event.Target,
		Severity:  event.Severity,
		Message:   event.Message,
	}
	return CorrelationChain{
		ID:         filePathRuleChainID(rule.RuleID, event),
		RuleID:     rule.RuleID,
		Title:      rule.Title,
		Severity:   rule.Severity,
		Confidence: rule.Confidence,
		Summary:    filePathRuleSummary(rule, event),
		Events:     []CorrelationEvent{chainEvent},
	}, true
}

func buildSuspiciousFilePathChains(events []domain.TimelineEvent, coveredFileEvents map[string]struct{}) []CorrelationChain {
	chains := make([]CorrelationChain, 0)
	groups := map[string]*filePathEventGroup{}
	groupOrder := make([]string, 0)

	for _, event := range events {
		if _, covered := coveredFileEvents[correlationEventKey(event)]; covered {
			continue
		}
		rule, ok := suspiciousFilePathRuleForEvent(event)
		if !ok {
			continue
		}
		info, grouped := filePathGroupForEvent(rule, event)
		if !grouped {
			chain, ok := buildSuspiciousFilePathChain(event)
			if ok {
				chains = append(chains, chain)
			}
			continue
		}

		bucket := filePathGroupTimeBucket(event)
		key := filePathGroupChainID(rule.RuleID, event, info, bucket)
		group, ok := groups[key]
		if !ok {
			group = &filePathEventGroup{
				Key:         key,
				Bucket:      bucket,
				Rule:        rule,
				Info:        info,
				EventCounts: map[string]int{},
				Severity:    rule.Severity,
			}
			groups[key] = group
			groupOrder = append(groupOrder, key)
		}
		group.Events = append(group.Events, event)
		group.EventCounts[event.EventType]++
		group.Severity = maxSeverity(group.Severity, rule.Severity)
		group.Paths = appendUniqueString(group.Paths, displayFileEventPath(event))
	}

	for _, key := range groupOrder {
		chains = append(chains, buildSuspiciousFilePathGroupChain(*groups[key]))
	}
	return chains
}

func filterIgnoredTimelineEvents(events []domain.TimelineEvent, rules []domain.HubFileIgnoreRule) []domain.TimelineEvent {
	if len(events) == 0 || len(rules) == 0 {
		return events
	}
	filtered := make([]domain.TimelineEvent, 0, len(events))
	for _, event := range events {
		if fileEventIgnored(event, rules) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func fileEventIgnored(event domain.TimelineEvent, rules []domain.HubFileIgnoreRule) bool {
	if !isFileMutationEventType(event.EventType) {
		return false
	}
	eventPath := normalizeFileIgnorePath(normalizedFileEventPath(event))
	if eventPath == "" {
		return false
	}
	for _, rule := range rules {
		if rule.Status != "" && rule.Status != "active" {
			continue
		}
		if rule.MatchKind != "file_path_prefix" {
			continue
		}
		prefix := normalizeFileIgnorePath(rule.NormalizedValue)
		if prefix == "" {
			prefix = normalizeFileIgnorePath(rule.MatchValue)
		}
		if eventPath == prefix || strings.HasPrefix(eventPath, prefix+"/") {
			return true
		}
	}
	return false
}

func suspiciousFilePathRuleForEvent(event domain.TimelineEvent) (filePathRule, bool) {
	if !isFileMutationEventType(event.EventType) || event.EventType == "file.deleted" {
		return filePathRule{}, false
	}
	path := normalizedFileEventPath(event)
	if path == "" {
		return filePathRule{}, false
	}
	switch {
	case filePathIsSensitiveConfig(path):
		return filePathRule{
			RuleID:     "file-sensitive-config-changed",
			Title:      "Sensitive configuration file changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
			Reason:     "sensitive configuration path",
		}, true
	case fileEventIsKnownBenignPHPGuard(event, path):
		return filePathRule{}, false
	case filePathIsWritableExecutable(path) && !filePathIsPotentialPrestaShopAssetGuard(path):
		return filePathRule{
			RuleID:     "file-php-in-writable-path",
			Title:      "PHP executable in writable path",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
			Reason:     "PHP-like file under writable content directory",
		}, true
	case filePathHasSuspiciousPattern(path):
		return filePathRule{
			RuleID:     "file-suspicious-path-pattern",
			Title:      "Suspicious file path pattern",
			Severity:   maxSeverity(event.Severity, domain.SeverityMedium),
			Confidence: domain.ConfidenceMedium,
			Reason:     "path contains a suspicious filename or extension pattern",
		}, true
	case filePathIsPluginThemeOrModule(path):
		return filePathRule{
			RuleID:     "file-plugin-theme-module-changed",
			Title:      "Plugin, theme, or module file changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityMedium),
			Confidence: domain.ConfidenceMedium,
			Reason:     "plugin, theme, or module path",
		}, true
	case looksPHP(path):
		return filePathRule{
			RuleID:     "file-php-changed",
			Title:      "PHP executable file changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityMedium),
			Confidence: domain.ConfidenceMedium,
			Reason:     "PHP-like executable path",
		}, true
	default:
		return filePathRule{}, false
	}
}

func normalizedFileEventPath(event domain.TimelineEvent) string {
	path := strings.ToLower(payloadStringAny(event.Payload, "relative_path", event.Target))
	if path == "" {
		path = strings.ToLower(event.Target)
	}
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimSpace(path)
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return strings.TrimPrefix(path, "./")
}

func displayFileEventPath(event domain.TimelineEvent) string {
	path := payloadStringAny(event.Payload, "relative_path", event.Target)
	if path == "" {
		path = event.Target
	}
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimSpace(path)
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return strings.TrimPrefix(path, "./")
}

func filePathIsSensitiveConfig(path string) bool {
	return strings.HasSuffix(path, "wp-config.php") ||
		strings.HasSuffix(path, "settings.inc.php") ||
		strings.HasSuffix(path, "parameters.php") ||
		strings.HasSuffix(path, "/.env") ||
		path == ".env" ||
		strings.HasSuffix(path, "/.user.ini") ||
		path == ".user.ini" ||
		strings.HasSuffix(path, "/.htaccess") ||
		path == ".htaccess"
}

func filePathIsWritableExecutable(path string) bool {
	if !looksPHP(path) {
		return false
	}
	return strings.Contains(path, "/uploads/") ||
		strings.HasPrefix(path, "uploads/") ||
		strings.Contains(path, "/upload/") ||
		strings.HasPrefix(path, "upload/") ||
		strings.Contains(path, "/files/") ||
		strings.HasPrefix(path, "files/") ||
		strings.Contains(path, "/media/") ||
		strings.HasPrefix(path, "media/") ||
		strings.Contains(path, "/img/") ||
		strings.HasPrefix(path, "img/") ||
		strings.Contains(path, "/cache/") ||
		strings.HasPrefix(path, "cache/") ||
		strings.Contains(path, "/tmp/") ||
		strings.HasPrefix(path, "tmp/") ||
		strings.Contains(path, "/storage/") ||
		strings.HasPrefix(path, "storage/")
}

func fileEventIsKnownBenignPHPGuard(event domain.TimelineEvent, path string) bool {
	if !filePathIsPotentialPrestaShopAssetGuard(path) {
		return false
	}
	return payloadStringAny(event.Payload, "file_kind", "") == "prestashop_asset_guard_index" &&
		payloadStringAny(event.Payload, "file_role", "") == "directory_guard" &&
		payloadStringAny(event.Payload, "file_role_confidence", "") == "high"
}

func filePathIsPotentialPrestaShopAssetGuard(path string) bool {
	if !strings.HasSuffix(path, "/index.php") && path != "index.php" {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for index := 0; index < len(parts); index++ {
		if parts[index] == "modules" && index+3 < len(parts) &&
			parts[index+2] == "views" && filePathIsPrestaShopAssetViewDir(parts[index+3]) {
			return true
		}
		if parts[index] == "themes" && index+5 < len(parts) &&
			parts[index+2] == "modules" && parts[index+4] == "views" &&
			filePathIsPrestaShopAssetViewDir(parts[index+5]) {
			return true
		}
	}
	return false
}

func filePathIsPrestaShopAssetViewDir(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "css", "font", "fonts", "img", "image", "images", "js":
		return true
	default:
		return false
	}
}

func filePathHasSuspiciousPattern(path string) bool {
	filename := path
	if index := strings.LastIndex(filename, "/"); index >= 0 {
		filename = filename[index+1:]
	}
	if strings.Contains(path, ".php.") || strings.Contains(path, ".phtml.") || strings.Contains(path, ".phar.") {
		return true
	}
	for _, marker := range []string{
		"backdoor",
		"c99",
		"cmd",
		"eval",
		"r57",
		"shell",
		"webshell",
		"wso",
	} {
		if strings.Contains(filename, marker) {
			return true
		}
	}
	return false
}

func filePathIsPluginThemeOrModule(path string) bool {
	return strings.Contains(path, "/plugins/") ||
		strings.Contains(path, "/themes/") ||
		strings.Contains(path, "/modules/") ||
		strings.HasPrefix(path, "plugins/") ||
		strings.HasPrefix(path, "themes/") ||
		strings.HasPrefix(path, "modules/")
}

func filePathGroupForEvent(rule filePathRule, event domain.TimelineEvent) (filePathGroupInfo, bool) {
	if rule.RuleID != "file-plugin-theme-module-changed" {
		return filePathGroupInfo{}, false
	}
	parts := strings.Split(normalizedFileEventPath(event), "/")
	for index := 0; index < len(parts); index++ {
		if parts[index] == "" {
			continue
		}
		if parts[index] == "wp-content" && index+2 < len(parts) {
			switch parts[index+1] {
			case "plugins":
				return buildFilePathGroupInfo("wordpress_plugin", "WordPress plugin", parts[index+2], strings.Join(parts[index:index+3], "/")), true
			case "themes":
				return buildFilePathGroupInfo("wordpress_theme", "WordPress theme", parts[index+2], strings.Join(parts[index:index+3], "/")), true
			}
		}
		if parts[index] == "modules" && index+1 < len(parts) {
			return buildFilePathGroupInfo("prestashop_module", "PrestaShop module", parts[index+1], strings.Join(parts[index:index+2], "/")), true
		}
		if parts[index] == "plugins" && index+1 < len(parts) {
			return buildFilePathGroupInfo("plugin", "Plugin", parts[index+1], strings.Join(parts[index:index+2], "/")), true
		}
		if parts[index] == "themes" && index+1 < len(parts) {
			return buildFilePathGroupInfo("theme", "Theme", parts[index+1], strings.Join(parts[index:index+2], "/")), true
		}
	}
	return filePathGroupInfo{}, false
}

func buildFilePathGroupInfo(kind string, labelPrefix string, name string, root string) filePathGroupInfo {
	name = strings.TrimSpace(name)
	root = strings.TrimSpace(root)
	label := labelPrefix
	if name != "" {
		label += " " + name
	}
	return filePathGroupInfo{
		Key:   kind + ":" + root,
		Kind:  kind,
		Name:  name,
		Root:  root,
		Label: label,
	}
}

func filePathRuleChainID(ruleID string, event domain.TimelineEvent) string {
	path := normalizedFileEventPath(event)
	sha := payloadStringAny(event.Payload, "sha256", "")
	if sha == "" {
		sha = payloadStringAny(event.Payload, "current_sha256", "")
	}
	parts := []string{
		ruleID,
		string(event.EnvironmentID),
		string(event.AppID),
		string(event.HostID),
		event.HostSlug,
		event.EventType,
		path,
		sha,
	}
	return "file-rule-" + sha256Short(strings.Join(parts, "\n"))
}

func filePathGroupChainID(ruleID string, event domain.TimelineEvent, group filePathGroupInfo, bucket string) string {
	parts := []string{
		ruleID,
		string(event.EnvironmentID),
		string(event.AppID),
		string(event.HostID),
		event.HostSlug,
		group.Key,
		bucket,
	}
	return "file-group-" + sha256Short(strings.Join(parts, "\n"))
}

func filePathGroupTimeBucket(event domain.TimelineEvent) string {
	if event.EventTime.IsZero() {
		return "unknown"
	}
	return event.EventTime.UTC().Truncate(time.Hour).Format(time.RFC3339)
}

func filePathRuleSummary(rule filePathRule, event domain.TimelineEvent) string {
	host := event.HostSlug
	if host == "" {
		host = "unknown-host"
	}
	target := normalizedFileEventPath(event)
	if target == "" {
		target = event.Target
	}
	return host + " " + event.EventType + " " + target + " (" + rule.Reason + ")"
}

func buildSuspiciousFilePathGroupChain(group filePathEventGroup) CorrelationChain {
	events := append([]domain.TimelineEvent(nil), group.Events...)
	slices.SortFunc(events, func(a domain.TimelineEvent, b domain.TimelineEvent) int {
		if a.EventTime.Equal(b.EventTime) {
			return strings.Compare(string(a.ID), string(b.ID))
		}
		if a.EventTime.Before(b.EventTime) {
			return -1
		}
		return 1
	})

	chainEvents := make([]CorrelationEvent, 0, len(events))
	for _, event := range events {
		chainEvents = append(chainEvents, CorrelationEvent{
			EventID:   event.ID,
			EventTime: event.EventTime,
			HostSlug:  event.HostSlug,
			EventType: event.EventType,
			Target:    displayFileEventPath(event),
			Severity:  event.Severity,
			Message:   event.Message,
		})
	}

	files := append([]string(nil), group.Paths...)
	displayFiles := files
	omitted := 0
	if len(displayFiles) > filePathGroupListLimit {
		omitted = len(displayFiles) - filePathGroupListLimit
		displayFiles = displayFiles[:filePathGroupListLimit]
	}

	return CorrelationChain{
		ID:         group.Key,
		RuleID:     group.Rule.RuleID,
		Title:      filePathGroupTitle(group),
		Severity:   group.Severity,
		Confidence: group.Rule.Confidence,
		Summary:    filePathGroupSummary(group),
		Events:     chainEvents,
		Metadata: map[string]any{
			"file_group":         true,
			"file_group_kind":    group.Info.Kind,
			"file_group_label":   group.Info.Label,
			"file_group_name":    group.Info.Name,
			"file_group_root":    group.Info.Root,
			"file_count":         len(files),
			"files":              displayFiles,
			"omitted_file_count": omitted,
			"event_type_counts":  group.EventCounts,
			"time_bucket":        group.Bucket,
		},
	}
}

func filePathGroupTitle(group filePathEventGroup) string {
	if group.Info.Name == "" {
		return group.Rule.Title
	}
	switch group.Info.Kind {
	case "wordpress_plugin":
		return "WordPress plugin files changed: " + group.Info.Name
	case "wordpress_theme":
		return "WordPress theme files changed: " + group.Info.Name
	case "prestashop_module":
		return "PrestaShop module files changed: " + group.Info.Name
	case "plugin":
		return "Plugin files changed: " + group.Info.Name
	case "theme":
		return "Theme files changed: " + group.Info.Name
	default:
		return group.Rule.Title + ": " + group.Info.Name
	}
}

func filePathGroupSummary(group filePathEventGroup) string {
	host := "unknown-host"
	if len(group.Events) > 0 && group.Events[0].HostSlug != "" {
		host = group.Events[0].HostSlug
	}
	action := filePathGroupAction(group.EventCounts)
	return fmt.Sprintf("%s observed %d %s file(s) under %s (%s)", host, len(group.Paths), action, group.Info.Root, group.Info.Label)
}

func filePathGroupAction(counts map[string]int) string {
	if len(counts) == 1 {
		if counts["file.created"] > 0 {
			return "created"
		}
		if counts["file.modified"] > 0 {
			return "modified"
		}
	}
	return "changed"
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
