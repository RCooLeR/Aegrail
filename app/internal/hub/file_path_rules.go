package hub

import (
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type filePathRule struct {
	RuleID     string
	Title      string
	Severity   domain.Severity
	Confidence domain.Confidence
	Reason     string
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

func suspiciousFilePathRuleForEvent(event domain.TimelineEvent) (filePathRule, bool) {
	if !strings.HasPrefix(event.EventType, "file.") || event.EventType == "file.deleted" {
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
	case filePathIsWritableExecutable(path):
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
