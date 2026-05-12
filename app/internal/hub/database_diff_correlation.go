package hub

import (
	"fmt"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type databaseSnapshotRule struct {
	RuleID     string
	Title      string
	Severity   domain.Severity
	Confidence domain.Confidence
}

func isDatabaseSnapshotDiffEvent(event domain.TimelineEvent) bool {
	switch event.EventType {
	case "db.snapshot.check_changed", "db.snapshot.check_added":
		return true
	default:
		return false
	}
}

func buildDatabaseSnapshotDiffChain(event domain.TimelineEvent) CorrelationChain {
	rule := databaseSnapshotRuleForEvent(event)
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
		ID:         databaseSnapshotDiffChainID(rule.RuleID, event),
		RuleID:     rule.RuleID,
		Title:      rule.Title,
		Severity:   rule.Severity,
		Confidence: rule.Confidence,
		Summary:    databaseSnapshotDiffSummary(event),
		Events:     []CorrelationEvent{chainEvent},
	}
}

func databaseSnapshotRuleForEvent(event domain.TimelineEvent) databaseSnapshotRule {
	profile := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "profile", ""),
		event.Labels["db_profile"],
	))
	check := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "check", ""),
		event.Labels["db_check"],
		event.Target,
	))
	metric := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "metric", ""),
		event.Labels["db_metric"],
	))
	text := check + " " + metric + " " + strings.ToLower(event.Target)

	switch profile {
	case "wordpress", "wp":
		return wordpressDatabaseSnapshotRule(text, event)
	case "prestashop", "ps":
		return prestashopDatabaseSnapshotRule(text, event)
	default:
		return databaseSnapshotRule{
			RuleID:     "database-snapshot-check-changed",
			Title:      "Database snapshot check changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func wordpressDatabaseSnapshotRule(text string, event domain.TimelineEvent) databaseSnapshotRule {
	switch {
	case strings.Contains(text, "admin_users") || strings.Contains(text, "administrator"):
		return databaseSnapshotRule{
			RuleID:     "wordpress-admin-users-changed",
			Title:      "WordPress administrator count changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "active_plugins"):
		return databaseSnapshotRule{
			RuleID:     "wordpress-active-plugins-changed",
			Title:      "WordPress active plugins changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "theme") || strings.Contains(text, "stylesheet") || strings.Contains(text, "template"):
		return databaseSnapshotRule{
			RuleID:     "wordpress-theme-option-changed",
			Title:      "WordPress active theme changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "cron"):
		return databaseSnapshotRule{
			RuleID:     "wordpress-cron-option-changed",
			Title:      "WordPress cron option changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "users"):
		return databaseSnapshotRule{
			RuleID:     "wordpress-users-changed",
			Title:      "WordPress user count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "options"):
		return databaseSnapshotRule{
			RuleID:     "wordpress-options-changed",
			Title:      "WordPress option count changed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "wordpress-database-check-changed",
			Title:      "WordPress database check changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func prestashopDatabaseSnapshotRule(text string, event domain.TimelineEvent) databaseSnapshotRule {
	switch {
	case strings.Contains(text, "active_employees") || strings.Contains(text, "employees"):
		return databaseSnapshotRule{
			RuleID:     "prestashop-employees-changed",
			Title:      "PrestaShop employee count changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "active_modules") || strings.Contains(text, "modules"):
		return databaseSnapshotRule{
			RuleID:     "prestashop-modules-changed",
			Title:      "PrestaShop module count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "configuration"):
		return databaseSnapshotRule{
			RuleID:     "prestashop-configuration-changed",
			Title:      "PrestaShop configuration count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "access"):
		return databaseSnapshotRule{
			RuleID:     "prestashop-access-rules-changed",
			Title:      "PrestaShop access rules changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "hooks"):
		return databaseSnapshotRule{
			RuleID:     "prestashop-hooks-changed",
			Title:      "PrestaShop hook count changed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "tabs"):
		return databaseSnapshotRule{
			RuleID:     "prestashop-tabs-changed",
			Title:      "PrestaShop tab count changed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "prestashop-database-check-changed",
			Title:      "PrestaShop database check changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func databaseSnapshotDiffChainID(ruleID string, event domain.TimelineEvent) string {
	current := payloadMap(event.Payload, "current")
	signature := payloadStringAny(current, "signature", "")
	if signature == "" {
		signature = string(event.ID)
	}
	parts := []string{
		ruleID,
		string(event.EnvironmentID),
		string(event.AppID),
		event.Target,
		payloadStringAny(event.Payload, "check", ""),
		signature,
	}
	return "corr-" + sha256Short(strings.Join(parts, "\n"))
}

func databaseSnapshotDiffSummary(event domain.TimelineEvent) string {
	target := event.Target
	if target == "" {
		target = payloadStringAny(event.Payload, "check", "")
	}
	host := event.HostSlug
	if host == "" {
		host = "unknown-host"
	}
	change := databaseSnapshotChangeSummary(event)
	if change != "" {
		return fmt.Sprintf("%s %s %s %s", host, event.EventType, target, change)
	}
	return fmt.Sprintf("%s %s %s", host, event.EventType, target)
}

func databaseSnapshotChangeSummary(event domain.TimelineEvent) string {
	previous := payloadMap(event.Payload, "previous")
	current := payloadMap(event.Payload, "current")
	previousCount, previousOK := payloadInt64(previous, "count")
	currentCount, currentOK := payloadInt64(current, "count")
	if previousOK && currentOK {
		return fmt.Sprintf("count %d -> %d", previousCount, currentCount)
	}
	previousHash := payloadStringAny(previous, "value_sha256", "")
	currentHash := payloadStringAny(current, "value_sha256", "")
	if previousHash != "" && currentHash != "" && previousHash != currentHash {
		return "digest changed"
	}
	return ""
}

func payloadMap(payload map[string]any, key string) map[string]any {
	value, ok := payload[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, value := range typed {
			converted[key] = value
		}
		return converted
	default:
		return nil
	}
}

func payloadInt64(payload map[string]any, key string) (int64, bool) {
	if payload == nil {
		return 0, false
	}
	switch value := payload[key].(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		return int64(value), true
	case string:
		var parsed int64
		if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil {
			return parsed, true
		}
		return 0, false
	default:
		return 0, false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func maxSeverity(a domain.Severity, b domain.Severity) domain.Severity {
	if severityRank(a) >= severityRank(b) {
		return a
	}
	return b
}
