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
	case "db.snapshot.check_changed", "db.snapshot.check_added", "db.entity.added", "db.entity.changed", "db.entity.removed":
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
	if strings.HasPrefix(event.EventType, "db.entity.") {
		return databaseEntityRuleForEvent(event)
	}
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

func databaseEntityRuleForEvent(event domain.TimelineEvent) databaseSnapshotRule {
	profile := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "profile", ""),
		event.Labels["db_profile"],
	))
	entityType := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "entity_type", ""),
		event.Labels["db_entity_type"],
	))
	current := payloadMap(event.Payload, "current")
	previous := payloadMap(event.Payload, "previous")
	currentAttributes := payloadMap(current, "attributes")
	previousAttributes := payloadMap(previous, "attributes")

	switch profile {
	case "wordpress", "wp":
		return wordpressDatabaseEntityRule(event, entityType, currentAttributes, previousAttributes)
	case "prestashop", "ps":
		return prestashopDatabaseEntityRule(event, entityType, currentAttributes, previousAttributes)
	default:
		return databaseSnapshotRule{
			RuleID:     "database-entity-changed",
			Title:      "Database entity changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func wordpressDatabaseEntityRule(event domain.TimelineEvent, entityType string, current map[string]any, previous map[string]any) databaseSnapshotRule {
	switch entityType {
	case "wordpress_user":
		currentAdmin := payloadBool(current, "administrator")
		previousAdmin := payloadBool(previous, "administrator")
		switch {
		case event.EventType == "db.entity.added" && currentAdmin:
			return databaseSnapshotRule{
				RuleID:     "wordpress-admin-user-added",
				Title:      "WordPress administrator added",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.changed" && currentAdmin && !previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "wordpress-user-became-admin",
				Title:      "WordPress user became administrator",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.changed":
			return databaseSnapshotRule{
				RuleID:     "wordpress-user-capabilities-changed",
				Title:      "WordPress user capabilities changed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.removed" && previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "wordpress-admin-user-removed",
				Title:      "WordPress administrator removed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceMedium,
			}
		default:
			return databaseSnapshotRule{
				RuleID:     "wordpress-user-entity-changed",
				Title:      "WordPress user changed",
				Severity:   maxSeverity(event.Severity, domain.SeverityLow),
				Confidence: domain.ConfidenceMedium,
			}
		}
	case "wordpress_plugin":
		switch event.EventType {
		case "db.entity.added":
			return databaseSnapshotRule{
				RuleID:     "wordpress-active-plugin-added",
				Title:      "WordPress active plugin added",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		case "db.entity.removed":
			return databaseSnapshotRule{
				RuleID:     "wordpress-active-plugin-removed",
				Title:      "WordPress active plugin removed",
				Severity:   domain.SeverityLow,
				Confidence: domain.ConfidenceMedium,
			}
		default:
			return databaseSnapshotRule{
				RuleID:     "wordpress-active-plugin-changed",
				Title:      "WordPress active plugin changed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceMedium,
			}
		}
	case "wordpress_theme":
		return databaseSnapshotRule{
			RuleID:     "wordpress-active-theme-changed",
			Title:      "WordPress active theme changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case "wordpress_option":
		return wordpressOptionEntityRule(event, current, previous)
	}
	return databaseSnapshotRule{
		RuleID:     "wordpress-database-entity-changed",
		Title:      "WordPress database entity changed",
		Severity:   maxSeverity(event.Severity, domain.SeverityLow),
		Confidence: domain.ConfidenceMedium,
	}
}

func wordpressOptionEntityRule(event domain.TimelineEvent, current map[string]any, previous map[string]any) databaseSnapshotRule {
	optionName := strings.ToLower(firstNonEmpty(
		payloadStringAny(current, "option_name", ""),
		payloadStringAny(previous, "option_name", ""),
	))
	switch optionName {
	case "active_plugins", "active_sitewide_plugins":
		return databaseSnapshotRule{
			RuleID:     "wordpress-active-plugins-option-changed",
			Title:      "WordPress active plugins option changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case "stylesheet", "template":
		return databaseSnapshotRule{
			RuleID:     "wordpress-theme-option-changed",
			Title:      "WordPress active theme option changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case "default_role", "users_can_register", "registration":
		return databaseSnapshotRule{
			RuleID:     "wordpress-registration-option-changed",
			Title:      "WordPress registration option changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case "site_admins":
		return databaseSnapshotRule{
			RuleID:     "wordpress-network-admins-option-changed",
			Title:      "WordPress network admins option changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case "siteurl", "home", "admin_email":
		return databaseSnapshotRule{
			RuleID:     "wordpress-identity-option-changed",
			Title:      "WordPress site identity option changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	default:
		if strings.HasSuffix(optionName, "user_roles") {
			return databaseSnapshotRule{
				RuleID:     "wordpress-user-roles-option-changed",
				Title:      "WordPress user roles option changed",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		}
		return databaseSnapshotRule{
			RuleID:     "wordpress-option-entity-changed",
			Title:      "WordPress tracked option changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityMedium),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func prestashopDatabaseEntityRule(event domain.TimelineEvent, entityType string, current map[string]any, previous map[string]any) databaseSnapshotRule {
	switch entityType {
	case "prestashop_employee":
		currentSuperAdmin := payloadBool(current, "super_admin")
		previousSuperAdmin := payloadBool(previous, "super_admin")
		switch {
		case event.EventType == "db.entity.added" && currentSuperAdmin:
			return databaseSnapshotRule{
				RuleID:     "prestashop-superadmin-employee-added",
				Title:      "PrestaShop SuperAdmin employee added",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.changed" && currentSuperAdmin && !previousSuperAdmin:
			return databaseSnapshotRule{
				RuleID:     "prestashop-employee-became-superadmin",
				Title:      "PrestaShop employee became SuperAdmin",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.changed":
			return databaseSnapshotRule{
				RuleID:     "prestashop-employee-changed",
				Title:      "PrestaShop employee changed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		default:
			return databaseSnapshotRule{
				RuleID:     "prestashop-employee-entity-changed",
				Title:      "PrestaShop employee entity changed",
				Severity:   maxSeverity(event.Severity, domain.SeverityLow),
				Confidence: domain.ConfidenceMedium,
			}
		}
	case "prestashop_module":
		if event.EventType == "db.entity.added" && payloadBool(current, "active") {
			return databaseSnapshotRule{
				RuleID:     "prestashop-active-module-added",
				Title:      "PrestaShop active module added",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		}
		return databaseSnapshotRule{
			RuleID:     "prestashop-module-entity-changed",
			Title:      "PrestaShop module changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "prestashop-database-entity-changed",
			Title:      "PrestaShop database entity changed",
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
		signature = payloadStringAny(payloadMap(event.Payload, "previous"), "signature", "")
	}
	if signature == "" {
		signature = string(event.ID)
	}
	parts := []string{
		ruleID,
		string(event.EnvironmentID),
		string(event.AppID),
		event.Target,
		payloadStringAny(event.Payload, "check", ""),
		payloadStringAny(event.Payload, "entity_key", ""),
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
	entity := payloadStringAny(event.Payload, "entity_type", "")
	if entity != "" {
		return strings.TrimPrefix(event.EventType, "db.entity.") + " " + entity
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

func payloadBool(payload map[string]any, key string) bool {
	if payload == nil {
		return false
	}
	switch value := payload[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "1", "yes":
			return true
		default:
			return false
		}
	case int:
		return value != 0
	case int64:
		return value != 0
	case float64:
		return value != 0
	default:
		return false
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
