package hub

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rcooler/aegrail/hub/internal/domain"
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
		if isPrestashopModuleCountSnapshotEvent(event) {
			return false
		}
		if isPrestashopModuleEntityEvent(event) {
			return prestashopModuleEntityShouldAlert(event)
		}
		if isMauticExtensionCountSnapshotEvent(event) {
			return false
		}
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
		Title:      databaseSnapshotDiffTitle(rule.Title, event),
		Severity:   rule.Severity,
		Confidence: rule.Confidence,
		Summary:    databaseSnapshotDiffSummary(event),
		Events:     []CorrelationEvent{chainEvent},
		Metadata:   databaseSnapshotDiffMetadata(event),
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
	case "mautic":
		return mauticDatabaseSnapshotRule(text, event)
	case "yii2-rbac":
		return yii2RBACDatabaseSnapshotRule(text, event)
	case "laravel":
		return laravelDatabaseSnapshotRule(text, event)
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
	case "mautic":
		return mauticDatabaseEntityRule(event, entityType, currentAttributes, previousAttributes)
	case "yii2-rbac":
		return yii2RBACDatabaseEntityRule(event, entityType, currentAttributes, previousAttributes)
	case "laravel":
		return laravelDatabaseEntityRule(event, entityType, currentAttributes, previousAttributes)
	default:
		return databaseSnapshotRule{
			RuleID:     "database-entity-changed",
			Title:      "Database entity changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func yii2RBACDatabaseSnapshotRule(text string, event domain.TimelineEvent) databaseSnapshotRule {
	switch {
	case strings.Contains(text, "admin_roles") || strings.Contains(text, "admin_auth_assignments"):
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-admin-access-count-changed",
			Title:      "Yii2 RBAC admin access count changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "roles") || strings.Contains(text, "auth_assignments") || strings.Contains(text, "rbac"):
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-access-model-changed",
			Title:      "Yii2 RBAC access model changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "users"):
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-users-count-changed",
			Title:      "Yii2 RBAC user count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "migration"):
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-migrations-changed",
			Title:      "Yii2 RBAC migrations changed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-database-check-changed",
			Title:      "Yii2 RBAC database check changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func yii2RBACDatabaseEntityRule(event domain.TimelineEvent, entityType string, current map[string]any, previous map[string]any) databaseSnapshotRule {
	currentAdmin := payloadBool(current, "admin_role") || payloadBool(current, "admin_like")
	previousAdmin := payloadBool(previous, "admin_role") || payloadBool(previous, "admin_like")
	switch entityType {
	case "yii2_rbac_user":
		switch {
		case event.EventType == "db.entity.added" && currentAdmin:
			return databaseSnapshotRule{
				RuleID:     "yii2-rbac-admin-user-added",
				Title:      "Yii2 RBAC admin user added",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.changed" && currentAdmin && !previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "yii2-rbac-user-became-admin",
				Title:      "Yii2 RBAC user became admin",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.removed" && previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "yii2-rbac-admin-user-removed",
				Title:      "Yii2 RBAC admin user removed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceMedium,
			}
		case event.EventType == "db.entity.changed":
			return databaseSnapshotRule{
				RuleID:     "yii2-rbac-user-access-changed",
				Title:      "Yii2 RBAC user access changed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		default:
			return databaseSnapshotRule{
				RuleID:     "yii2-rbac-user-changed",
				Title:      "Yii2 RBAC user changed",
				Severity:   maxSeverity(event.Severity, domain.SeverityLow),
				Confidence: domain.ConfidenceMedium,
			}
		}
	case "yii2_rbac_role_assignment", "yii2_rbac_assignment", "yii2_rbac_item":
		if currentAdmin || previousAdmin {
			return databaseSnapshotRule{
				RuleID:     "yii2-rbac-admin-role-changed",
				Title:      "Yii2 RBAC admin role changed",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		}
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-role-assignment-changed",
			Title:      "Yii2 RBAC role assignment changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "yii2-rbac-database-entity-changed",
			Title:      "Yii2 RBAC database entity changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func laravelDatabaseSnapshotRule(text string, event domain.TimelineEvent) databaseSnapshotRule {
	switch {
	case strings.Contains(text, "admin_roles") || strings.Contains(text, "admin_role_assignments") || strings.Contains(text, "sensitive_permissions"):
		return databaseSnapshotRule{
			RuleID:     "laravel-admin-access-count-changed",
			Title:      "Laravel admin access count changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "roles") || strings.Contains(text, "permissions") || strings.Contains(text, "role_assignments") || strings.Contains(text, "role_permissions") || strings.Contains(text, "direct_permission_assignments"):
		return databaseSnapshotRule{
			RuleID:     "laravel-access-model-changed",
			Title:      "Laravel access model changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "users"):
		return databaseSnapshotRule{
			RuleID:     "laravel-users-count-changed",
			Title:      "Laravel user count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "password_reset"):
		return databaseSnapshotRule{
			RuleID:     "laravel-password-reset-tokens-changed",
			Title:      "Laravel password reset tokens changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "sessions"):
		return databaseSnapshotRule{
			RuleID:     "laravel-sessions-changed",
			Title:      "Laravel sessions changed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "migration"):
		return databaseSnapshotRule{
			RuleID:     "laravel-migrations-changed",
			Title:      "Laravel migrations changed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "laravel-database-check-changed",
			Title:      "Laravel database check changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func laravelDatabaseEntityRule(event domain.TimelineEvent, entityType string, current map[string]any, previous map[string]any) databaseSnapshotRule {
	currentAdmin := payloadBool(current, "admin_role") || payloadBool(current, "admin_like") || payloadBool(current, "privileged") || payloadBool(current, "sensitive")
	previousAdmin := payloadBool(previous, "admin_role") || payloadBool(previous, "admin_like") || payloadBool(previous, "privileged") || payloadBool(previous, "sensitive")
	switch entityType {
	case "laravel_user":
		switch {
		case event.EventType == "db.entity.added" && currentAdmin:
			return databaseSnapshotRule{RuleID: "laravel-admin-user-added", Title: "Laravel admin user added", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh}
		case event.EventType == "db.entity.changed" && currentAdmin && !previousAdmin:
			return databaseSnapshotRule{RuleID: "laravel-user-became-admin", Title: "Laravel user became admin", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh}
		case event.EventType == "db.entity.removed" && previousAdmin:
			return databaseSnapshotRule{RuleID: "laravel-admin-user-removed", Title: "Laravel admin user removed", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium}
		case event.EventType == "db.entity.changed":
			return databaseSnapshotRule{RuleID: "laravel-user-access-changed", Title: "Laravel user access changed", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh}
		default:
			return databaseSnapshotRule{RuleID: "laravel-user-changed", Title: "Laravel user changed", Severity: maxSeverity(event.Severity, domain.SeverityLow), Confidence: domain.ConfidenceMedium}
		}
	case "laravel_role", "laravel_permission", "laravel_role_assignment", "laravel_role_permission", "laravel_permission_assignment":
		if currentAdmin || previousAdmin {
			return databaseSnapshotRule{RuleID: "laravel-privileged-access-changed", Title: "Laravel privileged access changed", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh}
		}
		return databaseSnapshotRule{RuleID: "laravel-access-assignment-changed", Title: "Laravel access assignment changed", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh}
	default:
		return databaseSnapshotRule{RuleID: "laravel-database-entity-changed", Title: "Laravel database entity changed", Severity: maxSeverity(event.Severity, domain.SeverityLow), Confidence: domain.ConfidenceMedium}
	}
}

func mauticDatabaseEntityRule(event domain.TimelineEvent, entityType string, current map[string]any, previous map[string]any) databaseSnapshotRule {
	switch entityType {
	case "mautic_user":
		currentAdmin := payloadBool(current, "admin_role")
		previousAdmin := payloadBool(previous, "admin_role")
		switch {
		case event.EventType == "db.entity.added" && currentAdmin:
			return databaseSnapshotRule{
				RuleID:     "mautic-admin-user-added",
				Title:      "Mautic admin user added",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.changed" && currentAdmin && !previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "mautic-user-became-admin",
				Title:      "Mautic user became admin",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		case event.EventType == "db.entity.removed" && previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "mautic-admin-user-removed",
				Title:      "Mautic admin user removed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceMedium,
			}
		case event.EventType == "db.entity.changed":
			return databaseSnapshotRule{
				RuleID:     "mautic-user-access-changed",
				Title:      "Mautic user access changed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		default:
			return databaseSnapshotRule{
				RuleID:     "mautic-user-entity-changed",
				Title:      "Mautic user changed",
				Severity:   maxSeverity(event.Severity, domain.SeverityLow),
				Confidence: domain.ConfidenceMedium,
			}
		}
	case "mautic_role":
		currentAdmin := payloadBool(current, "admin_role")
		previousAdmin := payloadBool(previous, "admin_role")
		switch {
		case currentAdmin && !previousAdmin:
			return databaseSnapshotRule{
				RuleID:     "mautic-admin-role-changed",
				Title:      "Mautic admin role changed",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		default:
			return databaseSnapshotRule{
				RuleID:     "mautic-role-permissions-changed",
				Title:      "Mautic role permissions changed",
				Severity:   domain.SeverityMedium,
				Confidence: domain.ConfidenceHigh,
			}
		}
	case "mautic_plugin":
		return mauticPluginEntityRule(event, current, previous)
	case "mautic_integration":
		if payloadBool(current, "published") && payloadBool(current, "api_keys_present") {
			return databaseSnapshotRule{
				RuleID:     "mautic-integration-credentials-changed",
				Title:      "Mautic integration credentials changed",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		}
		return databaseSnapshotRule{
			RuleID:     "mautic-integration-changed",
			Title:      "Mautic integration changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case "mautic_oauth_client":
		return databaseSnapshotRule{
			RuleID:     "mautic-oauth-client-changed",
			Title:      "Mautic OAuth client changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case "mautic_webhook":
		if payloadBool(current, "published") || payloadBool(previous, "published") || payloadBool(current, "secret_present") || payloadBool(previous, "secret_present") {
			return databaseSnapshotRule{
				RuleID:     "mautic-webhook-secret-changed",
				Title:      "Mautic webhook changed",
				Severity:   domain.SeverityHigh,
				Confidence: domain.ConfidenceHigh,
			}
		}
		return databaseSnapshotRule{
			RuleID:     "mautic-webhook-changed",
			Title:      "Mautic webhook changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "mautic-database-entity-changed",
			Title:      "Mautic database entity changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func mauticPluginEntityRule(event domain.TimelineEvent, current map[string]any, previous map[string]any) databaseSnapshotRule {
	switch event.EventType {
	case "db.entity.added":
		return databaseSnapshotRule{
			RuleID:     "mautic-plugin-added",
			Title:      "Mautic plugin added",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case "db.entity.removed":
		return databaseSnapshotRule{
			RuleID:     "mautic-plugin-removed",
			Title:      "Mautic plugin removed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
		}
	case "db.entity.changed":
		previousVersion := strings.TrimSpace(payloadStringAny(previous, "version", ""))
		currentVersion := strings.TrimSpace(payloadStringAny(current, "version", ""))
		if previousVersion != "" || currentVersion != "" {
			switch compareVersionLike(currentVersion, previousVersion) {
			case 1:
				return databaseSnapshotRule{
					RuleID:     "mautic-plugin-upgraded",
					Title:      "Mautic plugin upgraded",
					Severity:   domain.SeverityMedium,
					Confidence: domain.ConfidenceHigh,
				}
			case -1:
				return databaseSnapshotRule{
					RuleID:     "mautic-plugin-downgraded",
					Title:      "Mautic plugin downgraded",
					Severity:   domain.SeverityMedium,
					Confidence: domain.ConfidenceHigh,
				}
			default:
				return databaseSnapshotRule{
					RuleID:     "mautic-plugin-version-changed",
					Title:      "Mautic plugin version changed",
					Severity:   domain.SeverityMedium,
					Confidence: domain.ConfidenceHigh,
				}
			}
		}
	}
	return databaseSnapshotRule{
		RuleID:     "mautic-plugin-changed",
		Title:      "Mautic plugin changed",
		Severity:   domain.SeverityMedium,
		Confidence: domain.ConfidenceMedium,
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
	case "wordpress_cron":
		return wordpressCronEntityRule(event, current, previous)
	case "wordpress_content_script":
		return wordpressContentScriptEntityRule(event, current, previous)
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

func wordpressCronEntityRule(event domain.TimelineEvent, current map[string]any, previous map[string]any) databaseSnapshotRule {
	currentSuspicious := payloadBool(current, "suspicious")
	previousSuspicious := payloadBool(previous, "suspicious")
	switch {
	case event.EventType == "db.entity.added" && currentSuspicious:
		return databaseSnapshotRule{
			RuleID:     "wordpress-suspicious-cron-task-added",
			Title:      "Suspicious WordPress cron task added",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case event.EventType == "db.entity.changed" && currentSuspicious && !previousSuspicious:
		return databaseSnapshotRule{
			RuleID:     "wordpress-cron-task-became-suspicious",
			Title:      "WordPress cron task became suspicious",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case event.EventType == "db.entity.added":
		return databaseSnapshotRule{
			RuleID:     "wordpress-cron-task-added",
			Title:      "WordPress cron task added",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "wordpress-cron-task-changed",
			Title:      "WordPress cron task changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func wordpressContentScriptEntityRule(event domain.TimelineEvent, current map[string]any, previous map[string]any) databaseSnapshotRule {
	currentDomains := payloadInt(current, "external_domains_count")
	previousDomains := payloadInt(previous, "external_domains_count")
	switch {
	case event.EventType == "db.entity.added" && currentDomains > 0:
		return databaseSnapshotRule{
			RuleID:     "wordpress-script-content-added",
			Title:      "WordPress script-bearing content added",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case event.EventType == "db.entity.changed" && currentDomains > previousDomains:
		return databaseSnapshotRule{
			RuleID:     "wordpress-script-content-domain-added",
			Title:      "WordPress content gained an external script domain",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "wordpress-script-content-changed",
			Title:      "WordPress script-bearing content changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
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
		return prestashopModuleEntityRule(event, current, previous)
	case "prestashop_configuration":
		return prestashopConfigurationEntityRule(event, current, previous)
	default:
		return databaseSnapshotRule{
			RuleID:     "prestashop-database-entity-changed",
			Title:      "PrestaShop database entity changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityLow),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func prestashopConfigurationEntityRule(event domain.TimelineEvent, current map[string]any, previous map[string]any) databaseSnapshotRule {
	category := strings.ToLower(firstNonEmpty(
		payloadStringAny(current, "category", ""),
		payloadStringAny(previous, "category", ""),
	))
	currentSuspicious := payloadBool(current, "suspicious")
	previousSuspicious := payloadBool(previous, "suspicious")
	currentSensitive := payloadBool(current, "sensitive")
	previousSensitive := payloadBool(previous, "sensitive")
	switch {
	case category == "payment":
		return databaseSnapshotRule{
			RuleID:     "prestashop-payment-configuration-changed",
			Title:      "PrestaShop payment configuration changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case currentSuspicious && !previousSuspicious:
		return databaseSnapshotRule{
			RuleID:     "prestashop-suspicious-configuration-changed",
			Title:      "Suspicious PrestaShop configuration changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case category == "mail":
		return databaseSnapshotRule{
			RuleID:     "prestashop-mail-configuration-changed",
			Title:      "PrestaShop mail configuration changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case category == "shop_url" || category == "security" || category == "api":
		return databaseSnapshotRule{
			RuleID:     "prestashop-security-configuration-changed",
			Title:      "PrestaShop security or URL configuration changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case currentSensitive || previousSensitive:
		return databaseSnapshotRule{
			RuleID:     "prestashop-sensitive-configuration-changed",
			Title:      "PrestaShop sensitive configuration changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "prestashop-configuration-entity-changed",
			Title:      "PrestaShop tracked configuration changed",
			Severity:   maxSeverity(event.Severity, domain.SeverityMedium),
			Confidence: domain.ConfidenceMedium,
		}
	}
}

func prestashopModuleEntityRule(event domain.TimelineEvent, current map[string]any, previous map[string]any) databaseSnapshotRule {
	switch event.EventType {
	case "db.entity.added":
		return databaseSnapshotRule{
			RuleID:     "prestashop-module-added",
			Title:      "PrestaShop module added",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceHigh,
		}
	case "db.entity.removed":
		return databaseSnapshotRule{
			RuleID:     "prestashop-module-removed",
			Title:      "PrestaShop module removed",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceHigh,
		}
	case "db.entity.changed":
		previousVersion := strings.TrimSpace(payloadStringAny(previous, "version", ""))
		currentVersion := strings.TrimSpace(payloadStringAny(current, "version", ""))
		if previousVersion != "" || currentVersion != "" {
			switch compareVersionLike(currentVersion, previousVersion) {
			case 1:
				return databaseSnapshotRule{
					RuleID:     "prestashop-module-upgraded",
					Title:      "PrestaShop module upgraded",
					Severity:   domain.SeverityMedium,
					Confidence: domain.ConfidenceHigh,
				}
			case -1:
				return databaseSnapshotRule{
					RuleID:     "prestashop-module-downgraded",
					Title:      "PrestaShop module downgraded",
					Severity:   domain.SeverityMedium,
					Confidence: domain.ConfidenceHigh,
				}
			default:
				return databaseSnapshotRule{
					RuleID:     "prestashop-module-version-changed",
					Title:      "PrestaShop module version changed",
					Severity:   domain.SeverityMedium,
					Confidence: domain.ConfidenceHigh,
				}
			}
		}
	}
	return databaseSnapshotRule{
		RuleID:     "prestashop-module-entity-changed",
		Title:      "PrestaShop module changed",
		Severity:   domain.SeverityLow,
		Confidence: domain.ConfidenceMedium,
	}
}

func isPrestashopModuleCountSnapshotEvent(event domain.TimelineEvent) bool {
	if !strings.HasPrefix(event.EventType, "db.snapshot.check_") {
		return false
	}
	profile := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "profile", ""),
		event.Labels["db_profile"],
	))
	if profile != "prestashop" && profile != "ps" {
		return false
	}
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
	return strings.Contains(text, "modules")
}

func isPrestashopModuleEntityEvent(event domain.TimelineEvent) bool {
	if !strings.HasPrefix(event.EventType, "db.entity.") {
		return false
	}
	profile := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "profile", ""),
		event.Labels["db_profile"],
	))
	if profile != "prestashop" && profile != "ps" {
		return false
	}
	entityType := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "entity_type", ""),
		event.Labels["db_entity_type"],
	))
	return entityType == "prestashop_module"
}

func isMauticExtensionCountSnapshotEvent(event domain.TimelineEvent) bool {
	if !strings.HasPrefix(event.EventType, "db.snapshot.check_") {
		return false
	}
	profile := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "profile", ""),
		event.Labels["db_profile"],
	))
	if profile != "mautic" {
		return false
	}
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
	return strings.Contains(text, "plugins") ||
		strings.Contains(text, "integrations") ||
		strings.Contains(text, "oauth") ||
		strings.Contains(text, "webhooks")
}

func prestashopModuleEntityShouldAlert(event domain.TimelineEvent) bool {
	switch event.EventType {
	case "db.entity.added", "db.entity.removed":
		return true
	case "db.entity.changed":
		current := payloadMap(payloadMap(event.Payload, "current"), "attributes")
		previous := payloadMap(payloadMap(event.Payload, "previous"), "attributes")
		currentVersion := strings.TrimSpace(payloadStringAny(current, "version", ""))
		previousVersion := strings.TrimSpace(payloadStringAny(previous, "version", ""))
		return currentVersion != previousVersion
	default:
		return false
	}
}

func compareVersionLike(current string, previous string) int {
	current = strings.TrimSpace(current)
	previous = strings.TrimSpace(previous)
	if current == previous {
		return 0
	}
	currentParts := versionNumberParts(current)
	previousParts := versionNumberParts(previous)
	if len(currentParts) == 0 || len(previousParts) == 0 {
		return 0
	}
	limit := len(currentParts)
	if len(previousParts) > limit {
		limit = len(previousParts)
	}
	for index := 0; index < limit; index++ {
		var currentPart int
		var previousPart int
		if index < len(currentParts) {
			currentPart = currentParts[index]
		}
		if index < len(previousParts) {
			previousPart = previousParts[index]
		}
		switch {
		case currentPart > previousPart:
			return 1
		case currentPart < previousPart:
			return -1
		}
	}
	return 0
}

func versionNumberParts(value string) []int {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r < '0' || r > '9'
	})
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		parsed, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		parts = append(parts, parsed)
	}
	return parts
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

func mauticDatabaseSnapshotRule(text string, event domain.TimelineEvent) databaseSnapshotRule {
	switch {
	case strings.Contains(text, "admin_roles"):
		return databaseSnapshotRule{
			RuleID:     "mautic-admin-roles-changed",
			Title:      "Mautic admin role count changed",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceHigh,
		}
	case strings.Contains(text, "users"):
		return databaseSnapshotRule{
			RuleID:     "mautic-users-changed",
			Title:      "Mautic user count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	case strings.Contains(text, "roles"):
		return databaseSnapshotRule{
			RuleID:     "mautic-roles-changed",
			Title:      "Mautic role count changed",
			Severity:   domain.SeverityMedium,
			Confidence: domain.ConfidenceMedium,
		}
	default:
		return databaseSnapshotRule{
			RuleID:     "mautic-database-check-changed",
			Title:      "Mautic database check changed",
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

func databaseSnapshotDiffTitle(title string, event domain.TimelineEvent) string {
	if display := databaseEntityAccountDisplay(event); display != "" && databaseEntityIsAccountLike(event) {
		return title + ": " + display
	}
	return title
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
		summary := strings.TrimPrefix(event.EventType, "db.entity.") + " " + entity
		if display := databaseEntityAccountDisplay(event); display != "" {
			summary += " account " + display
		}
		return summary
	}
	return ""
}

func databaseSnapshotDiffMetadata(event domain.TimelineEvent) map[string]any {
	metadata := map[string]any{
		"database_profile": firstNonEmpty(
			payloadStringAny(event.Payload, "profile", ""),
			event.Labels["db_profile"],
		),
		"database": payloadStringAny(event.Payload, "database", ""),
	}
	if check := payloadStringAny(event.Payload, "check", ""); check != "" {
		metadata["database_check"] = check
	}
	if entityType := payloadStringAny(event.Payload, "entity_type", ""); entityType != "" {
		metadata["entity_type"] = entityType
		metadata["change_type"] = strings.TrimPrefix(event.EventType, "db.entity.")
	}
	if entityKey := payloadStringAny(event.Payload, "entity_key", ""); entityKey != "" {
		metadata["entity_key"] = entityKey
	}

	currentAttributes := payloadMap(payloadMap(event.Payload, "current"), "attributes")
	previousAttributes := payloadMap(payloadMap(event.Payload, "previous"), "attributes")
	if display := databaseEntityAccountDisplay(event); display != "" {
		metadata["account_display"] = display
	}
	for _, item := range []struct {
		Key        string
		OutputKey  string
		Attributes map[string]any
	}{
		{Key: "email", OutputKey: "email", Attributes: currentAttributes},
		{Key: "login", OutputKey: "login", Attributes: currentAttributes},
		{Key: "email_masked", OutputKey: "email_masked", Attributes: currentAttributes},
		{Key: "login_masked", OutputKey: "login_masked", Attributes: currentAttributes},
		{Key: "email", OutputKey: "previous_email", Attributes: previousAttributes},
		{Key: "login", OutputKey: "previous_login", Attributes: previousAttributes},
		{Key: "email_masked", OutputKey: "previous_email_masked", Attributes: previousAttributes},
		{Key: "login_masked", OutputKey: "previous_login_masked", Attributes: previousAttributes},
	} {
		if value := payloadStringAny(item.Attributes, item.Key, ""); value != "" {
			metadata[item.OutputKey] = value
		}
	}
	return metadata
}

func databaseEntityAccountDisplay(event domain.TimelineEvent) string {
	current := payloadMap(event.Payload, "current")
	previous := payloadMap(event.Payload, "previous")
	currentAttributes := payloadMap(current, "attributes")
	previousAttributes := payloadMap(previous, "attributes")
	return firstNonEmpty(
		payloadStringAny(currentAttributes, "email", ""),
		payloadStringAny(currentAttributes, "account_display", ""),
		payloadStringAny(currentAttributes, "login", ""),
		payloadStringAny(currentAttributes, "email_masked", ""),
		payloadStringAny(currentAttributes, "login_masked", ""),
		payloadStringAny(previousAttributes, "email", ""),
		payloadStringAny(previousAttributes, "account_display", ""),
		payloadStringAny(previousAttributes, "login", ""),
		payloadStringAny(previousAttributes, "email_masked", ""),
		payloadStringAny(previousAttributes, "login_masked", ""),
	)
}

func databaseEntityIsAccountLike(event domain.TimelineEvent) bool {
	entityType := strings.ToLower(firstNonEmpty(
		payloadStringAny(event.Payload, "entity_type", ""),
		event.Labels["db_entity_type"],
	))
	return strings.Contains(entityType, "user") || strings.Contains(entityType, "employee") || strings.Contains(entityType, "admin")
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
