package hub

import (
	"strings"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const currentOperatorActionVersion = "2026-05-17.1"

func findingOperatorActionMetadata(finding domain.HubFinding) map[string]any {
	definition, ok := ruleDefinition(finding.RuleID)
	category := RuleCategoryCorrelation
	if ok {
		category = definition.Category
	}
	primary := operatorPrimaryAction(finding, category)
	return map[string]any{
		"version":                     currentOperatorActionVersion,
		"primary_action":              primary,
		"recommended_status_expected": "acknowledged",
		"recommended_status_noise":    "false_positive",
		"recommended_status_fixed":    "resolved",
		"safe_to_acknowledge_when":    safeToAcknowledgeText(finding, category),
		"escalate_when":               escalateWhenText(finding, category),
		"actions":                     operatorActionSteps(finding, category),
	}
}

func operatorPrimaryAction(finding domain.HubFinding, category RuleCategory) string {
	rule := strings.ToLower(finding.RuleID + " " + finding.Title + " " + finding.Summary)
	switch {
	case strings.Contains(rule, "incident-chain") || strings.Contains(rule, "file-change-to"):
		return "Open the linked timeline, verify whether the sequence matches your deployment or admin work, and preserve evidence before changing files or database rows."
	case category == RuleCategoryBrowserScript:
		return "Verify the script domain/hash/tag-manager ID owner; allowlist it only after confirming it belongs to an expected deployment or approved integration."
	case category == RuleCategoryWebRequest:
		return "Review access logs around the window for source fingerprint, admin path, status codes, and whether the traffic matches your monitoring/CDN/WAF behavior."
	case category == RuleCategoryFilePath || category == RuleCategoryFileBaseline:
		return "Inspect the changed file set and compare it with the expected release; ignore only generated/runtime paths that are safe for this node."
	case category == RuleCategoryDatabaseSnapshot:
		return databaseOperatorPrimaryAction(finding)
	default:
		return "Review the timeline events in order, decide whether the change is expected, and update the finding status with a note."
	}
}

func databaseOperatorPrimaryAction(finding domain.HubFinding) string {
	rule := strings.ToLower(finding.RuleID + " " + finding.Title + " " + finding.Summary)
	switch {
	case strings.Contains(rule, "wordpress"):
		return "Check the WordPress admin/user/plugin/theme/option change against recent admin sessions and deployments."
	case strings.Contains(rule, "prestashop"):
		return "Check the PrestaShop employee/module/config/payment/mail change against back office activity and deployments."
	case strings.Contains(rule, "mautic"):
		return "Check the Mautic user/role/plugin/integration/OAuth/webhook change against marketing/admin activity and deployments."
	case strings.Contains(rule, "yii2-rbac"):
		return "Check the Yii2 RBAC user/role/assignment/migration change against expected admin or deployment activity."
	case strings.Contains(rule, "laravel"):
		return "Check the Laravel user/role/permission/session/token/migration change against expected admin, queue, or deployment activity."
	default:
		return "Review the database entity/check diff and confirm whether it is expected before acknowledging the finding."
	}
}

func safeToAcknowledgeText(finding domain.HubFinding, category RuleCategory) string {
	switch category {
	case RuleCategoryBrowserScript:
		return "the script or tag manager is owned, expected, and documented in the allowlist or deployment notes"
	case RuleCategoryWebRequest:
		return "the requests are explained by known admin work, monitoring, CDN/WAF behavior, or expected public traffic"
	case RuleCategoryFilePath, RuleCategoryFileBaseline:
		return "the file changes match a deployment, upgrade, or known generated/runtime directory"
	case RuleCategoryDatabaseSnapshot:
		return "the database change matches an authorized admin action, migration, module/plugin update, or deployment"
	default:
		if finding.Severity == domain.SeverityHigh || finding.Severity == domain.SeverityCritical {
			return "the full timeline has a confirmed authorized explanation"
		}
		return "the referenced evidence has a clear expected explanation"
	}
}

func escalateWhenText(finding domain.HubFinding, category RuleCategory) string {
	if finding.Severity == domain.SeverityCritical || finding.Severity == domain.SeverityHigh {
		return "no owner can explain the change, the actor/source is unfamiliar, or the evidence touches admin access, writable PHP, payment/security configuration, persistence, or third-party script injection"
	}
	switch category {
	case RuleCategoryBrowserScript:
		return "the domain or inline script is unknown, recently injected into CMS content, or not tied to a planned deployment"
	case RuleCategoryFilePath:
		return "the changed file is executable, in a writable path, has a suspicious name, or is not part of a known release"
	case RuleCategoryDatabaseSnapshot:
		return "the change grants access, changes admin users/roles, changes integrations/secrets, or cannot be tied to a known admin action"
	default:
		return "the explanation is missing, inconsistent, or points to unauthorized access"
	}
}

func operatorActionSteps(finding domain.HubFinding, category RuleCategory) []string {
	steps := []string{"Review the finding timeline and evidence before changing status."}
	switch category {
	case RuleCategoryBrowserScript:
		steps = append(steps, "Verify script ownership and deployment source.", "Allowlist only after confirming the script is expected.")
	case RuleCategoryWebRequest:
		steps = append(steps, "Inspect access log context around the event window.", "Compare source fingerprint and path against known admin, monitoring, CDN, and WAF traffic.")
	case RuleCategoryFilePath, RuleCategoryFileBaseline:
		steps = append(steps, "Inspect changed files or compare them with release artifacts.", "Use a file ignore only for safe generated/runtime paths.")
	case RuleCategoryDatabaseSnapshot:
		steps = append(steps, "Inspect the database diff and affected user/config/module/integration entity.", "Match the change to a known admin action, migration, or deployment.")
	default:
		steps = append(steps, "Confirm the timeline has a normal explanation or escalate for incident triage.")
	}
	steps = append(steps, "Set status to acknowledged if expected, false positive if noisy/irrelevant, or resolved after cleanup/fix.")
	return steps
}
