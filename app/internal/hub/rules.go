package hub

import (
	"slices"
	"strings"
	"unicode"
)

const currentRuleVersion = "2026-05-12.1"

type RuleCategory string

const (
	RuleCategoryCorrelation      RuleCategory = "correlation"
	RuleCategoryDatabaseSnapshot RuleCategory = "database_snapshot"
	RuleCategoryBrowserScript    RuleCategory = "browser_script"
	RuleCategoryWebRequest       RuleCategory = "web_request"
	RuleCategoryFilePath         RuleCategory = "file_path"
	RuleCategoryFileBaseline     RuleCategory = "file_baseline"
)

type RuleActionHint string

const (
	RuleActionAcknowledge        RuleActionHint = "acknowledge"
	RuleActionMarkFalsePositive  RuleActionHint = "mark_false_positive"
	RuleActionInspectTimeline    RuleActionHint = "inspect_timeline"
	RuleActionInspectDatabase    RuleActionHint = "inspect_database"
	RuleActionInspectFiles       RuleActionHint = "inspect_files"
	RuleActionInspectDeployment  RuleActionHint = "inspect_deployment"
	RuleActionAllowBrowserScript RuleActionHint = "allow_browser_script"
)

type RuleDefinition struct {
	ID            string
	Version       string
	Title         string
	Category      RuleCategory
	Platforms     []string
	EvidenceTypes []string
	ActionHints   []RuleActionHint
}

type RuleRegistry interface {
	Get(id string) (RuleDefinition, bool)
	List() []RuleDefinition
}

type StaticRuleRegistry struct {
	rules map[string]RuleDefinition
}

func NewStaticRuleRegistry(definitions []RuleDefinition) StaticRuleRegistry {
	rules := make(map[string]RuleDefinition, len(definitions))
	for _, definition := range definitions {
		if strings.TrimSpace(definition.ID) == "" {
			continue
		}
		if strings.TrimSpace(definition.Version) == "" {
			definition.Version = currentRuleVersion
		}
		definition.Platforms = cleanRuleStrings(definition.Platforms)
		definition.EvidenceTypes = cleanRuleStrings(definition.EvidenceTypes)
		definition.ActionHints = cleanRuleActions(definition.ActionHints)
		rules[definition.ID] = definition
	}
	return StaticRuleRegistry{rules: rules}
}

func (r StaticRuleRegistry) Get(id string) (RuleDefinition, bool) {
	definition, ok := r.rules[id]
	if !ok {
		return RuleDefinition{}, false
	}
	return cloneRuleDefinition(definition), true
}

func (r StaticRuleRegistry) List() []RuleDefinition {
	definitions := make([]RuleDefinition, 0, len(r.rules))
	for _, definition := range r.rules {
		definitions = append(definitions, cloneRuleDefinition(definition))
	}
	slices.SortFunc(definitions, func(a RuleDefinition, b RuleDefinition) int {
		if a.Category != b.Category {
			return strings.Compare(string(a.Category), string(b.Category))
		}
		return strings.Compare(a.ID, b.ID)
	})
	return definitions
}

var defaultRuleRegistry = NewStaticRuleRegistry(defaultRuleDefinitions())

func (h *Hub) ListRuleDefinitions() []RuleDefinition {
	return defaultRuleRegistry.List()
}

func ruleDefinition(ruleID string) (RuleDefinition, bool) {
	return defaultRuleRegistry.Get(ruleID)
}

func ruleVersion(ruleID string) string {
	if definition, ok := ruleDefinition(ruleID); ok {
		return definition.Version
	}
	return currentRuleVersion
}

func ruleMetadata(ruleID string, metadata map[string]any) map[string]any {
	enriched := cloneAnyMap(metadata)
	if definition, ok := ruleDefinition(ruleID); ok {
		enriched["rule"] = map[string]any{
			"id":             definition.ID,
			"version":        definition.Version,
			"category":       string(definition.Category),
			"platforms":      append([]string(nil), definition.Platforms...),
			"evidence_types": append([]string(nil), definition.EvidenceTypes...),
			"action_hints":   ruleActionStrings(definition.ActionHints),
		}
	}
	return enriched
}

func ruleHasActionHint(ruleID string, action RuleActionHint) bool {
	definition, ok := ruleDefinition(ruleID)
	if !ok {
		return false
	}
	return slices.Contains(definition.ActionHints, action)
}

func defaultRuleDefinitions() []RuleDefinition {
	ids := []string{
		"probable-incident-chain",
		"web-to-file-change",
		"file-change-to-sensitive-followup",
		"file-change-to-db-security-change",
		"file-change-to-persistence",
		"database-snapshot-check-changed",
		"database-entity-changed",
		"wordpress-admin-user-added",
		"wordpress-user-became-admin",
		"wordpress-user-capabilities-changed",
		"wordpress-admin-user-removed",
		"wordpress-user-entity-changed",
		"wordpress-active-plugin-added",
		"wordpress-active-plugin-removed",
		"wordpress-active-plugin-changed",
		"wordpress-active-theme-changed",
		"wordpress-database-entity-changed",
		"wordpress-active-plugins-option-changed",
		"wordpress-theme-option-changed",
		"wordpress-registration-option-changed",
		"wordpress-network-admins-option-changed",
		"wordpress-identity-option-changed",
		"wordpress-user-roles-option-changed",
		"wordpress-option-entity-changed",
		"wordpress-suspicious-cron-task-added",
		"wordpress-cron-task-became-suspicious",
		"wordpress-cron-task-added",
		"wordpress-cron-task-changed",
		"wordpress-script-content-added",
		"wordpress-script-content-domain-added",
		"wordpress-script-content-changed",
		"wordpress-admin-users-changed",
		"wordpress-active-plugins-changed",
		"wordpress-cron-option-changed",
		"wordpress-users-changed",
		"wordpress-options-changed",
		"wordpress-database-check-changed",
		"prestashop-superadmin-employee-added",
		"prestashop-employee-became-superadmin",
		"prestashop-employee-changed",
		"prestashop-employee-entity-changed",
		"prestashop-active-module-added",
		"prestashop-module-entity-changed",
		"prestashop-database-entity-changed",
		"prestashop-payment-configuration-changed",
		"prestashop-suspicious-configuration-changed",
		"prestashop-mail-configuration-changed",
		"prestashop-security-configuration-changed",
		"prestashop-sensitive-configuration-changed",
		"prestashop-configuration-entity-changed",
		"prestashop-employees-changed",
		"prestashop-modules-changed",
		"prestashop-configuration-changed",
		"prestashop-access-rules-changed",
		"prestashop-hooks-changed",
		"prestashop-tabs-changed",
		"prestashop-database-check-changed",
		"browser-script-domain-new",
		"browser-inline-script-changed",
		"browser-tag-manager-id-new",
		"browser-script-drift",
		"web-admin-success-after-failures",
		"web-admin-failed-request-burst",
		"web-admin-login-post-burst",
		"web-admin-tool-probe",
		"file-php-in-writable-path",
		"file-sensitive-config-changed",
		"file-suspicious-path-pattern",
		"file-plugin-theme-module-changed",
		"file-php-changed",
		"file-baseline-drift",
	}
	definitions := make([]RuleDefinition, 0, len(ids))
	for _, id := range ids {
		definitions = append(definitions, inferRuleDefinition(id))
	}
	return definitions
}

func inferRuleDefinition(id string) RuleDefinition {
	definition := RuleDefinition{
		ID:      id,
		Version: currentRuleVersion,
		Title:   humanizeRuleTitle(id),
	}
	switch {
	case strings.HasPrefix(id, "browser-"):
		definition.Category = RuleCategoryBrowserScript
		definition.Platforms = []string{"web"}
		definition.EvidenceTypes = []string{"browser"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectDeployment, RuleActionAllowBrowserScript}
	case isWebRequestRuleID(id):
		definition.Category = RuleCategoryWebRequest
		definition.Platforms = []string{"generic_php", "wordpress", "prestashop"}
		definition.EvidenceTypes = []string{"log"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectTimeline}
	case id == "file-baseline-drift":
		definition.Category = RuleCategoryFileBaseline
		definition.Platforms = []string{"generic_php"}
		definition.EvidenceTypes = []string{"file"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectTimeline, RuleActionInspectFiles, RuleActionInspectDeployment}
	case isFilePathRuleID(id):
		definition.Category = RuleCategoryFilePath
		definition.Platforms = []string{"generic_php", "wordpress", "prestashop"}
		definition.EvidenceTypes = []string{"file"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectTimeline, RuleActionInspectFiles, RuleActionInspectDeployment}
	case strings.HasPrefix(id, "wordpress-"):
		definition.Category = RuleCategoryDatabaseSnapshot
		definition.Platforms = []string{"wordpress"}
		definition.EvidenceTypes = []string{"database"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectDatabase, RuleActionInspectTimeline, RuleActionInspectDeployment}
	case strings.HasPrefix(id, "prestashop-"):
		definition.Category = RuleCategoryDatabaseSnapshot
		definition.Platforms = []string{"prestashop"}
		definition.EvidenceTypes = []string{"database"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectDatabase, RuleActionInspectTimeline, RuleActionInspectDeployment}
	case strings.HasPrefix(id, "database-"):
		definition.Category = RuleCategoryDatabaseSnapshot
		definition.Platforms = []string{"generic"}
		definition.EvidenceTypes = []string{"database"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectDatabase, RuleActionInspectDeployment}
	default:
		definition.Category = RuleCategoryCorrelation
		definition.Platforms = []string{"generic_php"}
		definition.EvidenceTypes = []string{"timeline"}
		definition.ActionHints = []RuleActionHint{RuleActionAcknowledge, RuleActionMarkFalsePositive, RuleActionInspectTimeline, RuleActionInspectFiles, RuleActionInspectDatabase, RuleActionInspectDeployment}
	}
	return definition
}

func humanizeRuleTitle(id string) string {
	words := strings.Split(strings.ReplaceAll(id, "_", "-"), "-")
	for index, word := range words {
		if word == "" {
			continue
		}
		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		words[index] = string(runes)
	}
	title := strings.Join(words, " ")
	replacements := map[string]string{
		"Wordpress":  "WordPress",
		"Prestashop": "PrestaShop",
		"Db":         "DB",
		"Php":        "PHP",
		"Url":        "URL",
		"Id":         "ID",
	}
	for old, replacement := range replacements {
		title = strings.ReplaceAll(title, old, replacement)
	}
	return title
}

func cloneRuleDefinition(definition RuleDefinition) RuleDefinition {
	definition.Platforms = append([]string(nil), definition.Platforms...)
	definition.EvidenceTypes = append([]string(nil), definition.EvidenceTypes...)
	definition.ActionHints = append([]RuleActionHint(nil), definition.ActionHints...)
	return definition
}

func cleanRuleStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func cleanRuleActions(values []RuleActionHint) []RuleActionHint {
	cleaned := make([]RuleActionHint, 0, len(values))
	seen := map[RuleActionHint]struct{}{}
	for _, value := range values {
		value = RuleActionHint(strings.TrimSpace(string(value)))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func ruleActionStrings(actions []RuleActionHint) []string {
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return values
}

func isFilePathRuleID(id string) bool {
	switch id {
	case "file-php-in-writable-path",
		"file-sensitive-config-changed",
		"file-suspicious-path-pattern",
		"file-plugin-theme-module-changed",
		"file-php-changed":
		return true
	default:
		return false
	}
}

func isWebRequestRuleID(id string) bool {
	switch id {
	case "web-admin-success-after-failures",
		"web-admin-failed-request-burst",
		"web-admin-login-post-burst",
		"web-admin-tool-probe":
		return true
	default:
		return false
	}
}
