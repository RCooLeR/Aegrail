package hub

import (
	"math"
	"strings"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const currentRiskScoreVersion = "2026-05-13.1"

type riskFactor struct {
	ID     string
	Points int
	Reason string
}

type riskScoreResult struct {
	Score   int
	Band    string
	Factors []riskFactor
}

func applyRiskScoringToFindings(findings []domain.HubFinding) []domain.HubFinding {
	if len(findings) == 0 {
		return findings
	}
	enriched := make([]domain.HubFinding, len(findings))
	for index, finding := range findings {
		enriched[index] = applyRiskScoring(finding)
	}
	return enriched
}

func applyRiskScoring(finding domain.HubFinding) domain.HubFinding {
	result := calculateFindingRisk(finding)
	metadata := cloneAnyMap(finding.Metadata)
	metadata["operator_action"] = findingOperatorActionMetadata(finding)
	metadata["risk"] = map[string]any{
		"version":           currentRiskScoreVersion,
		"score":             result.Score,
		"band":              result.Band,
		"severity":          string(finding.Severity),
		"confidence":        string(finding.Confidence),
		"rule_id":           finding.RuleID,
		"rule_category":     string(riskRuleCategory(finding.RuleID)),
		"event_count":       len(finding.EventIDs),
		"host_count":        riskMetadataHostCount(metadata),
		"factors":           riskFactorMetadata(result.Factors),
		"deployment_active": riskDeploymentActive(metadata),
	}
	finding.Metadata = metadata
	return finding
}

func calculateFindingRisk(finding domain.HubFinding) riskScoreResult {
	var factors []riskFactor
	add := func(id string, points int, reason string) {
		if points == 0 {
			return
		}
		factors = append(factors, riskFactor{ID: id, Points: points, Reason: reason})
	}

	add("severity:"+string(finding.Severity), severityRiskPoints(finding.Severity), "finding severity")
	add("confidence:"+string(finding.Confidence), confidenceRiskPoints(finding.Confidence), "finding confidence")
	add("category:"+string(riskRuleCategory(finding.RuleID)), categoryRiskPoints(riskRuleCategory(finding.RuleID)), "rule category")
	for _, factor := range ruleSpecificRiskFactors(finding.RuleID) {
		add(factor.ID, factor.Points, factor.Reason)
	}

	eventCount := len(finding.EventIDs)
	switch {
	case eventCount >= 5:
		add("evidence:event_count:5_plus", 8, "five or more supporting events")
	case eventCount >= 3:
		add("evidence:event_count:3_plus", 5, "three or more supporting events")
	}

	hostCount := riskMetadataHostCount(finding.Metadata)
	if hostCount >= 2 {
		add("evidence:multi_host", 6, "evidence spans multiple hosts")
	}

	if riskDeploymentAdjusted(finding.Metadata) {
		add("context:deployment_adjusted", -5, "active deployment lowered expected-change risk")
	}

	score := 0
	for _, factor := range factors {
		score += factor.Points
	}
	score = int(math.Max(0, math.Min(100, float64(score))))
	return riskScoreResult{
		Score:   score,
		Band:    riskBand(score),
		Factors: factors,
	}
}

func severityRiskPoints(severity domain.Severity) int {
	switch severity {
	case domain.SeverityCritical:
		return 90
	case domain.SeverityHigh:
		return 72
	case domain.SeverityMedium:
		return 46
	case domain.SeverityLow:
		return 22
	case domain.SeverityInfo:
		return 8
	default:
		return 8
	}
}

func confidenceRiskPoints(confidence domain.Confidence) int {
	switch confidence {
	case domain.ConfidenceHigh:
		return 8
	case domain.ConfidenceMedium:
		return 0
	case domain.ConfidenceLow:
		return -8
	default:
		return 0
	}
}

func categoryRiskPoints(category RuleCategory) int {
	switch category {
	case RuleCategoryCorrelation:
		return 4
	case RuleCategoryDatabaseSnapshot:
		return 5
	case RuleCategoryFileBaseline:
		return 5
	case RuleCategoryFilePath:
		return 4
	case RuleCategoryBrowserScript:
		return 3
	case RuleCategoryWebRequest:
		return 0
	default:
		return 0
	}
}

func ruleSpecificRiskFactors(ruleID string) []riskFactor {
	var factors []riskFactor
	add := func(id string, points int, reason string) {
		factors = append(factors, riskFactor{ID: id, Points: points, Reason: reason})
	}

	switch ruleID {
	case "probable-incident-chain":
		add("rule:incident_chain", 12, "probable multi-step incident chain")
	case "web-to-file-change", "file-change-to-sensitive-followup", "file-change-to-db-security-change", "file-change-to-persistence":
		add("rule:correlated_followup", 8, "sensitive follow-up after an earlier signal")
	case "file-php-in-writable-path":
		add("rule:writable_php", 8, "PHP file under writable path")
	case "file-sensitive-config-changed":
		add("rule:sensitive_config", 6, "sensitive configuration file changed")
	case "browser-tag-manager-id-new":
		add("rule:tag_manager_new", 5, "new tag manager container")
	case "web-tor-admin-request":
		add("rule:tor_admin", 5, "Tor-marked request touched an admin path")
	case "web-tor-request-observed":
		add("rule:tor_public", -3, "Tor-marked public request is weak by itself")
	}

	lower := strings.ToLower(ruleID)
	if strings.Contains(lower, "admin") ||
		strings.Contains(lower, "superadmin") ||
		strings.Contains(lower, "privilege") ||
		strings.Contains(lower, "capabilities") ||
		strings.Contains(lower, "payment") {
		add("rule:privileged_or_payment", 8, "privileged, administrative, or payment-sensitive rule")
	}
	if strings.Contains(lower, "cron") ||
		strings.Contains(lower, "persistence") {
		add("rule:persistence", 6, "persistence-related signal")
	}
	return factors
}

func riskRuleCategory(ruleID string) RuleCategory {
	if definition, ok := ruleDefinition(ruleID); ok {
		return definition.Category
	}
	return RuleCategoryCorrelation
}

func riskBand(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "informational"
	}
}

func riskFactorMetadata(factors []riskFactor) []map[string]any {
	values := make([]map[string]any, 0, len(factors))
	for _, factor := range factors {
		values = append(values, map[string]any{
			"id":     factor.ID,
			"points": factor.Points,
			"reason": factor.Reason,
		})
	}
	return values
}

func riskMetadataHostCount(metadata map[string]any) int {
	events, ok := metadata["events"].([]map[string]any)
	if ok {
		return riskMetadataHostCountFromEventMaps(events)
	}
	anyEvents, ok := metadata["events"].([]any)
	if !ok {
		return 0
	}
	hosts := map[string]struct{}{}
	for _, item := range anyEvents {
		event, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if host := strings.TrimSpace(payloadStringAny(event, "host", "")); host != "" {
			hosts[host] = struct{}{}
		}
	}
	return len(hosts)
}

func riskMetadataHostCountFromEventMaps(events []map[string]any) int {
	hosts := map[string]struct{}{}
	for _, event := range events {
		if host := strings.TrimSpace(payloadStringAny(event, "host", "")); host != "" {
			hosts[host] = struct{}{}
		}
	}
	return len(hosts)
}

func riskDeploymentActive(metadata map[string]any) bool {
	context, ok := metadata["deployment_context"].(map[string]any)
	if !ok {
		return false
	}
	return payloadBool(context, "active")
}

func riskDeploymentAdjusted(metadata map[string]any) bool {
	context, ok := metadata["deployment_context"].(map[string]any)
	if !ok {
		return false
	}
	return payloadBool(context, "severity_adjusted")
}
