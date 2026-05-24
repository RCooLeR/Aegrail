package hub

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const (
	deploymentWindowPadding = 5 * time.Minute
	openDeploymentWindow    = 30 * time.Minute
)

var deploymentExpectedRuleIDs = []string{
	"browser-inline-script-changed",
	"browser-script-domain-new",
	"browser-script-drift",
	"browser-tag-manager-id-new",
	"file-baseline-drift",
	"file-php-changed",
	"file-plugin-theme-module-changed",
}

type deploymentExpectedFindingStatusRepository interface {
	UpdateOpenHubFindingStatusesForRulesInWindow(ctx context.Context, environmentID domain.ID, appID domain.ID, ruleIDs []string, windowStart time.Time, windowEnd time.Time, update domain.HubFindingStatusUpdate) (int, error)
}

func (h *Hub) applyDeploymentContextToFindings(ctx context.Context, environmentID domain.ID, scopeAppID domain.ID, findings []domain.HubFinding) ([]domain.HubFinding, error) {
	if len(findings) == 0 || h.inventory == nil {
		return findings, nil
	}
	deployments, err := h.inventory.ListDeploymentMarkers(ctx, environmentID, "")
	if err != nil {
		return nil, err
	}
	if len(deployments) == 0 {
		return findings, nil
	}

	enriched := make([]domain.HubFinding, len(findings))
	copy(enriched, findings)
	for index := range enriched {
		appID := enriched[index].AppID
		if appID == "" {
			appID = scopeAppID
		}
		active := activeDeploymentMarkers(deployments, appID, enriched[index].FirstEventAt, enriched[index].LastEventAt)
		if len(active) == 0 {
			continue
		}
		enriched[index] = applyDeploymentScoring(enriched[index], active)
	}
	return enriched, nil
}

func filterDeploymentExpectedFindings(findings []domain.HubFinding) []domain.HubFinding {
	if len(findings) == 0 {
		return findings
	}
	filtered := make([]domain.HubFinding, 0, len(findings))
	for _, finding := range findings {
		if deploymentExpectedFinding(finding) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func deploymentExpectedFinding(finding domain.HubFinding) bool {
	if !deploymentMetadataActive(finding.Metadata) {
		return false
	}
	return deploymentExpectedRuleID(finding.RuleID)
}

func deploymentExpectedRuleID(ruleID string) bool {
	for _, expected := range deploymentExpectedRuleIDs {
		if ruleID == expected {
			return true
		}
	}
	return false
}

func deploymentMetadataActive(metadata map[string]any) bool {
	context, ok := metadata["deployment_context"].(map[string]any)
	if !ok {
		return false
	}
	active, ok := context["active"].(bool)
	return ok && active
}

func (h *Hub) acknowledgeDeploymentExpectedOpenFindings(ctx context.Context, deployment domain.DeploymentMarker) (int, error) {
	if h.findings == nil {
		return 0, nil
	}
	repository, ok := h.findings.(deploymentExpectedFindingStatusRepository)
	if !ok {
		return 0, nil
	}
	windowStart, windowEnd, ok := deploymentScoringWindow(deployment)
	if !ok {
		return 0, nil
	}
	actor := strings.TrimSpace(deployment.Actor)
	if actor == "" {
		actor = "dashboard"
	}
	note := fmt.Sprintf(
		"Marked as expected deployment activity for %s (%s to %s).",
		deployment.Version,
		windowStart.Format(time.RFC3339),
		windowEnd.Format(time.RFC3339),
	)
	return repository.UpdateOpenHubFindingStatusesForRulesInWindow(ctx, deployment.EnvironmentID, deployment.AppID, deploymentExpectedRuleIDs, windowStart, windowEnd, domain.HubFindingStatusUpdate{
		Status: "acknowledged",
		Reason: "deployment_window",
		Note:   note,
		Actor:  actor,
	})
}

func activeDeploymentMarkers(deployments []domain.DeploymentMarker, appID domain.ID, firstEventAt time.Time, lastEventAt time.Time) []domain.DeploymentMarker {
	eventStart, eventEnd, ok := findingEventWindow(firstEventAt, lastEventAt)
	if !ok {
		return nil
	}

	active := make([]domain.DeploymentMarker, 0)
	for _, deployment := range deployments {
		if !deploymentAppliesToApp(deployment, appID) {
			continue
		}
		windowStart, windowEnd, ok := deploymentScoringWindow(deployment)
		if !ok {
			continue
		}
		if eventEnd.Before(windowStart) || eventStart.After(windowEnd) {
			continue
		}
		active = append(active, deployment)
	}
	slices.SortFunc(active, func(a domain.DeploymentMarker, b domain.DeploymentMarker) int {
		if a.StartedAt.Equal(b.StartedAt) {
			return strings.Compare(string(a.ID), string(b.ID))
		}
		if a.StartedAt.Before(b.StartedAt) {
			return -1
		}
		return 1
	})
	return active
}

func findingEventWindow(firstEventAt time.Time, lastEventAt time.Time) (time.Time, time.Time, bool) {
	if firstEventAt.IsZero() && lastEventAt.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	if firstEventAt.IsZero() {
		firstEventAt = lastEventAt
	}
	if lastEventAt.IsZero() {
		lastEventAt = firstEventAt
	}
	if lastEventAt.Before(firstEventAt) {
		firstEventAt, lastEventAt = lastEventAt, firstEventAt
	}
	return firstEventAt.UTC(), lastEventAt.UTC(), true
}

func deploymentAppliesToApp(deployment domain.DeploymentMarker, appID domain.ID) bool {
	return deployment.AppID == "" || deployment.AppID == appID
}

func deploymentScoringWindow(deployment domain.DeploymentMarker) (time.Time, time.Time, bool) {
	if deployment.StartedAt.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	start := deployment.StartedAt.UTC().Add(-deploymentWindowPadding)
	end := deployment.StartedAt.UTC().Add(openDeploymentWindow)
	if deployment.FinishedAt != nil && !deployment.FinishedAt.IsZero() {
		end = deployment.FinishedAt.UTC()
	}
	end = end.Add(deploymentWindowPadding)
	if end.Before(start) {
		end = start
	}
	return start, end, true
}

func applyDeploymentScoring(finding domain.HubFinding, deployments []domain.DeploymentMarker) domain.HubFinding {
	originalSeverity := finding.Severity
	adjustedSeverity := deploymentAdjustedSeverity(finding)
	finding.Severity = adjustedSeverity

	metadata := cloneAnyMap(finding.Metadata)
	metadata["deployment_context"] = map[string]any{
		"active":                 true,
		"severity_adjusted":      adjustedSeverity != originalSeverity,
		"original_severity":      string(originalSeverity),
		"adjusted_severity":      string(adjustedSeverity),
		"window_padding_seconds": int(deploymentWindowPadding.Seconds()),
		"open_window_seconds":    int(openDeploymentWindow.Seconds()),
		"deployments":            deploymentMetadataRecords(deployments),
	}
	finding.Metadata = metadata
	return finding
}

func deploymentAdjustedSeverity(finding domain.HubFinding) domain.Severity {
	if !deploymentCanLowerFinding(finding) {
		return finding.Severity
	}
	switch finding.Severity {
	case domain.SeverityMedium:
		return domain.SeverityLow
	case domain.SeverityLow:
		return domain.SeverityInfo
	default:
		return finding.Severity
	}
}

func deploymentCanLowerFinding(finding domain.HubFinding) bool {
	if severityRank(finding.Severity) >= severityRank(domain.SeverityHigh) {
		return false
	}
	definition, ok := ruleDefinition(finding.RuleID)
	if !ok {
		return false
	}
	return definition.Category == RuleCategoryDatabaseSnapshot ||
		definition.Category == RuleCategoryBrowserScript ||
		definition.Category == RuleCategoryFilePath
}

func deploymentMetadataRecords(deployments []domain.DeploymentMarker) []map[string]any {
	records := make([]map[string]any, 0, len(deployments))
	for _, deployment := range deployments {
		record := map[string]any{
			"id":         string(deployment.ID),
			"app_id":     string(deployment.AppID),
			"version":    deployment.Version,
			"commit_sha": deployment.CommitSHA,
			"actor":      deployment.Actor,
			"started_at": deployment.StartedAt.UTC().Format(time.RFC3339Nano),
		}
		if deployment.FinishedAt != nil && !deployment.FinishedAt.IsZero() {
			record["finished_at"] = deployment.FinishedAt.UTC().Format(time.RFC3339Nano)
		} else {
			record["finished_at"] = nil
		}
		records = append(records, record)
	}
	return records
}
