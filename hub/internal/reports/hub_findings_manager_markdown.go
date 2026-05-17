package reports

import (
	"fmt"
	"io"
	"strings"
)

func WriteHubFindingsManagerMarkdown(w io.Writer, report HubFindingsJSONReport) error {
	var builder strings.Builder
	findings := markdownSortedFindings(report.Findings)
	stats := managerSummaryStats(findings)

	builder.WriteString("# Aegrail Manager Summary\n\n")
	fmt.Fprintf(&builder, "Generated: %s\n\n", markdownTime(report.GeneratedAt))
	builder.WriteString("## Scope\n\n")
	markdownKeyValue(&builder, "Organization", report.Scope.Organization)
	markdownKeyValue(&builder, "Project", report.Scope.Project)
	markdownKeyValue(&builder, "Environment", report.Scope.Environment)
	if strings.TrimSpace(report.Scope.App) != "" {
		markdownKeyValue(&builder, "App", report.Scope.App)
	}

	builder.WriteString("\n## What Happened\n\n")
	if len(findings) == 0 {
		builder.WriteString("Aegrail has no persisted Hub findings for this scope.\n")
	} else {
		fmt.Fprintf(
			&builder,
			"Aegrail found %d persisted finding(s) for this scope. %d finding(s) are critical or high risk. The top item is \"%s\" (%s), currently rated %s.\n",
			len(findings),
			stats.CriticalHigh,
			markdownInline(findings[0].Title),
			markdownInline(findings[0].ID),
			markdownInline(markdownRisk(findings[0])),
		)
	}

	builder.WriteString("\n## Business Impact\n\n")
	builder.WriteString(managerBusinessImpact(stats))
	builder.WriteString("\n")

	builder.WriteString("\n## Current Status\n\n")
	if len(findings) == 0 {
		builder.WriteString("- No active finding status records in this report scope.\n")
	} else {
		fmt.Fprintf(&builder, "- Open: %d\n", stats.StatusCounts["open"])
		fmt.Fprintf(&builder, "- Acknowledged: %d\n", stats.StatusCounts["acknowledged"])
		fmt.Fprintf(&builder, "- Resolved: %d\n", stats.StatusCounts["resolved"])
		fmt.Fprintf(&builder, "- False positive: %d\n", stats.StatusCounts["false_positive"])
		if stats.DeploymentContext > 0 {
			fmt.Fprintf(&builder, "- Findings with active deployment context: %d\n", stats.DeploymentContext)
		}
	}

	if len(findings) > 0 {
		builder.WriteString("\n## Priority Findings\n\n")
		limit := min(5, len(findings))
		for index := 0; index < limit; index++ {
			finding := findings[index]
			fmt.Fprintf(
				&builder,
				"- %s: %s, %s, status %s\n",
				markdownInline(finding.ID),
				markdownInline(finding.Title),
				markdownInline(markdownRisk(finding)),
				markdownInline(managerFindingStatus(finding)),
			)
		}
	}

	builder.WriteString("\n## Recommended Next Steps\n\n")
	for _, step := range managerRecommendedSteps(findings, stats) {
		fmt.Fprintf(&builder, "- %s\n", markdownInline(step))
	}

	_, err := io.WriteString(w, builder.String())
	return err
}

type managerStats struct {
	CriticalHigh      int
	Medium            int
	LowInfo           int
	DeploymentContext int
	StatusCounts      map[string]int
}

func managerSummaryStats(findings []HubFindingJSONRecord) managerStats {
	stats := managerStats{StatusCounts: map[string]int{}}
	for _, finding := range findings {
		switch markdownRiskBand(finding) {
		case "critical", "high":
			stats.CriticalHigh++
		case "medium":
			stats.Medium++
		default:
			stats.LowInfo++
		}
		stats.StatusCounts[managerFindingStatus(finding)]++
		if context, ok := metadataMap(finding.Metadata, "deployment_context"); ok && metadataBool(context, "active") {
			stats.DeploymentContext++
		}
	}
	return stats
}

func managerFindingStatus(finding HubFindingJSONRecord) string {
	status := strings.TrimSpace(finding.Status)
	if status == "" {
		return "open"
	}
	return status
}

func managerBusinessImpact(stats managerStats) string {
	switch {
	case stats.CriticalHigh > 0:
		return "Critical or high-risk evidence may indicate unauthorized access, web application tampering, database privilege drift, persistence, or unsafe third-party script changes. Treat the highest-risk items as incident triage until an operator confirms the cause."
	case stats.Medium > 0:
		return "Aegrail found medium-risk drift that could affect application integrity or operational trust if left unreviewed. Review the affected systems and confirm whether the changes match expected maintenance."
	case stats.LowInfo > 0:
		return "Aegrail found low or informational signals. These do not currently point to a high-risk incident, but they can still help confirm coverage and spot early drift."
	default:
		return "No business-impacting findings are present in this report scope."
	}
}

func managerRecommendedSteps(findings []HubFindingJSONRecord, stats managerStats) []string {
	if len(findings) == 0 {
		return []string{
			"Keep agents, database checks, and browser crawls running on the normal schedule.",
			"Review coverage records to confirm each production site still has file, log, database, and browser monitoring.",
		}
	}

	steps := []string{
		"Review the priority finding IDs in the technical report and Hub timeline.",
		"Preserve referenced evidence before cleanup, deployment rollback, or account changes.",
	}
	if stats.CriticalHigh > 0 {
		steps = append(steps, "Start incident triage for critical and high-risk findings until authorized activity is confirmed.")
	}
	if stats.DeploymentContext > 0 {
		steps = append(steps, "Compare findings inside deployment windows against the release artifact and deployment actor.")
	}
	steps = append(steps, "Update finding status to acknowledged, resolved, or false positive after operator review.")
	return steps
}
