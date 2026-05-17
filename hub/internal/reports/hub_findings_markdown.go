package reports

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

const markdownEvidenceLimit = 8

func WriteHubFindingsMarkdown(w io.Writer, report HubFindingsJSONReport) error {
	var builder strings.Builder
	findings := markdownSortedFindings(report.Findings)

	builder.WriteString("# Aegrail Technical Findings Report\n\n")
	fmt.Fprintf(&builder, "Generated: %s\n\n", markdownTime(report.GeneratedAt))
	builder.WriteString("## Scope\n\n")
	markdownKeyValue(&builder, "Tool", markdownTool(report.Tool))
	markdownKeyValue(&builder, "Organization", report.Scope.Organization)
	markdownKeyValue(&builder, "Project", report.Scope.Project)
	markdownKeyValue(&builder, "Environment", report.Scope.Environment)
	if strings.TrimSpace(report.Scope.App) != "" {
		markdownKeyValue(&builder, "App", report.Scope.App)
	}
	builder.WriteString("\n")

	builder.WriteString("## Summary\n\n")
	markdownKeyValue(&builder, "Findings", strconv.Itoa(report.FindingCount))
	if report.FindingCount > 0 {
		builder.WriteString("\n| Risk | Count |\n| --- | ---: |\n")
		for _, row := range markdownRiskDistribution(findings) {
			fmt.Fprintf(&builder, "| %s | %d |\n", markdownCell(row.Band), row.Count)
		}
		builder.WriteString("\n")
	}

	if len(findings) == 0 {
		builder.WriteString("No persisted Hub findings matched this report scope.\n")
		_, err := io.WriteString(w, builder.String())
		return err
	}

	builder.WriteString("## Findings\n")
	for index, finding := range findings {
		fmt.Fprintf(&builder, "\n### %d. %s\n\n", index+1, markdownInline(finding.Title))
		markdownKeyValue(&builder, "Finding ID", finding.ID)
		markdownKeyValue(&builder, "Rule", markdownRule(finding))
		markdownKeyValue(&builder, "Severity", finding.Severity)
		markdownKeyValue(&builder, "Confidence", finding.Confidence)
		markdownKeyValue(&builder, "Risk", markdownRisk(finding))
		markdownKeyValue(&builder, "Status", markdownStatus(finding))
		markdownKeyValue(&builder, "Window", markdownWindow(finding))
		markdownKeyValue(&builder, "Dedupe key", finding.DedupeKey)

		if text := markdownInline(finding.Summary); text != "" {
			builder.WriteString("\nSummary: ")
			builder.WriteString(text)
			builder.WriteString("\n")
		}
		if text := markdownInline(finding.Description); text != "" {
			builder.WriteString("\nDescription: ")
			builder.WriteString(text)
			builder.WriteString("\n")
		}

		markdownDeploymentContext(&builder, finding.Metadata)
		markdownOperatorAction(&builder, finding)
		markdownEvidence(&builder, finding)
		markdownRiskFactors(&builder, finding.Metadata)
		markdownNextChecks(&builder, finding)
	}

	_, err := io.WriteString(w, builder.String())
	return err
}

func markdownSortedFindings(findings []HubFindingJSONRecord) []HubFindingJSONRecord {
	items := slices.Clone(findings)
	slices.SortFunc(items, func(a HubFindingJSONRecord, b HubFindingJSONRecord) int {
		if a.RiskScore != b.RiskScore {
			return b.RiskScore - a.RiskScore
		}
		if severityRankText(a.Severity) != severityRankText(b.Severity) {
			return severityRankText(b.Severity) - severityRankText(a.Severity)
		}
		if !a.FirstEventAt.Equal(b.FirstEventAt) {
			if a.FirstEventAt.After(b.FirstEventAt) {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	return items
}

type markdownDistributionRow struct {
	Band  string
	Count int
}

func markdownRiskDistribution(findings []HubFindingJSONRecord) []markdownDistributionRow {
	counts := map[string]int{}
	for _, finding := range findings {
		counts[markdownRiskBand(finding)]++
	}
	order := []string{"critical", "high", "medium", "low", "informational", "scored", "unscored"}
	rows := make([]markdownDistributionRow, 0, len(order))
	for _, band := range order {
		if count := counts[band]; count > 0 {
			rows = append(rows, markdownDistributionRow{Band: band, Count: count})
			delete(counts, band)
		}
	}
	unknownBands := make([]string, 0, len(counts))
	for band := range counts {
		unknownBands = append(unknownBands, band)
	}
	slices.Sort(unknownBands)
	for _, band := range unknownBands {
		if counts[band] > 0 {
			rows = append(rows, markdownDistributionRow{Band: band, Count: counts[band]})
		}
	}
	return rows
}

func markdownTool(tool ToolInfo) string {
	parts := []string{}
	if strings.TrimSpace(tool.Name) != "" {
		parts = append(parts, tool.Name)
	}
	if strings.TrimSpace(tool.Binary) != "" {
		parts = append(parts, "binary "+tool.Binary)
	}
	if strings.TrimSpace(tool.Version) != "" {
		parts = append(parts, "version "+tool.Version)
	}
	if strings.TrimSpace(tool.Commit) != "" {
		parts = append(parts, "commit "+tool.Commit)
	}
	if len(parts) == 0 {
		return "Aegrail"
	}
	return strings.Join(parts, ", ")
}

func markdownRule(finding HubFindingJSONRecord) string {
	if strings.TrimSpace(finding.RuleVersion) == "" {
		return finding.RuleID
	}
	return finding.RuleID + "@" + finding.RuleVersion
}

func markdownStatus(finding HubFindingJSONRecord) string {
	status := finding.Status
	if strings.TrimSpace(status) == "" {
		status = "open"
	}
	details := []string{status}
	if strings.TrimSpace(finding.StatusReason) != "" {
		details = append(details, finding.StatusReason)
	}
	if strings.TrimSpace(finding.StatusActor) != "" {
		details = append(details, "by "+finding.StatusActor)
	}
	if !finding.StatusUpdatedAt.IsZero() {
		details = append(details, "updated "+markdownTime(finding.StatusUpdatedAt))
	}
	return strings.Join(details, ", ")
}

func markdownRisk(finding HubFindingJSONRecord) string {
	band := markdownRiskBand(finding)
	if finding.RiskScore <= 0 {
		return band
	}
	return fmt.Sprintf("%s (%d)", band, finding.RiskScore)
}

func markdownRiskBand(finding HubFindingJSONRecord) string {
	if strings.TrimSpace(finding.RiskBand) != "" {
		return strings.ToLower(strings.TrimSpace(finding.RiskBand))
	}
	if finding.RiskScore > 0 {
		return "scored"
	}
	return "unscored"
}

func markdownWindow(finding HubFindingJSONRecord) string {
	first := markdownTime(finding.FirstEventAt)
	last := markdownTime(finding.LastEventAt)
	if first == "-" && last == "-" {
		return "-"
	}
	if last == "-" || first == last {
		return first
	}
	if first == "-" {
		return last
	}
	return first + " to " + last
}

func markdownDeploymentContext(builder *strings.Builder, metadata map[string]any) {
	context, ok := metadataMap(metadata, "deployment_context")
	if !ok {
		return
	}
	active := metadataBool(context, "active")
	adjusted := metadataBool(context, "severity_adjusted")
	builder.WriteString("\nDeployment context:\n")
	fmt.Fprintf(builder, "- Active deployment window: %t\n", active)
	if original := metadataString(context, "original_severity"); original != "" {
		adjustedSeverity := metadataString(context, "adjusted_severity")
		if adjustedSeverity == "" {
			adjustedSeverity = "-"
		}
		fmt.Fprintf(builder, "- Severity adjustment: %s to %s (adjusted: %t)\n", markdownInline(original), markdownInline(adjustedSeverity), adjusted)
	}
	deployments := metadataMapSlice(context, "deployments")
	for index, deployment := range deployments {
		if index >= 3 {
			fmt.Fprintf(builder, "- Additional deployments: %d omitted\n", len(deployments)-index)
			break
		}
		version := metadataString(deployment, "version")
		if version == "" {
			version = metadataString(deployment, "commit_sha")
		}
		if version == "" {
			version = metadataString(deployment, "id")
		}
		actor := metadataString(deployment, "actor")
		startedAt := metadataString(deployment, "started_at")
		fmt.Fprintf(builder, "- Deployment: %s, actor %s, started %s\n", markdownInline(version), markdownInline(actor), markdownInline(startedAt))
	}
}

func markdownOperatorAction(builder *strings.Builder, finding HubFindingJSONRecord) {
	action := finding.OperatorAction
	if len(action) == 0 {
		if metadataAction, ok := metadataMap(finding.Metadata, "operator_action"); ok {
			action = metadataAction
		}
	}
	if len(action) == 0 {
		return
	}
	builder.WriteString("\nOperator action:\n")
	if primary := metadataString(action, "primary_action"); primary != "" {
		fmt.Fprintf(builder, "- Primary action: %s\n", markdownInline(primary))
	}
	if safe := metadataString(action, "safe_to_acknowledge_when"); safe != "" {
		fmt.Fprintf(builder, "- Acknowledge when: %s\n", markdownInline(safe))
	}
	if escalate := metadataString(action, "escalate_when"); escalate != "" {
		fmt.Fprintf(builder, "- Escalate when: %s\n", markdownInline(escalate))
	}
}

func markdownEvidence(builder *strings.Builder, finding HubFindingJSONRecord) {
	events := metadataMapSlice(finding.Metadata, "events")
	if len(events) == 0 {
		if len(finding.EventIDs) == 0 {
			return
		}
		builder.WriteString("\nEvidence references:\n")
		for _, eventID := range finding.EventIDs {
			fmt.Fprintf(builder, "- %s\n", markdownInline(eventID))
		}
		return
	}

	builder.WriteString("\nEvidence references:\n")
	for index, event := range events {
		if index >= markdownEvidenceLimit {
			fmt.Fprintf(builder, "- %d additional evidence event(s) omitted from report body\n", len(events)-index)
			break
		}
		parts := []string{
			metadataString(event, "event_id"),
			metadataString(event, "event_time"),
			metadataString(event, "host"),
			metadataString(event, "type"),
			metadataString(event, "target"),
		}
		builder.WriteString("- ")
		builder.WriteString(markdownInline(strings.Join(nonEmptyStrings(parts), " | ")))
		builder.WriteString("\n")
	}
}

func markdownRiskFactors(builder *strings.Builder, metadata map[string]any) {
	risk, ok := metadataMap(metadata, "risk")
	if !ok {
		return
	}
	factors := metadataMapSlice(risk, "factors")
	if len(factors) == 0 {
		return
	}
	builder.WriteString("\nRisk scoring factors:\n")
	for _, factor := range factors {
		id := metadataString(factor, "id")
		reason := metadataString(factor, "reason")
		points := metadataInt(factor, "points")
		fmt.Fprintf(builder, "- %+d %s: %s\n", points, markdownInline(id), markdownInline(reason))
	}
}

func markdownNextChecks(builder *strings.Builder, finding HubFindingJSONRecord) {
	checks := nextChecksForFinding(finding)
	if len(checks) == 0 {
		return
	}
	builder.WriteString("\nRecommended next checks:\n")
	for _, check := range checks {
		fmt.Fprintf(builder, "- %s\n", markdownInline(check))
	}
}

func nextChecksForFinding(finding HubFindingJSONRecord) []string {
	rule := strings.ToLower(finding.RuleID + " " + finding.Title + " " + finding.Summary)
	switch {
	case strings.Contains(rule, "incident-chain") || strings.Contains(rule, "file-change-to"):
		return []string{
			"Inspect the referenced file and compare it against the expected release artifact.",
			"Review authentication, admin, database, and cron activity around the finding window.",
			"Preserve the referenced evidence before cleanup or deployment rollback.",
		}
	case strings.Contains(rule, "browser") || strings.Contains(rule, "script") || strings.Contains(rule, "tag-manager"):
		return []string{
			"Review the script URL, host, and tag manager container against the approved allowlist.",
			"Check recent CMS content, theme, plugin, and page builder edits for injected script tags.",
		}
	case strings.Contains(rule, "wordpress") || strings.Contains(rule, "capabilities") || strings.Contains(rule, "option"):
		return []string{
			"Review recent WordPress administrator, capability, option, plugin, theme, cron, and content changes.",
			"Confirm whether the change matches a deployment, support action, or authorized admin session.",
		}
	case strings.Contains(rule, "prestashop") || strings.Contains(rule, "superadmin") || strings.Contains(rule, "payment"):
		return []string{
			"Review recent PrestaShop employee, module, payment, mail, hook, tab, and access changes.",
			"Confirm whether the change matches an authorized back office or deployment action.",
		}
	case strings.Contains(rule, "mautic") || strings.Contains(rule, "oauth") || strings.Contains(rule, "webhook"):
		return []string{
			"Review recent Mautic user, role, plugin, integration, OAuth client, and webhook changes.",
			"Confirm whether the change matches an authorized marketing/admin action or deployment.",
		}
	case strings.Contains(rule, "yii2-rbac") || strings.Contains(rule, "yii2") || strings.Contains(rule, "rbac"):
		return []string{
			"Review recent Yii2 RBAC user, role, RBAC, migration, and config changes.",
			"Confirm whether the change matches an authorized deployment or admin action.",
		}
	case strings.Contains(rule, "laravel"):
		return []string{
			"Review recent Laravel user, role, permission, migration, session, reset-token, and config changes.",
			"Confirm whether the change matches an authorized deployment, queue/admin action, or support login.",
		}
	case strings.Contains(rule, "tor") || strings.Contains(rule, "request") || strings.Contains(rule, "admin"):
		return []string{
			"Review normalized access logs around the finding window for repeated source fingerprints and admin paths.",
			"Compare the request pattern against known monitoring, uptime, CDN, or WAF traffic.",
		}
	default:
		return []string{
			"Open the finding in the Hub timeline and review the referenced events in chronological order.",
			"Compare affected hosts against the expected release, CMS configuration, and deployment history.",
		}
	}
}

func markdownKeyValue(builder *strings.Builder, key string, value string) {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	fmt.Fprintf(builder, "- %s: %s\n", markdownInline(key), markdownInline(value))
}

func markdownCell(value string) string {
	value = markdownInline(value)
	return strings.ReplaceAll(value, "|", "\\|")
}

func markdownInline(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	return strings.TrimSpace(value)
}

func markdownTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func metadataMap(metadata map[string]any, key string) (map[string]any, bool) {
	if metadata == nil {
		return nil, false
	}
	value, ok := metadata[key].(map[string]any)
	return value, ok
}

func metadataMapSlice(metadata map[string]any, key string) []map[string]any {
	if metadata == nil {
		return nil
	}
	switch values := metadata[key].(type) {
	case []map[string]any:
		return values
	case []any:
		items := make([]map[string]any, 0, len(values))
		for _, value := range values {
			item, ok := value.(map[string]any)
			if ok {
				items = append(items, item)
			}
		}
		return items
	default:
		return nil
	}
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	switch value := metadata[key].(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(value)
	}
}

func metadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, _ := metadata[key].(bool)
	return value
}

func metadataInt(metadata map[string]any, key string) int {
	if metadata == nil {
		return 0
	}
	switch value := metadata[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

func nonEmptyStrings(values []string) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			items = append(items, value)
		}
	}
	return items
}

func severityRankText(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	default:
		return 0
	}
}
