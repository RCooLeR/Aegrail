package reports

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type FindingReviewReport struct {
	GeneratedAt  time.Time           `json:"generated_at"`
	Tool         ToolInfo            `json:"tool"`
	Scope        HubFindingsScope    `json:"scope"`
	FindingCount int                 `json:"finding_count"`
	Items        []FindingReviewItem `json:"items"`
}

type FindingReviewItem struct {
	Finding     HubFindingJSONRecord       `json:"finding"`
	ModelReport *FindingReviewModelSummary `json:"model_report,omitempty"`
}

type FindingReviewModelSummary struct {
	ID                    string    `json:"id"`
	Status                string    `json:"status"`
	ModelName             string    `json:"model_name,omitempty"`
	PromptTemplateVersion string    `json:"prompt_template_version"`
	EvidenceBundleSHA256  string    `json:"evidence_bundle_sha256"`
	GeneratedAt           time.Time `json:"generated_at"`
	AnalysisExcerpt       string    `json:"analysis_excerpt,omitempty"`
	Error                 string    `json:"error,omitempty"`
}

func BuildFindingReviewReport(meta domain.AppMeta, scope HubFindingsScope, findings []domain.HubFinding, modelReports []domain.ModelAnalysisReport, generatedAt time.Time) FindingReviewReport {
	findingsReport := BuildHubFindingsJSONReport(meta, scope, findings, generatedAt)
	latestByFinding := latestModelReportsByFinding(modelReports)
	items := make([]FindingReviewItem, 0, len(findingsReport.Findings))
	for _, finding := range markdownSortedFindings(findingsReport.Findings) {
		item := FindingReviewItem{Finding: finding}
		if report, ok := latestByFinding[finding.ID]; ok {
			summary := findingReviewModelSummary(report)
			item.ModelReport = &summary
		}
		items = append(items, item)
	}
	return FindingReviewReport{
		GeneratedAt:  generatedAt.UTC(),
		Tool:         findingsReport.Tool,
		Scope:        scope,
		FindingCount: len(items),
		Items:        items,
	}
}

func WriteFindingReviewJSON(w io.Writer, report FindingReviewReport, pretty bool) error {
	encoder := json.NewEncoder(w)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}

func WriteFindingReviewMarkdown(w io.Writer, report FindingReviewReport) error {
	var builder strings.Builder
	builder.WriteString("# Aegrail Finding Review\n\n")
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

	if len(report.Items) == 0 {
		builder.WriteString("No persisted Hub findings matched this report scope.\n")
		_, err := io.WriteString(w, builder.String())
		return err
	}

	builder.WriteString("## Side-By-Side Review\n\n")
	builder.WriteString("| Finding | Deterministic Hub View | Latest Model Analysis |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, item := range report.Items {
		fmt.Fprintf(
			&builder,
			"| %s | %s | %s |\n",
			markdownCell(reviewFindingCell(item.Finding)),
			markdownCell(reviewDeterministicCell(item.Finding)),
			markdownCell(reviewModelCell(item.ModelReport)),
		)
	}
	builder.WriteString("\n")
	_, err := io.WriteString(w, builder.String())
	return err
}

func latestModelReportsByFinding(modelReports []domain.ModelAnalysisReport) map[string]domain.ModelAnalysisReport {
	items := slices.Clone(modelReports)
	slices.SortFunc(items, func(a domain.ModelAnalysisReport, b domain.ModelAnalysisReport) int {
		if !a.GeneratedAt.Equal(b.GeneratedAt) {
			if a.GeneratedAt.After(b.GeneratedAt) {
				return -1
			}
			return 1
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			if a.CreatedAt.After(b.CreatedAt) {
				return -1
			}
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	latest := map[string]domain.ModelAnalysisReport{}
	for _, report := range items {
		for _, findingID := range report.SourceFindingIDs {
			id := string(findingID)
			if id == "" {
				continue
			}
			if _, exists := latest[id]; !exists {
				latest[id] = report
			}
		}
	}
	return latest
}

func findingReviewModelSummary(report domain.ModelAnalysisReport) FindingReviewModelSummary {
	return FindingReviewModelSummary{
		ID:                    string(report.ID),
		Status:                report.Status,
		ModelName:             report.ModelName,
		PromptTemplateVersion: report.PromptTemplateVersion,
		EvidenceBundleSHA256:  report.EvidenceBundleSHA256,
		GeneratedAt:           report.GeneratedAt,
		AnalysisExcerpt:       reviewExcerpt(report.Analysis, 420),
		Error:                 reviewExcerpt(report.Error, 220),
	}
}

func reviewFindingCell(finding HubFindingJSONRecord) string {
	risk := markdownRisk(finding)
	if risk == "" {
		risk = finding.Severity
	}
	return strings.TrimSpace(finding.ID + ": " + finding.Title + " (" + risk + ")")
}

func reviewDeterministicCell(finding HubFindingJSONRecord) string {
	parts := []string{}
	if finding.Summary != "" {
		parts = append(parts, finding.Summary)
	}
	if action := operatorPrimaryActionText(finding); action != "" {
		parts = append(parts, "Action: "+action)
	}
	if len(parts) == 0 {
		parts = append(parts, "Review the deterministic rule evidence and timeline.")
	}
	return strings.Join(parts, " ")
}

func reviewModelCell(report *FindingReviewModelSummary) string {
	if report == nil {
		return "No model report yet."
	}
	parts := []string{report.Status}
	if report.ModelName != "" {
		parts = append(parts, report.ModelName)
	}
	if !report.GeneratedAt.IsZero() {
		parts = append(parts, markdownTime(report.GeneratedAt))
	}
	if report.Error != "" {
		parts = append(parts, "Error: "+report.Error)
	} else if report.AnalysisExcerpt != "" {
		parts = append(parts, report.AnalysisExcerpt)
	}
	return strings.Join(parts, " | ")
}

func operatorPrimaryActionText(finding HubFindingJSONRecord) string {
	if finding.OperatorAction != nil {
		if action := metadataString(finding.OperatorAction, "primary_action"); action != "" {
			return action
		}
	}
	if action, ok := metadataMap(finding.Metadata, "operator_action"); ok {
		return metadataString(action, "primary_action")
	}
	return ""
}

func reviewExcerpt(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" || limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return strings.TrimSpace(value[:limit-3]) + "..."
}
