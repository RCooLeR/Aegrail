package reports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

const (
	ModelAnalysisReportSchema          = "aegrail.model_analysis_report.v1"
	ModelAnalysisPromptTemplateID      = "aegrail.incident_analysis"
	ModelAnalysisPromptTemplateVersion = "2026-05-16.1"
	ModelAnalysisStatusCompleted       = "completed"
	ModelAnalysisStatusOffline         = "offline"
	ModelAnalysisStatusFailed          = "failed"
)

const modelAnalysisNotice = "Model output is advisory analysis. Deterministic Aegrail findings remain the source of truth."

const modelAnalysisSystemPrompt = `You are Aegrail's incident assistant for production security review.
Use only the supplied redacted evidence bundle and never invent facts.
Separate confirmed facts from inference and keep recommendations investigative and actionable.
Never provide exploit instructions or destructive remediation.
Return strict structured JSON so Aegrail can render controlled HTML. Do not return markdown or HTML.
If evidence is thin, say so clearly and ask for follow-up checks instead of guessing.`

const modelAnalysisUserPromptTemplate = `Analyze this redacted Aegrail evidence bundle and output JSON using EXACTLY this schema:

{
  "executive_summary": "2-4 sentence incident readout, no speculation",
  "operator_comment": "2-3 sentence issue comment explaining what this probably means, why, and the next operator action",
  "operator_insight": {
    "operator_summary": "one-paragraph operator-focused summary",
    "likely_real_issue": "true|false",
    "false_positive_risk": "true|false",
    "platform_expected_behavior": "what looks normal for this platform",
    "suspicious_indicators": [
      "high-signal markers that increase confidence"
    ],
    "recommended_operator_response": "immediate and concrete operator next action",
    "normal_operations_checks": [
      "checks to rule out planned admin/deployment behavior"
    ]
  },
  "incident_assessment": {
    "platform_behavior_likely": "true|false",
    "platform_context": "how this looks for the given platform",
    "is_intrusive": "true|false",
    "confidence": "high|medium|low",
    "rationale": "short explanation"
  },
  "issue_judgment": {
    "is_likely_true_issue": "true|false",
    "is_false_positive_risk": "true|false",
    "recommended_priority": "critical|high|medium|low|info",
    "recommended_response": "immediate operator action"
  },
  "incident_chain": [
    {
      "step": "what happened, phrased for action",
      "evidence": ["finding:ID", "event:ID"],
      "likelihood": "high|medium|low",
      "impact": "why this matters",
      "inference": "observation or uncertainty statement"
    }
  ],
  "priority_findings": [
    {
      "priority": "critical|high|medium|low|info",
      "finding_id": "source finding id if applicable",
      "observation": "concise observed signal",
      "investigation_recommendation": "next human action",
      "requires_human_verification": true
    }
  ],
  "recommended_next_checks": [
    "ordered list of verification commands or evidence checks"
  ],
  "uncertainty_and_gaps": [
    "what is missing / where inference starts"
  ]
}

Platform context:
{{PLATFORM_CONTEXT}}

Issue profile:
{{ISSUE_PROFILE}}

Issue context:
{{ISSUE_CONTEXT}}

Rules:
- Reference finding IDs when discussing evidence.
- Treat deterministic finding severity, confidence, risk score, and event references as source-of-truth facts.
- Return JSON only, no markdown, no extra prose.
- Write UI-ready sentences that explain meaning and next action; do not merely restate the raw fields.
- Write operator_comment as a useful human comment for the issue detail page: what likely happened, what normal explanation could fit, what makes it suspicious, and exactly what the operator should verify next.
- If the finding looks like a deployment/module/plugin/theme update, say what evidence would justify marking the timeframe as deployment instead of suppressing the issue silently.
- If the finding looks like ignore-rule noise, state the narrow ignore scope that would be safe and why broad ignores would be risky.
- For common WordPress, WordPress multisite, PrestaShop, and Mautic behavior, explicitly say what could be normal and what would make it suspicious.
- If evidence is insufficient for a chain, say so.
- For every schema field under "incident_assessment" and "issue_judgment", provide the best available answer, even if uncertain.
- Use "platform_behavior_likely" and "is_false_positive_risk" to help indicate normal/platform-expected behavior.
- Do not include exploit instructions, destructive remediation, or commands that modify production state.
- Keep every item short, factual, and triage-first.

Evidence bundle JSON:
{{EVIDENCE_BUNDLE_JSON}}
`

type ModelAnalysisOptions struct {
	Model             string
	AppKind           string
	FindingRuleID     string
	FindingID         string
	FindingTitle      string
	FindingSummary    string
	FindingSeverity   string
	FindingConfidence string
}

type modelAnalysisOperatorInsight struct {
	OperatorSummary           string   `json:"operator_summary"`
	LikelyRealIssue           string   `json:"likely_real_issue"`
	FalsePositiveRisk         string   `json:"false_positive_risk"`
	PlatformExpectedBehavior  string   `json:"platform_expected_behavior"`
	SuspiciousIndicators      []string `json:"suspicious_indicators"`
	RecommendedOperatorAction string   `json:"recommended_operator_response"`
	NormalOperationsChecks    []string `json:"normal_operations_checks"`
}

type modelAnalysisIncidentAssessment struct {
	PlatformBehaviorLikely string `json:"platform_behavior_likely"`
	PlatformContext        string `json:"platform_context"`
	IsIntrusive            string `json:"is_intrusive"`
	Confidence             string `json:"confidence"`
	Rationale              string `json:"rationale"`
}

type modelAnalysisIssueJudgment struct {
	IsLikelyTrueIssue   string `json:"is_likely_true_issue"`
	FalsePositiveRisk   string `json:"is_false_positive_risk"`
	RecommendedPriority string `json:"recommended_priority"`
	RecommendedResponse string `json:"recommended_response"`
}

type ModelAnalysisPromptTemplate struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type ModelAnalysisEvidenceBundleRef struct {
	Schema           string    `json:"schema"`
	SHA256           string    `json:"sha256"`
	RedactionVersion string    `json:"redaction_version"`
	GeneratedAt      time.Time `json:"generated_at"`
}

type ModelAnalysisModelInfo struct {
	Provider string `json:"provider,omitempty"`
	BaseURL  string `json:"base_url,omitempty"`
	Model    string `json:"model,omitempty"`
	Offline  bool   `json:"offline"`
}

type ModelAnalysisStats struct {
	TotalDurationMillis int64 `json:"total_duration_millis,omitempty"`
	PromptEvalCount     int   `json:"prompt_eval_count,omitempty"`
	EvalCount           int   `json:"eval_count,omitempty"`
}

type ModelAnalysisReport struct {
	ID                  string                         `json:"id,omitempty"`
	Schema              string                         `json:"schema"`
	GeneratedAt         time.Time                      `json:"generated_at"`
	CreatedAt           *time.Time                     `json:"created_at,omitempty"`
	Tool                ToolInfo                       `json:"tool"`
	Scope               HubFindingsScope               `json:"scope"`
	Status              string                         `json:"status"`
	Notice              string                         `json:"notice"`
	FindingCount        int                            `json:"finding_count"`
	SourceFindingIDs    []string                       `json:"source_finding_ids"`
	EvidenceBundle      ModelAnalysisEvidenceBundleRef `json:"evidence_bundle"`
	PromptTemplate      ModelAnalysisPromptTemplate    `json:"prompt_template"`
	PromptSHA256        string                         `json:"prompt_sha256"`
	Model               ModelAnalysisModelInfo         `json:"model"`
	Stats               *ModelAnalysisStats            `json:"stats,omitempty"`
	Analysis            string                         `json:"analysis,omitempty"`
	Error               string                         `json:"error,omitempty"`
	DeterministicSource string                         `json:"deterministic_source"`
}

type ModelAnalysisPrompt struct {
	Template     ModelAnalysisPromptTemplate
	System       string
	User         string
	PromptSHA256 string
}

type modelAnalysisIncidentStep struct {
	Step       string   `json:"step"`
	Evidence   []string `json:"evidence"`
	Likelihood string   `json:"likelihood"`
	Impact     string   `json:"impact"`
	Inference  string   `json:"inference"`
}

type modelAnalysisPriorityFinding struct {
	Priority                    string `json:"priority"`
	FindingID                   string `json:"finding_id"`
	Observation                 string `json:"observation"`
	InvestigationRecommendation string `json:"investigation_recommendation"`
	RequiresHumanVerification   bool   `json:"requires_human_verification"`
}

type modelAnalysisStructuredResponse struct {
	ExecutiveSummary   string                          `json:"executive_summary"`
	OperatorComment    string                          `json:"operator_comment"`
	OperatorInsight    modelAnalysisOperatorInsight    `json:"operator_insight"`
	IncidentAssessment modelAnalysisIncidentAssessment `json:"incident_assessment"`
	IssueJudgment      modelAnalysisIssueJudgment      `json:"issue_judgment"`
	IncidentChain      []modelAnalysisIncidentStep     `json:"incident_chain"`
	PriorityFindings   []modelAnalysisPriorityFinding  `json:"priority_findings"`
	RecommendedChecks  []string                        `json:"recommended_next_checks"`
	UncertaintyAndGaps []string                        `json:"uncertainty_and_gaps"`
}

func GenerateModelAnalysisReport(ctx context.Context, gateway ports.ModelGateway, bundle EvidenceBundle, options ModelAnalysisOptions, generatedAt time.Time) (ModelAnalysisReport, error) {
	prompt, err := BuildModelAnalysisPrompt(bundle, options)
	if err != nil {
		return ModelAnalysisReport{}, err
	}

	report := baseModelAnalysisReport(bundle, options, prompt, generatedAt)
	if gateway == nil {
		report.Status = ModelAnalysisStatusFailed
		report.Error = "model gateway is not configured"
		return report, nil
	}

	health, err := gateway.Health(ctx)
	if err != nil {
		report.Status = ModelAnalysisStatusFailed
		report.Error = err.Error()
		return report, nil
	}
	report.Model.Provider = health.Provider
	report.Model.BaseURL = health.BaseURL
	report.Model.Offline = health.Offline
	if strings.TrimSpace(report.Model.Model) == "" {
		report.Model.Model = health.InvestigationModel
	}
	if health.Offline {
		report.Status = ModelAnalysisStatusOffline
		report.Error = ports.ErrModelGatewayOffline.Error()
		return report, nil
	}

	selectedModel := strings.TrimSpace(options.Model)
	response, err := gateway.Generate(ctx, ports.ModelGenerateRequest{
		Model:   selectedModel,
		System:  prompt.System,
		Prompt:  prompt.User,
		Options: modelAnalysisGenerateOptions(),
	})
	if err != nil {
		if errors.Is(err, ports.ErrModelGatewayOffline) {
			report.Status = ModelAnalysisStatusOffline
		} else {
			report.Status = ModelAnalysisStatusFailed
		}
		report.Error = err.Error()
		return report, nil
	}

	report.Status = ModelAnalysisStatusCompleted
	report.Model.Model = firstNonEmptyString(response.Model, report.Model.Model, options.Model)
	report.Analysis = formatModelAnalysisResponse(response.Text)
	report.Stats = &ModelAnalysisStats{
		TotalDurationMillis: response.TotalDuration.Milliseconds(),
		PromptEvalCount:     response.PromptEvalCount,
		EvalCount:           response.EvalCount,
	}
	return report, nil
}

func formatModelAnalysisResponse(raw string) string {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return `<div class="model-analysis-report"><section class="analysis-section"><h4>No analysis</h4><p>No analysis text returned.</p></section></div>`
	}
	parsed, ok := parseModelAnalysisStructured(normalized)
	if !ok {
		return formatModelAnalysisFreeText(normalized)
	}
	return formatModelAnalysisStructured(parsed)
}

func parseModelAnalysisStructured(raw string) (modelAnalysisStructuredResponse, bool) {
	cleaned := normalizeModelAnalysisFence(raw)
	var parsed modelAnalysisStructuredResponse
	if err := json.Unmarshal([]byte(cleaned), &parsed); err == nil {
		return parsed, true
	}

	start := strings.IndexRune(cleaned, '{')
	end := strings.LastIndex(cleaned, "}")
	if start >= 0 && end > start {
		candidate := strings.TrimSpace(cleaned[start : end+1])
		if err := json.Unmarshal([]byte(candidate), &parsed); err == nil {
			return parsed, true
		}
	}
	return modelAnalysisStructuredResponse{}, false
}

func normalizeModelAnalysisFence(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "```") {
		if strings.HasPrefix(strings.ToLower(trimmed), "```json") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "```json"))
		} else {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
		}
		if idx := strings.Index(trimmed, "```"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
	}
	return trimmed
}

func formatModelAnalysisStructured(response modelAnalysisStructuredResponse) string {
	var b strings.Builder

	b.WriteString(`<div class="model-analysis-report">`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Executive Summary</h4>`)
	summary := strings.TrimSpace(response.ExecutiveSummary)
	if summary == "" {
		summary = "Insufficient evidence to produce a concise summary."
	}
	writeParagraph(&b, summary)
	b.WriteString(`</section>`)

	if comment := strings.TrimSpace(response.OperatorComment); comment != "" {
		b.WriteString(`<section class="analysis-section analysis-operator-comment">`)
		b.WriteString(`<h4>Operator Comment</h4>`)
		writeParagraph(&b, comment)
		b.WriteString(`</section>`)
	}

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Operator Insight</h4>`)
	writeKV(&b, []modelAnalysisKV{
		{"Likely real issue", normalizedBoolean(response.OperatorInsight.LikelyRealIssue)},
		{"False positive risk", normalizedBoolean(response.OperatorInsight.FalsePositiveRisk)},
		{"Platform expected behavior", strings.TrimSpace(defaultOperatorText(response.OperatorInsight.PlatformExpectedBehavior, response.IncidentAssessment.PlatformContext))},
	})
	if response.OperatorInsight.OperatorSummary != "" {
		writeParagraph(&b, response.OperatorInsight.OperatorSummary)
	}
	if response.OperatorInsight.RecommendedOperatorAction != "" {
		writeCallout(&b, "Recommended response", response.OperatorInsight.RecommendedOperatorAction)
	}
	if len(response.OperatorInsight.SuspiciousIndicators) > 0 {
		writeListBlock(&b, "Suspicious indicators", response.OperatorInsight.SuspiciousIndicators)
	}
	if len(response.OperatorInsight.NormalOperationsChecks) > 0 {
		writeListBlock(&b, "Normal operations checks", response.OperatorInsight.NormalOperationsChecks)
	}

	// Keep an explicit fallback if the model omitted a platform behavior readout.
	if strings.TrimSpace(response.OperatorInsight.PlatformExpectedBehavior) == "" && strings.TrimSpace(response.IncidentAssessment.PlatformContext) == "" {
		writeCallout(&b, "Platform expected behavior", "Platform context not provided in model output.")
	}

	b.WriteString(`</section>`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Probable Incident Chain</h4>`)
	if len(response.IncidentChain) == 0 {
		writeParagraph(&b, "Insufficient evidence to establish a confident chain.")
	} else {
		b.WriteString(`<ol class="analysis-list">`)
		for _, item := range response.IncidentChain {
			step := strings.TrimSpace(item.Step)
			if step == "" {
				step = "Step not clearly observable."
			}
			evidence := strings.Join(quotedEvidence(item.Evidence), ", ")
			likelihood := strings.TrimSpace(item.Likelihood)
			if likelihood == "" {
				likelihood = "medium"
			}
			impact := strings.TrimSpace(item.Impact)
			if impact == "" {
				impact = "unclear"
			}
			inference := strings.TrimSpace(item.Inference)
			if inference == "" {
				inference = "observation only"
			}
			b.WriteString(`<li>`)
			b.WriteString(`<strong>`)
			b.WriteString(html.EscapeString(step))
			b.WriteString(`</strong>`)
			writeKV(&b, []modelAnalysisKV{
				{"Likelihood", likelihood},
				{"Impact", impact},
				{"Evidence", evidence},
				{"Inference", inference},
			})
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ol>`)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Priority Findings</h4>`)
	if len(response.PriorityFindings) == 0 {
		writeParagraph(&b, "No actionable priority findings identified from available evidence.")
	} else {
		b.WriteString(`<ul class="analysis-list">`)
		for _, finding := range response.PriorityFindings {
			priority := strings.TrimSpace(finding.Priority)
			if priority == "" {
				priority = "info"
			}
			findingID := strings.TrimSpace(finding.FindingID)
			if findingID == "" {
				findingID = "unknown"
			}
			observation := strings.TrimSpace(finding.Observation)
			recommendation := strings.TrimSpace(finding.InvestigationRecommendation)
			b.WriteString(`<li>`)
			b.WriteString(`<strong>`)
			b.WriteString(html.EscapeString("[" + priority + "] " + findingID))
			b.WriteString(`</strong>`)
			if observation != "" {
				writeParagraph(&b, observation)
			}
			if recommendation != "" {
				writeCallout(&b, "Recommendation", recommendation)
			}
			writeKV(&b, []modelAnalysisKV{{"Human verification required", fmt.Sprintf("%v", finding.RequiresHumanVerification)}})
			b.WriteString(`</li>`)
		}
		b.WriteString(`</ul>`)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Incident Assessment</h4>`)
	writeKV(&b, []modelAnalysisKV{
		{"Platform behavior likely", normalizedBoolean(response.IncidentAssessment.PlatformBehaviorLikely)},
		{"Platform context", strings.TrimSpace(response.IncidentAssessment.PlatformContext)},
		{"Intrusion marker", normalizedBoolean(response.IncidentAssessment.IsIntrusive)},
		{"Confidence", normalizedConfidence(response.IncidentAssessment.Confidence)},
	})
	if strings.TrimSpace(response.IncidentAssessment.Rationale) != "" {
		writeParagraph(&b, response.IncidentAssessment.Rationale)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Issue Judgment</h4>`)
	priority := strings.TrimSpace(response.IssueJudgment.RecommendedPriority)
	if strings.TrimSpace(response.IssueJudgment.RecommendedPriority) == "" {
		priority = "medium"
	}
	writeKV(&b, []modelAnalysisKV{
		{"Likely true issue", normalizedBoolean(response.IssueJudgment.IsLikelyTrueIssue)},
		{"False positive risk", normalizedBoolean(response.IssueJudgment.FalsePositiveRisk)},
		{"Recommended priority", priority},
	})
	if strings.TrimSpace(response.IssueJudgment.RecommendedResponse) != "" {
		writeCallout(&b, "Recommended response", response.IssueJudgment.RecommendedResponse)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Recommended Next Checks</h4>`)
	if len(response.RecommendedChecks) == 0 {
		writeParagraph(&b, "No specific checks were identified.")
	} else {
		writeList(&b, response.RecommendedChecks)
	}
	b.WriteString(`</section>`)

	b.WriteString(`<section class="analysis-section">`)
	b.WriteString(`<h4>Uncertainty And Gaps</h4>`)
	if len(response.UncertaintyAndGaps) == 0 {
		writeParagraph(&b, "No major gaps identified.")
	} else {
		writeList(&b, response.UncertaintyAndGaps)
	}
	b.WriteString(`</section>`)
	b.WriteString(`</div>`)
	return strings.TrimSpace(b.String())
}

type modelAnalysisKV struct {
	Key   string
	Value string
}

func formatModelAnalysisFreeText(value string) string {
	var b strings.Builder
	b.WriteString(`<div class="model-analysis-report"><section class="analysis-section"><h4>Analysis</h4>`)
	for _, paragraph := range strings.Split(value, "\n") {
		if strings.TrimSpace(paragraph) != "" {
			writeParagraph(&b, paragraph)
		}
	}
	b.WriteString(`</section></div>`)
	return b.String()
}

func writeParagraph(b *strings.Builder, value string) {
	text := strings.TrimSpace(value)
	if text == "" {
		return
	}
	b.WriteString(`<p>`)
	b.WriteString(html.EscapeString(text))
	b.WriteString(`</p>`)
}

func writeCallout(b *strings.Builder, label string, value string) {
	text := strings.TrimSpace(value)
	if text == "" {
		return
	}
	b.WriteString(`<p class="analysis-callout"><strong>`)
	b.WriteString(html.EscapeString(label))
	b.WriteString(`:</strong> `)
	b.WriteString(html.EscapeString(text))
	b.WriteString(`</p>`)
}

func writeKV(b *strings.Builder, values []modelAnalysisKV) {
	wrote := false
	for _, value := range values {
		if strings.TrimSpace(value.Key) == "" || strings.TrimSpace(value.Value) == "" {
			continue
		}
		if !wrote {
			b.WriteString(`<dl class="analysis-kv">`)
			wrote = true
		}
		b.WriteString(`<dt>`)
		b.WriteString(html.EscapeString(value.Key))
		b.WriteString(`</dt><dd>`)
		b.WriteString(html.EscapeString(value.Value))
		b.WriteString(`</dd>`)
	}
	if wrote {
		b.WriteString(`</dl>`)
	}
}

func writeListBlock(b *strings.Builder, label string, values []string) {
	b.WriteString(`<div class="analysis-subsection"><strong>`)
	b.WriteString(html.EscapeString(label))
	b.WriteString(`</strong>`)
	writeList(b, values)
	b.WriteString(`</div>`)
}

func writeList(b *strings.Builder, values []string) {
	items := make([]string, 0, len(values))
	for _, value := range values {
		if item := strings.TrimSpace(value); item != "" {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return
	}
	b.WriteString(`<ul class="analysis-list">`)
	for _, item := range items {
		b.WriteString(`<li>`)
		b.WriteString(html.EscapeString(item))
		b.WriteString(`</li>`)
	}
	b.WriteString(`</ul>`)
}

func quotedEvidence(values []string) []string {
	if len(values) == 0 {
		return []string{"none"}
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item != "" {
			out = append(out, fmt.Sprintf("`%s`", item))
		}
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

func BuildModelAnalysisPrompt(bundle EvidenceBundle, options ModelAnalysisOptions) (ModelAnalysisPrompt, error) {
	content, err := json.Marshal(bundle)
	if err != nil {
		return ModelAnalysisPrompt{}, err
	}
	issueType := inferModelAnalysisIssueType(options.FindingRuleID)
	userPrompt := modelAnalysisUserPromptTemplate
	userPrompt = strings.ReplaceAll(userPrompt, "{{PLATFORM_CONTEXT}}", modelAnalysisPlatformContextText(options.AppKind, options.FindingRuleID))
	userPrompt = strings.ReplaceAll(userPrompt, "{{ISSUE_PROFILE}}", modelAnalysisIssuePromptProfile(issueType, options.AppKind, options.FindingRuleID))
	userPrompt = strings.ReplaceAll(userPrompt, "{{ISSUE_CONTEXT}}", modelAnalysisIssueContextText(bundle, options))
	userPrompt = strings.ReplaceAll(userPrompt, "{{EVIDENCE_BUNDLE_JSON}}", string(content))
	return ModelAnalysisPrompt{
		Template:     CurrentModelAnalysisPromptTemplate(),
		System:       modelAnalysisSystemPrompt,
		User:         userPrompt,
		PromptSHA256: sha256Hex(modelAnalysisSystemPrompt + "\n" + userPrompt),
	}, nil
}

func CurrentModelAnalysisPromptTemplate() ModelAnalysisPromptTemplate {
	return ModelAnalysisPromptTemplate{
		ID:      ModelAnalysisPromptTemplateID,
		Version: ModelAnalysisPromptTemplateVersion,
		SHA256:  sha256Hex(modelAnalysisSystemPrompt + "\n" + modelAnalysisUserPromptTemplate),
	}
}

func WriteModelAnalysisReportJSON(w io.Writer, report ModelAnalysisReport, pretty bool) error {
	encoder := json.NewEncoder(w)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}

func DomainModelAnalysisReport(report ModelAnalysisReport) domain.ModelAnalysisReport {
	record := domain.ModelAnalysisReport{
		ID:                             domain.ID(report.ID),
		ReportSchema:                   report.Schema,
		Status:                         report.Status,
		ModelProvider:                  report.Model.Provider,
		ModelName:                      report.Model.Model,
		PromptTemplateID:               report.PromptTemplate.ID,
		PromptTemplateVersion:          report.PromptTemplate.Version,
		PromptTemplateSHA256:           report.PromptTemplate.SHA256,
		PromptSHA256:                   report.PromptSHA256,
		EvidenceBundleSchema:           report.EvidenceBundle.Schema,
		EvidenceBundleSHA256:           report.EvidenceBundle.SHA256,
		EvidenceBundleRedactionVersion: report.EvidenceBundle.RedactionVersion,
		EvidenceBundleGeneratedAt:      report.EvidenceBundle.GeneratedAt,
		SourceFindingIDs:               domainFindingIDs(report.SourceFindingIDs),
		Analysis:                       report.Analysis,
		Error:                          report.Error,
		GeneratedAt:                    report.GeneratedAt,
		Metadata: map[string]any{
			"tool":                 report.Tool,
			"scope":                report.Scope,
			"notice":               report.Notice,
			"finding_count":        report.FindingCount,
			"model_base_url":       report.Model.BaseURL,
			"model_offline":        report.Model.Offline,
			"deterministic_source": report.DeterministicSource,
		},
	}
	if report.CreatedAt != nil {
		record.CreatedAt = report.CreatedAt.UTC()
	}
	if report.Stats != nil {
		record.TotalDurationMillis = report.Stats.TotalDurationMillis
		record.PromptEvalCount = report.Stats.PromptEvalCount
		record.EvalCount = report.Stats.EvalCount
	}
	return record
}

func ApplySavedModelAnalysisReport(report ModelAnalysisReport, saved domain.ModelAnalysisReport) ModelAnalysisReport {
	report.ID = string(saved.ID)
	createdAt := saved.CreatedAt.UTC()
	report.CreatedAt = &createdAt
	report.GeneratedAt = saved.GeneratedAt.UTC()
	return report
}

func baseModelAnalysisReport(bundle EvidenceBundle, options ModelAnalysisOptions, prompt ModelAnalysisPrompt, generatedAt time.Time) ModelAnalysisReport {
	return ModelAnalysisReport{
		Schema:           ModelAnalysisReportSchema,
		GeneratedAt:      generatedAt.UTC(),
		Tool:             bundle.Tool,
		Scope:            bundle.Scope,
		Status:           ModelAnalysisStatusFailed,
		Notice:           modelAnalysisNotice,
		FindingCount:     bundle.FindingCount,
		SourceFindingIDs: modelAnalysisFindingIDs(bundle.Findings),
		EvidenceBundle: ModelAnalysisEvidenceBundleRef{
			Schema:           bundle.Schema,
			SHA256:           bundle.BundleSHA256,
			RedactionVersion: bundle.Redaction.Version,
			GeneratedAt:      bundle.GeneratedAt.UTC(),
		},
		PromptTemplate: prompt.Template,
		PromptSHA256:   prompt.PromptSHA256,
		Model: ModelAnalysisModelInfo{
			Model: strings.TrimSpace(options.Model),
		},
		DeterministicSource: "Aegrail persisted Hub findings and redacted evidence bundle",
	}
}

func modelAnalysisGenerateOptions() map[string]any {
	return map[string]any{
		"temperature": 0,
	}
}

func modelAnalysisFindingIDs(findings []EvidenceBundleFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		if strings.TrimSpace(finding.ID) != "" {
			ids = append(ids, finding.ID)
		}
	}
	return ids
}

func domainFindingIDs(values []string) []domain.ID {
	ids := make([]domain.ID, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			ids = append(ids, domain.ID(value))
		}
	}
	return ids
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizedBoolean(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "true", "false":
		return value
	default:
		return "unknown"
	}
}

func normalizedConfidence(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "high", "medium", "low":
		return value
	default:
		return "unknown"
	}
}

func modelAnalysisPlatformContextText(appKind string, issueRuleID string) string {
	platform := strings.TrimSpace(strings.ToLower(appKind))
	if platform == "" {
		platform = "generic"
	}
	switch platform {
	case "wordpress":
		return "Application platform: WordPress. Prioritize normal admin actions, plugin/theme updates, media uploads, cron, and scheduled maintenance before flagging intrusion. Be careful with new admins, role/capability changes, script content in posts/options, and suspicious PHP uploads in writable paths."
	case "wordpress-network":
		return "Application platform: WordPress Network (multisite). Treat network-configuration, network admin users, cross-site plugin/theme activation, and multisite option changes as higher impact. Confirm whether the action was expected at network-admin level or isolated to one child site."
	case "prestashop":
		return "Application platform: PrestaShop. Expected behavior includes module uploads/updates, hook/tab changes, theme module assets, and back office admin operations. Distinguish module cache/log artifacts and vendor index.php redirect guards from newly introduced executable payloads, payment/mail/security configuration drift, or employee privilege changes."
	case "mautic":
		return "Application platform: Mautic. Expected behavior includes campaign/email tracking requests, redirects, plugin updates, integration setup, cache rebuilds, and marketer/admin changes. Treat admin role changes, OAuth clients, webhook secrets, published integrations with API keys, executable files in media, and unexpected plugin changes as higher-impact signals."
	case "yii2-rbac":
		return "Application platform: Yii2 RBAC. Expected behavior includes deploys touching config, controllers, models, migrations, views, Yii entrypoints, and web assets. Treat user/role/RBAC changes, config/db.php or production config edits, unexpected PHP entrypoints, and executable files in writable web/runtime areas as higher-impact signals."
	case "laravel":
		return "Application platform: Laravel. Expected behavior includes deploys touching app, routes, config, database migrations/seeders, resources, composer files, npm/vite assets, and public/index.php. Treat user, role, Spatie permission, .env, auth/database/service config, Horizon/Telescope exposure, and unexpected executable public/storage files as higher-impact signals."
	default:
		if strings.Contains(platform, "presta") {
			return "Application platform: PrestaShop-like. Distinguish normal module/theme cache, module package files, and directory guard files from suspicious write activity or sensitive configuration drift."
		}
		if strings.Contains(platform, "mautic") {
			return "Application platform: Mautic-like. Filter routine email redirect and tracking traffic, but scrutinize admin/API/auth paths, integration credentials, OAuth clients, webhooks, and executable code in writable media."
		}
		if strings.Contains(platform, "yii") {
			return "Application platform: Yii2-like. Focus on config, routes/controllers, migrations, RBAC/user tables, web entrypoints, and executable code outside expected source directories."
		}
		if strings.Contains(platform, "laravel") {
			return "Application platform: Laravel-like. Focus on app code, routes, middleware, migrations, Spatie roles/permissions, .env/config changes, public entrypoints, queues, Horizon, and Telescope."
		}
		if issueRuleID != "" {
			return "Application platform: detected from context/metadata. No explicit platform profile was provided; apply conservative, evidence-first judgments."
		}
		return "Application platform: unknown. Apply conservative baseline, treat ambiguous patterns as potentially suspicious until verified."
	}
}

func modelAnalysisIssuePromptProfile(issueType string, appKind string, ruleID string) string {
	platform := strings.TrimSpace(strings.ToLower(appKind))
	rule := strings.TrimSpace(strings.ToLower(ruleID))
	switch issueType {
	case "incident_chain":
		return `Incident-chain perspective:
- Explain the chain in plain operational language: entry signal, follow-up change, and possible impact.
- Separate observed sequence from inferred causality; do not claim compromise solely from timing.
- Increase confidence only when web access, file change, database/config change, or identity evidence line up in the same window.
- Recommend a tight review window and concrete rollback/containment checks without destructive commands.`
	case "identity_and_access":
		return `Identity/access perspective:
- Prioritize whether this matches known admin actions and expected role changes.
- Flag unknown actor onboarding, privilege escalation, employee/superadmin changes, network-admin changes, or non-standard auth/session activity.
- Mention user/email/account identifiers exactly as supplied in the redacted evidence; do not invent actor names.
- Prefer confidence upgrades only when file/db/browser signals align with the identity change.
- Include scheduled admin work, staff onboarding, and expected role maintenance as benign explanations when evidence supports them.`
	case "platform_extension_change":
		return platformExtensionPromptProfile(platform, rule)
	case "scheduled_task_change":
		return `Scheduled-task perspective:
- WordPress cron and platform scheduled tasks change during plugin/theme updates, cache rebuilds, mail jobs, and maintenance.
- Treat newly added tasks as suspicious when the hook/function name, callback, or cadence is unusual, hidden, obfuscated, or unrelated to installed plugins/modules.
- Recommend checking the owning plugin/module, deployment window, next run time, and whether the task modifies users, files, payments, or external scripts.
- Avoid calling it intrusion unless the task behavior or surrounding evidence supports that conclusion.`
	case "file_system_change":
		return `File/system perspective:
- Verify if changes align with deploy pipeline, trusted developer accounts, and writable-path expectations.
- Treat unexpected PHP, phar, shell payloads, or changed executables in web roots as high-risk.
- Distinguish cache/log/archive artifacts from active module/theme/code changes; if many files changed under one plugin/theme/module, describe it as one deploy/update candidate rather than many unrelated issues.
- For PrestaShop, tiny index.php files inside module/theme asset directories may be directory guard or redirect files, especially when they only send cache headers and redirect to parent; still verify whether the file is vendor-known and recently changed.
- For Mautic, media assets and tracking artifacts are usually noisy; executable PHP/PHAR/PHTML in media or unexpected plugin code changes deserve higher scrutiny.
- Report if file owner or path ownership appears inconsistent with expected deployment users.`
	case "database_activity":
		return `Database perspective:
- Distinguish maintenance scripts/migrations from direct privilege or auth table writes.
- Counts alone are a weak signal; entity-level diffs with account, role, option, module, hook, payment, mail, or security fields are stronger.
- For Mautic, prioritize user/role, plugin, integration, OAuth client, and webhook entity diffs over routine tracking-log volume.
- Flag schema/value changes that touch credential-like tables, privilege grants, payment/mail/security settings, or script content outside deployments.
- Check for bursty writes with unusual actor/user mismatch before escalating.
- Treat expected backup/sync tasks as the first benign hypothesis if logs are available.`
	case "configuration_change":
		return `Configuration perspective:
- Focus on trust-boundary changes (security tokens, email settings, plugin/network allowlists, payment and integration secrets).
- Separate bootstrap/config cache changes from policy-affecting edits.
- If change touched environment files, config stores, auth directives, payment routing, mail transport, or browser/script allowlists, raise triage urgency.
- Missing or disabled collectors are monitoring gaps, not proof of site compromise; recommend either fixing config or documenting an intentional disablement.`
	case "browser_activity":
		return `Browser instrumentation perspective:
- Separate legitimate A/B/deploy scripts from external injections or unexpected third-party script hosts.
- Look for first-party deployment origin, file modification pattern, and CSP/headers consistency.
- Emphasize whether inserted script modifies auth, payment, checkout, account, or privilege flows.
- If the only evidence is a new domain/hash/tag-manager ID, recommend allowlisting only after ownership and expected deployment are confirmed.`
	case "web_access_activity":
		return `Web/access-log perspective:
- Access logs show request behavior, not by themselves successful compromise.
- For admin probes, login POST bursts, success-after-failures, Tor-marked traffic, or request/error spikes, explain whether the pattern looks like scanning, brute force, app instability, or a real admin session risk.
- Use remote fingerprints and path families from evidence; do not ask for raw IPs if Aegrail only supplied hashes.
- Recommend checking the same timeframe for successful admin sessions, file writes, database role/config changes, PHP errors, WAF/CDN logs, and planned load tests.`
	case "platform_configuration_change":
		return platformConfigurationPromptProfile(platform, rule)
	default:
		return `General perspective:
- Treat this as a cross-signal investigation with preference for cross-validator consistency.
- Confirm whether observed behavior is explained by planned admin work or release activity before escalation.
- Prioritize evidence linking identity, file change, and timeline before declaring high confidence.`
	}
}

func modelAnalysisIssueContextText(bundle EvidenceBundle, options ModelAnalysisOptions) string {
	var lines []string
	issueType := inferModelAnalysisIssueType(options.FindingRuleID)
	lines = append(lines, "Issue type: "+issueType)
	if strings.TrimSpace(options.FindingID) != "" {
		lines = append(lines, "Finding ID: "+strings.TrimSpace(options.FindingID))
	}
	if strings.TrimSpace(options.FindingRuleID) != "" {
		lines = append(lines, "Rule ID: "+strings.TrimSpace(options.FindingRuleID))
	}
	if strings.TrimSpace(options.FindingSeverity) != "" {
		lines = append(lines, "Severity: "+strings.TrimSpace(options.FindingSeverity))
	}
	if strings.TrimSpace(options.FindingConfidence) != "" {
		lines = append(lines, "Confidence: "+strings.TrimSpace(options.FindingConfidence))
	}
	if strings.TrimSpace(options.FindingTitle) != "" {
		lines = append(lines, "Finding title: "+strings.TrimSpace(options.FindingTitle))
	}
	if strings.TrimSpace(options.FindingSummary) != "" {
		lines = append(lines, "Finding summary: "+strings.TrimSpace(options.FindingSummary))
	}
	evidenceTypes := modelAnalysisEvidenceTypes(bundle)
	if len(evidenceTypes) > 0 {
		lines = append(lines, "Evidence types: "+strings.Join(evidenceTypes, ", "))
	}
	lines = append(lines, "Issue guidance: "+modelAnalysisIssueGuidance(issueType))
	return "- " + strings.Join(lines, "\n- ")
}

func defaultOperatorText(preferred string, fallback string) string {
	if strings.TrimSpace(preferred) != "" {
		return preferred
	}
	return fallback
}

func inferModelAnalysisIssueType(ruleID string) string {
	r := strings.ToLower(strings.TrimSpace(ruleID))
	switch {
	case r == "":
		return "generic"
	case r == "probable-incident-chain" || strings.Contains(r, "-to-") || strings.Contains(r, "incident-chain"):
		return "incident_chain"
	case strings.HasPrefix(r, "web-") || strings.Contains(r, "request") || strings.Contains(r, "access-log"):
		return "web_access_activity"
	case strings.HasPrefix(r, "browser-"):
		return "browser_activity"
	case strings.HasPrefix(r, "file-") || strings.Contains(r, "upload") || strings.Contains(r, "php-in-writable"):
		return "file_system_change"
	case strings.Contains(r, "coverage") || strings.Contains(r, "collector") || strings.Contains(r, "missing"):
		return "configuration_change"
	case containsAny(r, "superadmin", "employee", "admin-user", "admin-users", "user-became", "capabilities", "roles", "network-admins", "login", "auth", "access-rules", "users-changed"):
		return "identity_and_access"
	case containsAny(r, "script-content", "javascript"):
		return "browser_activity"
	case containsAny(r, "cron-task", "cron-option", "cron"):
		return "scheduled_task_change"
	case containsAny(r, "active-plugin", "active-theme", "plugin", "theme", "module", "hook", "tabs", "-tab"):
		return "platform_extension_change"
	case containsAny(r, "configuration", "config", "option", "setting", "payment", "mail", "security", "sensitive", "integration", "webhook", "credentials"):
		return "platform_configuration_change"
	case strings.Contains(r, "db") || strings.Contains(r, "table") || strings.Contains(r, "database") || strings.Contains(r, "query"):
		return "database_activity"
	default:
		return "generic_security_signal"
	}
}

func modelAnalysisIssueGuidance(issueType string) string {
	switch issueType {
	case "incident_chain":
		return "Explain the timeline as observed facts plus uncertainty; require cross-signal validation before recommending incident response escalation."
	case "identity_and_access":
		return "Pay attention to whether account, role, capability, or employee privilege changes are expected from known admins and whether there are matching admin-session or deployment records."
	case "platform_extension_change":
		return "Determine whether plugin/theme/module/hook/tab changes are part of a planned release; group related file changes under the same extension instead of treating every file as a separate incident."
	case "scheduled_task_change":
		return "Check whether the scheduled task belongs to a known plugin/module and whether its callback/cadence is expected or persistence-like."
	case "file_system_change":
		return "Check if file changes match release tooling, trusted maintainers, and allowed directories; treat unexpected executable content as higher risk, while recognizing vendor guard files and grouped extension updates."
	case "database_activity":
		return "Look for maintenance windows, migration jobs, and schema sync tasks before assuming data tampering; prioritize entity diffs that affect identity, payment, mail, security, scripts, or privileges."
	case "configuration_change":
		return "Distinguish expected platform bootstrap/collector config updates from sensitive credential or trust-boundary changes; missing deployment reference increases risk."
	case "browser_activity":
		return "Separate expected script changes from externally injected scripts; validate origin domains, tag-manager ownership, checkout/auth impact, and user intent."
	case "web_access_activity":
		return "Treat access-log patterns as request evidence; verify whether they led to successful admin sessions, file writes, database changes, or server-side PHP errors before declaring compromise."
	case "platform_configuration_change":
		return "Review whether option/configuration drift affects payment, mail, security, browser scripts, or platform trust boundaries and whether it occurred during an approved deployment."
	default:
		return "Treat as cross-cutting signal: determine whether this matches scheduled admin work, deployment automation, or unusual actor behavior."
	}
}

func modelAnalysisEvidenceTypes(bundle EvidenceBundle) []string {
	if len(bundle.Findings) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var types []string
	for _, finding := range bundle.Findings {
		for _, key := range []string{"category", "categories", "platforms", "evidence_types", "action_hints"} {
			values := modelAnalysisMetadataValues(finding.Rule[key])
			for _, value := range values {
				item := key + "=" + value
				if _, ok := seen[item]; ok {
					continue
				}
				seen[item] = struct{}{}
				types = append(types, item)
			}
		}
	}
	sort.Strings(types)
	return types
}

func platformExtensionPromptProfile(platform string, rule string) string {
	base := `Platform extension perspective:
- Plugins, themes, modules, hooks, tabs, and add-ons often change during normal deployments.
- Group related changes under one extension/update when paths or database rows point to the same plugin/theme/module.
- Treat unexpected activation, hidden modules, unknown package origin, code changes after admin probes, or checkout/auth-related extension changes as higher risk.
- Recommend verifying the release/deployment record, package source, version change, and whether file/database/browser signals align.`
	if strings.Contains(platform, "presta") || strings.Contains(rule, "prestashop") {
		return base + `
- For PrestaShop, module installs commonly touch ps_module, hooks, tabs, translations, caches, and theme module assets; payment, shipping, checkout, and back office modules deserve extra scrutiny.`
	}
	if strings.Contains(platform, "mautic") || strings.Contains(rule, "mautic") {
		return base + `
- For Mautic, plugin changes commonly touch integrations, campaigns, builders, and email features; scrutinize unknown bundles, downgraded plugins, and changes near admin/API/auth activity.`
	}
	if strings.Contains(platform, "yii") || strings.Contains(rule, "yii2-rbac") {
		return base + `
- For Yii2 RBAC, deployment-like code changes usually touch controllers, models, components, migrations, views, composer files, and web entrypoints; scrutinize unexpected writable web/runtime PHP, unknown entrypoints, and code changes near login/admin traffic.`
	}
	if strings.Contains(platform, "laravel") || strings.Contains(rule, "laravel") {
		return base + `
- For Laravel, deployment-like code changes usually touch app, routes, config, database/migrations, database/seeders, resources, composer/npm lockfiles, Vite config, and public/index.php; scrutinize executable files under public/storage, public/vendor, storage, or cache paths.`
	}
	if strings.Contains(platform, "wordpress") || strings.Contains(rule, "wordpress") {
		return base + `
- For WordPress, plugin/theme activation usually appears in options plus file changes; network-wide activation on multisite is higher impact than one child site.`
	}
	return base
}

func platformConfigurationPromptProfile(platform string, rule string) string {
	base := `Platform configuration perspective:
- Configuration/option changes are normal during deploys, plugin/module setup, cache rebuilds, and admin maintenance.
- Prioritize trust-boundary settings: auth, registration, roles, payment, mail, checkout, script injection, API integrations, and security controls.
- Recommend verifying who changed it, whether there is a deployment marker, and whether the old/new values imply a security or business-routing change.
- If values are redacted, reason from field names, table/option names, risk factors, and surrounding timeline rather than inventing the hidden value.`
	if strings.Contains(platform, "presta") || strings.Contains(rule, "prestashop") {
		return base + `
- For PrestaShop, payment, mail, security, employee profile, access, hook, and module configuration changes can affect checkout integrity and back office control.`
	}
	if strings.Contains(platform, "mautic") || strings.Contains(rule, "mautic") {
		return base + `
- For Mautic, integration API keys, OAuth clients, webhook secrets, admin roles, mail/transport settings, and public tracking endpoints affect campaign delivery and account control.`
	}
	if strings.Contains(platform, "yii") || strings.Contains(rule, "yii2-rbac") {
		return base + `
- For Yii2 RBAC, config/db.php, production web/console config, RBAC/user role tables, auth keys, password reset tokens, and migration changes affect application control and access.`
	}
	if strings.Contains(platform, "laravel") || strings.Contains(rule, "laravel") {
		return base + `
- For Laravel, .env, config/database.php, config/auth.php, config/services.php, config/permission.php, Spatie role/permission tables, password reset tokens, sessions, queue/failed job tables, Horizon, and Telescope are security-relevant.`
	}
	if strings.Contains(platform, "wordpress") || strings.Contains(rule, "wordpress") {
		return base + `
- For WordPress, registration, roles/capabilities, network admin, active plugins/themes, cron, and content/script options deserve higher scrutiny.`
	}
	return base
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func modelAnalysisMetadataValues(value any) []string {
	switch typed := value.(type) {
	case string:
		item := strings.TrimSpace(typed)
		if item == "" {
			return nil
		}
		return []string{item}
	case []string:
		items := make([]string, 0, len(typed))
		for _, value := range typed {
			if item := strings.TrimSpace(value); item != "" {
				items = append(items, item)
			}
		}
		return items
	case []any:
		items := make([]string, 0, len(typed))
		for _, value := range typed {
			if text, ok := value.(string); ok {
				if item := strings.TrimSpace(text); item != "" {
					items = append(items, item)
				}
			}
		}
		return items
	default:
		return nil
	}
}
