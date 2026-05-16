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
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/ports"
)

const (
	ModelAnalysisReportSchema          = "aegrail.model_analysis_report.v1"
	ModelAnalysisPromptTemplateID      = "aegrail.incident_analysis"
	ModelAnalysisPromptTemplateVersion = "2026-05-15.2"
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
- For common WordPress, WordPress multisite, and PrestaShop behavior, explicitly say what could be normal and what would make it suspicious.
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
	userPrompt = strings.ReplaceAll(userPrompt, "{{ISSUE_PROFILE}}", modelAnalysisIssuePromptProfile(issueType))
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
		return "Application platform: WordPress. Prioritize normal admin actions, plugin/theme updates, media uploads, and scheduled maintenance before flagging intrusion. Be careful with user role changes and suspicious PHP uploads in writable paths."
	case "wordpress-network":
		return "Application platform: WordPress Network (multisite). Treat network-configuration and multisite admin actions as potentially higher impact. Confirm whether action was on network admin and expected delegation model."
	case "prestashop":
		return "Application platform: PrestaShop. Expected behavior includes module uploads/updates, hook changes, and back office admin operations. Distinguish module cache artifacts from executable payloads."
	default:
		if strings.Contains(platform, "presta") {
			return "Application platform: PrestaShop-like. Distinguish normal module/theme cache and package artifacts from suspicious write activity."
		}
		if issueRuleID != "" {
			return "Application platform: detected from context/metadata. No explicit platform profile was provided; apply conservative, evidence-first judgments."
		}
		return "Application platform: unknown. Apply conservative baseline, treat ambiguous patterns as potentially suspicious until verified."
	}
}

func modelAnalysisIssuePromptProfile(issueType string) string {
	switch issueType {
	case "identity_and_access":
		return `Identity/access perspective:
- Prioritize whether this matches known admin actions and expected role changes.
- Flag unknown actor onboarding, privilege escalation, or non-standard auth/session activity.
- Prefer confidence upgrades only when file/db/browser signals align with the identity change.
- Include "scheduled admin work" as a likely benign explanation when maintenance markers exist.`
	case "file_system_change":
		return `File/system perspective:
- Verify if changes align with deploy pipeline, trusted developer accounts, and writable-path expectations.
- Treat unexpected PHP, phar, shell payloads, or changed executables in web roots as high-risk.
- Distinguish cache/log/archive artifacts from active module/theme/code changes.
- Report if file owner or path ownership appears inconsistent with expected deployment users.`
	case "database_activity":
		return `Database perspective:
- Distinguish maintenance scripts/migrations from direct privilege or auth table writes.
- Flag schema/value changes that touch credential-like tables or privilege grants outside deployments.
- Check for bursty writes with unusual actor/user mismatch before escalating.
- Treat expected backup/sync tasks as the first benign hypothesis if logs are available.`
	case "configuration_change":
		return `Configuration perspective:
- Focus on trust-boundary changes (security tokens, email settings, plugin/network allowlists, payment and integration secrets).
- Separate bootstrap/config cache changes from policy-affecting edits.
- If change touched environment files, config stores, or auth directives, raise triage urgency.`
	case "browser_activity":
		return `Browser instrumentation perspective:
- Separate legitimate A/B/deploy scripts from external injections or unexpected third-party script hosts.
- Look for first-party deployment origin, file modification pattern, and CSP/headers consistency.
- Emphasize whether inserted script modifies auth, payment, account, or privilege flows.`
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
	case strings.Contains(r, "user") || strings.Contains(r, "login") || strings.Contains(r, "auth") || strings.Contains(r, "admin"):
		return "identity_and_access"
	case strings.Contains(r, "file") || strings.Contains(r, "upload") || strings.Contains(r, "module") || strings.Contains(r, "plugin") || strings.Contains(r, "theme") || strings.Contains(r, "php"):
		return "file_system_change"
	case strings.Contains(r, "db") || strings.Contains(r, "table") || strings.Contains(r, "database") || strings.Contains(r, "query"):
		return "database_activity"
	case strings.Contains(r, "config") || strings.Contains(r, "setting"):
		return "configuration_change"
	case strings.Contains(r, "browser") || strings.Contains(r, "script") || strings.Contains(r, "javascript"):
		return "browser_activity"
	default:
		return "generic_security_signal"
	}
}

func modelAnalysisIssueGuidance(issueType string) string {
	switch issueType {
	case "identity_and_access":
		return "Pay attention to whether the actor and role change is expected from known admins, and whether the account was recently created/modified during an approved deployment window."
	case "file_system_change":
		return "Check if file/module/theme changes match release tooling, trusted maintainers, and allowed directories; treat unexpected executable content as higher risk."
	case "database_activity":
		return "Look for maintenance windows, migration jobs, and schema sync tasks before assuming data tampering; prioritize high-volume or privilege-elevating queries."
	case "configuration_change":
		return "Distinguish expected platform bootstrap config updates from sensitive credential or trust-boundary changes; missing deployment reference increases risk."
	case "browser_activity":
		return "Separate expected script changes from externally injected scripts; validate origin domains and user intent."
	default:
		return "Treat as cross-cutting signal: determine whether this matches scheduled admin work, deployment automation, or unusual actor behavior."
	}
}

func modelAnalysisEvidenceTypes(bundle EvidenceBundle) []string {
	if len(bundle.Findings) == 0 {
		return nil
	}
	types := make([]string, 0, len(bundle.Findings[0].Rule))
	for key := range bundle.Findings[0].Rule {
		switch strings.ToLower(key) {
		case "platforms", "categories", "evidence_types", "action_hints":
			types = append(types, key)
		}
	}
	return types
}
