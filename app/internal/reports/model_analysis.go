package reports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/ports"
)

const (
	ModelAnalysisReportSchema          = "aegrail.model_analysis_report.v1"
	ModelAnalysisPromptTemplateID      = "aegrail.incident_analysis"
	ModelAnalysisPromptTemplateVersion = "2026-05-13.1"
	ModelAnalysisStatusCompleted       = "completed"
	ModelAnalysisStatusOffline         = "offline"
	ModelAnalysisStatusFailed          = "failed"
)

const modelAnalysisNotice = "Model output is advisory analysis. Deterministic Aegrail findings remain the source of truth."

const modelAnalysisSystemPrompt = `You are Aegrail's local model-assisted incident analysis component.
Use only the supplied redacted evidence bundle.
Do not invent evidence, identities, IP addresses, files, database rows, or causal links.
Separate confirmed evidence from inference.
Keep recommendations defensive and investigation-focused.`

const modelAnalysisUserPromptTemplate = `Analyze this redacted Aegrail evidence bundle.

Return concise Markdown with exactly these headings:

## Executive Summary
## Probable Incident Chain
## Priority Findings
## Recommended Next Checks
## Uncertainty And Gaps

Rules:
- Reference finding IDs when discussing evidence.
- Treat deterministic finding severity, confidence, risk score, and event references as source-of-truth facts.
- Label inference clearly.
- If evidence is insufficient for a chain, say so.
- Do not include exploit instructions or destructive remediation.

Evidence bundle JSON:
{{EVIDENCE_BUNDLE_JSON}}
`

type ModelAnalysisOptions struct {
	Model string
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
	Schema              string                         `json:"schema"`
	GeneratedAt         time.Time                      `json:"generated_at"`
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

func GenerateModelAnalysisReport(ctx context.Context, gateway ports.ModelGateway, bundle EvidenceBundle, options ModelAnalysisOptions, generatedAt time.Time) (ModelAnalysisReport, error) {
	prompt, err := BuildModelAnalysisPrompt(bundle)
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

	response, err := gateway.Generate(ctx, ports.ModelGenerateRequest{
		Model:   options.Model,
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
	report.Analysis = strings.TrimSpace(response.Text)
	report.Stats = &ModelAnalysisStats{
		TotalDurationMillis: response.TotalDuration.Milliseconds(),
		PromptEvalCount:     response.PromptEvalCount,
		EvalCount:           response.EvalCount,
	}
	return report, nil
}

func BuildModelAnalysisPrompt(bundle EvidenceBundle) (ModelAnalysisPrompt, error) {
	content, err := json.Marshal(bundle)
	if err != nil {
		return ModelAnalysisPrompt{}, err
	}
	userPrompt := strings.ReplaceAll(modelAnalysisUserPromptTemplate, "{{EVIDENCE_BUNDLE_JSON}}", string(content))
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
