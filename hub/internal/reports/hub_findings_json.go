package reports

import (
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type ToolInfo struct {
	Name      string `json:"name"`
	Binary    string `json:"binary"`
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
}

type HubFindingsScope struct {
	Organization string `json:"organization"`
	Project      string `json:"project"`
	Environment  string `json:"environment"`
	App          string `json:"app,omitempty"`
}

type HubFindingsJSONReport struct {
	GeneratedAt  time.Time              `json:"generated_at"`
	Tool         ToolInfo               `json:"tool"`
	Scope        HubFindingsScope       `json:"scope"`
	FindingCount int                    `json:"finding_count"`
	Findings     []HubFindingJSONRecord `json:"findings"`
}

type HubFindingJSONRecord struct {
	ID              string         `json:"id"`
	RuleID          string         `json:"rule_id"`
	RuleVersion     string         `json:"rule_version"`
	DedupeKey       string         `json:"dedupe_key"`
	Severity        string         `json:"severity"`
	Confidence      string         `json:"confidence"`
	RiskScore       int            `json:"risk_score,omitempty"`
	RiskBand        string         `json:"risk_band,omitempty"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	Description     string         `json:"description"`
	OperatorAction  map[string]any `json:"operator_action,omitempty"`
	EventIDs        []string       `json:"event_ids"`
	FirstEventAt    time.Time      `json:"first_event_at"`
	LastEventAt     time.Time      `json:"last_event_at"`
	Status          string         `json:"status"`
	StatusReason    string         `json:"status_reason,omitempty"`
	StatusNote      string         `json:"status_note,omitempty"`
	StatusActor     string         `json:"status_actor,omitempty"`
	StatusUpdatedAt time.Time      `json:"status_updated_at"`
	Metadata        map[string]any `json:"metadata"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func BuildHubFindingsJSONReport(meta domain.AppMeta, scope HubFindingsScope, findings []domain.HubFinding, generatedAt time.Time) HubFindingsJSONReport {
	items := slices.Clone(findings)
	slices.SortFunc(items, func(a domain.HubFinding, b domain.HubFinding) int {
		if !a.FirstEventAt.Equal(b.FirstEventAt) {
			if a.FirstEventAt.After(b.FirstEventAt) {
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

	records := make([]HubFindingJSONRecord, 0, len(items))
	for _, finding := range items {
		records = append(records, hubFindingJSONRecord(finding))
	}
	return HubFindingsJSONReport{
		GeneratedAt: generatedAt.UTC(),
		Tool: ToolInfo{
			Name:      meta.Name,
			Binary:    meta.Binary,
			Version:   meta.Version,
			Commit:    meta.Commit,
			BuildDate: meta.BuildDate,
		},
		Scope:        scope,
		FindingCount: len(records),
		Findings:     records,
	}
}

func WriteHubFindingsJSON(w io.Writer, report HubFindingsJSONReport, pretty bool) error {
	encoder := json.NewEncoder(w)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}

func hubFindingJSONRecord(finding domain.HubFinding) HubFindingJSONRecord {
	metadata := finding.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	return HubFindingJSONRecord{
		ID:              string(finding.ID),
		RuleID:          finding.RuleID,
		RuleVersion:     finding.RuleVersion,
		DedupeKey:       finding.DedupeKey,
		Severity:        string(finding.Severity),
		Confidence:      string(finding.Confidence),
		RiskScore:       hubFindingRiskScore(metadata),
		RiskBand:        hubFindingRiskBand(metadata),
		Title:           finding.Title,
		Summary:         finding.Summary,
		Description:     finding.Description,
		OperatorAction:  hubFindingOperatorAction(metadata),
		EventIDs:        stringDomainIDs(finding.EventIDs),
		FirstEventAt:    finding.FirstEventAt,
		LastEventAt:     finding.LastEventAt,
		Status:          hubFindingStatus(finding),
		StatusReason:    finding.StatusReason,
		StatusNote:      finding.StatusNote,
		StatusActor:     finding.StatusActor,
		StatusUpdatedAt: hubFindingStatusUpdatedAt(finding),
		Metadata:        metadata,
		CreatedAt:       finding.CreatedAt,
		UpdatedAt:       finding.UpdatedAt,
	}
}

func hubFindingOperatorAction(metadata map[string]any) map[string]any {
	action, ok := metadata["operator_action"].(map[string]any)
	if !ok {
		return nil
	}
	return action
}

func hubFindingRiskScore(metadata map[string]any) int {
	risk, ok := metadata["risk"].(map[string]any)
	if !ok {
		return 0
	}
	switch score := risk["score"].(type) {
	case int:
		return score
	case int64:
		return int(score)
	case float64:
		return int(score)
	default:
		return 0
	}
}

func hubFindingRiskBand(metadata map[string]any) string {
	risk, ok := metadata["risk"].(map[string]any)
	if !ok {
		return ""
	}
	band, _ := risk["band"].(string)
	return band
}

func hubFindingStatus(finding domain.HubFinding) string {
	if strings.TrimSpace(finding.Status) == "" {
		return "open"
	}
	return finding.Status
}

func hubFindingStatusUpdatedAt(finding domain.HubFinding) time.Time {
	if finding.StatusUpdatedAt.IsZero() {
		return finding.UpdatedAt
	}
	return finding.StatusUpdatedAt
}

func stringDomainIDs(ids []domain.ID) []string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, string(id))
	}
	return values
}
