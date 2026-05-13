package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/redaction"
)

const (
	EvidenceBundleSchema           = "aegrail.evidence_bundle.v1"
	EvidenceBundleRedactionVersion = "2026-05-13.1"
)

type EvidenceBundleOptions struct {
	MaxFindings          int
	MaxEventsPerFinding  int
	MaxMetadataDepth     int
	MaxCollectionEntries int
	MaxStringLength      int
}

type EvidenceBundle struct {
	Schema       string                  `json:"schema"`
	GeneratedAt  time.Time               `json:"generated_at"`
	Tool         ToolInfo                `json:"tool"`
	Scope        HubFindingsScope        `json:"scope"`
	Redaction    EvidenceBundleRedaction `json:"redaction"`
	FindingCount int                     `json:"finding_count"`
	Findings     []EvidenceBundleFinding `json:"findings"`
	BundleSHA256 string                  `json:"bundle_sha256"`
}

type EvidenceBundleRedaction struct {
	Version string   `json:"version"`
	Rules   []string `json:"rules"`
}

type EvidenceBundleFinding struct {
	ID              string                        `json:"id"`
	RuleID          string                        `json:"rule_id"`
	RuleVersion     string                        `json:"rule_version"`
	Severity        string                        `json:"severity"`
	Confidence      string                        `json:"confidence"`
	RiskScore       int                           `json:"risk_score,omitempty"`
	RiskBand        string                        `json:"risk_band,omitempty"`
	Status          string                        `json:"status"`
	Title           string                        `json:"title"`
	Summary         string                        `json:"summary"`
	Description     string                        `json:"description,omitempty"`
	EventIDs        []string                      `json:"event_ids"`
	FirstEventAt    time.Time                     `json:"first_event_at"`
	LastEventAt     time.Time                     `json:"last_event_at"`
	Rule            map[string]any                `json:"rule,omitempty"`
	RiskFactors     []map[string]any              `json:"risk_factors,omitempty"`
	Deployment      map[string]any                `json:"deployment_context,omitempty"`
	Evidence        []EvidenceBundleEvidenceEvent `json:"evidence,omitempty"`
	MetadataExcerpt map[string]any                `json:"metadata_excerpt,omitempty"`
	RecommendedNext []string                      `json:"recommended_next_checks,omitempty"`
}

type EvidenceBundleEvidenceEvent struct {
	EventID   string `json:"event_id,omitempty"`
	EventTime string `json:"event_time,omitempty"`
	Host      string `json:"host,omitempty"`
	Type      string `json:"type,omitempty"`
	Target    string `json:"target,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Message   string `json:"message,omitempty"`
}

func DefaultEvidenceBundleOptions() EvidenceBundleOptions {
	return EvidenceBundleOptions{
		MaxFindings:          50,
		MaxEventsPerFinding:  8,
		MaxMetadataDepth:     4,
		MaxCollectionEntries: 12,
		MaxStringLength:      500,
	}
}

func BuildEvidenceBundle(report HubFindingsJSONReport, options EvidenceBundleOptions) (EvidenceBundle, error) {
	options = normalizeEvidenceBundleOptions(options)
	findings := markdownSortedFindings(report.Findings)
	if options.MaxFindings > 0 && len(findings) > options.MaxFindings {
		findings = findings[:options.MaxFindings]
	}

	bundleFindings := make([]EvidenceBundleFinding, 0, len(findings))
	for _, finding := range findings {
		bundleFindings = append(bundleFindings, evidenceBundleFinding(finding, options))
	}
	bundle := EvidenceBundle{
		Schema:      EvidenceBundleSchema,
		GeneratedAt: report.GeneratedAt.UTC(),
		Tool:        report.Tool,
		Scope:       report.Scope,
		Redaction: EvidenceBundleRedaction{
			Version: EvidenceBundleRedactionVersion,
			Rules: []string{
				"sensitive keys are replaced with [REDACTED]",
				"URLs are query-redacted for token, session, password, secret, and API key parameters",
				"free text is pattern-redacted for credentials, cookies, and authorization-like assignments",
				"metadata is depth-limited and long strings are truncated",
			},
		},
		FindingCount: len(bundleFindings),
		Findings:     bundleFindings,
	}
	hash, err := evidenceBundleHash(bundle)
	if err != nil {
		return EvidenceBundle{}, err
	}
	bundle.BundleSHA256 = hash
	return bundle, nil
}

func WriteEvidenceBundleJSON(w io.Writer, bundle EvidenceBundle, pretty bool) error {
	encoder := json.NewEncoder(w)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(bundle)
}

func evidenceBundleFinding(finding HubFindingJSONRecord, options EvidenceBundleOptions) EvidenceBundleFinding {
	metadata := nonNilMetadata(finding.Metadata)
	return EvidenceBundleFinding{
		ID:              redactedString(finding.ID, options.MaxStringLength),
		RuleID:          redactedString(finding.RuleID, options.MaxStringLength),
		RuleVersion:     redactedString(finding.RuleVersion, options.MaxStringLength),
		Severity:        redactedString(finding.Severity, options.MaxStringLength),
		Confidence:      redactedString(finding.Confidence, options.MaxStringLength),
		RiskScore:       finding.RiskScore,
		RiskBand:        redactedString(finding.RiskBand, options.MaxStringLength),
		Status:          redactedString(managerFindingStatus(finding), options.MaxStringLength),
		Title:           redactedString(finding.Title, options.MaxStringLength),
		Summary:         redactedString(finding.Summary, options.MaxStringLength),
		Description:     redactedString(finding.Description, options.MaxStringLength),
		EventIDs:        redactedStrings(finding.EventIDs, options.MaxStringLength),
		FirstEventAt:    finding.FirstEventAt.UTC(),
		LastEventAt:     finding.LastEventAt.UTC(),
		Rule:            compactMap(metadataMapValue(metadata, "rule"), options.MaxMetadataDepth, options),
		RiskFactors:     compactMapSlice(evidenceMetadataMapSlice(metadata, "risk", "factors"), options),
		Deployment:      compactMap(metadataMapValue(metadata, "deployment_context"), options.MaxMetadataDepth, options),
		Evidence:        evidenceBundleEvents(evidenceMetadataMapSlice(metadata, "events"), options),
		MetadataExcerpt: evidenceBundleMetadataExcerpt(metadata, options),
		RecommendedNext: redactedStrings(nextChecksForFinding(finding), options.MaxStringLength),
	}
}

func evidenceBundleEvents(events []map[string]any, options EvidenceBundleOptions) []EvidenceBundleEvidenceEvent {
	if len(events) == 0 {
		return nil
	}
	limit := min(options.MaxEventsPerFinding, len(events))
	records := make([]EvidenceBundleEvidenceEvent, 0, limit)
	for _, event := range events[:limit] {
		records = append(records, EvidenceBundleEvidenceEvent{
			EventID:   redactedString(metadataString(event, "event_id"), options.MaxStringLength),
			EventTime: redactedString(metadataString(event, "event_time"), options.MaxStringLength),
			Host:      redactedString(metadataString(event, "host"), options.MaxStringLength),
			Type:      redactedString(metadataString(event, "type"), options.MaxStringLength),
			Target:    redactedString(metadataString(event, "target"), options.MaxStringLength),
			Severity:  redactedString(metadataString(event, "severity"), options.MaxStringLength),
			Message:   redactedString(metadataString(event, "message"), options.MaxStringLength),
		})
	}
	return records
}

func evidenceBundleMetadataExcerpt(metadata map[string]any, options EvidenceBundleOptions) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	skip := map[string]struct{}{
		"deployment_context": {},
		"events":             {},
		"risk":               {},
		"rule":               {},
	}
	excerpt := map[string]any{}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		if _, ok := skip[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if len(excerpt) >= options.MaxCollectionEntries {
			excerpt["_omitted_keys"] = len(keys) - len(excerpt)
			break
		}
		excerpt[key] = compactRedactedValue(key, metadata[key], options.MaxMetadataDepth, options)
	}
	if len(excerpt) == 0 {
		return nil
	}
	return excerpt
}

func compactMap(value map[string]any, depth int, options EvidenceBundleOptions) map[string]any {
	if len(value) == 0 {
		return nil
	}
	compact, _ := compactRedactedValue("", value, depth, options).(map[string]any)
	if len(compact) == 0 {
		return nil
	}
	return compact
}

func compactMapSlice(values []map[string]any, options EvidenceBundleOptions) []map[string]any {
	if len(values) == 0 {
		return nil
	}
	limit := min(options.MaxCollectionEntries, len(values))
	items := make([]map[string]any, 0, limit)
	for _, value := range values[:limit] {
		items = append(items, compactMap(value, options.MaxMetadataDepth, options))
	}
	return items
}

func compactRedactedValue(key string, value any, depth int, options EvidenceBundleOptions) any {
	value = redaction.RedactAny(map[string]any{key: value}).(map[string]any)[key]
	if depth <= 0 {
		switch value.(type) {
		case map[string]any, []any, []string, []map[string]any:
			return "[OMITTED_DEPTH_LIMIT]"
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for itemKey := range typed {
			keys = append(keys, itemKey)
		}
		slices.Sort(keys)
		compact := map[string]any{}
		for _, itemKey := range keys {
			if len(compact) >= options.MaxCollectionEntries {
				compact["_omitted_keys"] = len(keys) - len(compact)
				break
			}
			compact[itemKey] = compactRedactedValue(itemKey, typed[itemKey], depth-1, options)
		}
		return compact
	case []map[string]any:
		limit := min(options.MaxCollectionEntries, len(typed))
		items := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			items = append(items, compactRedactedValue("", item, depth-1, options))
		}
		return items
	case []any:
		limit := min(options.MaxCollectionEntries, len(typed))
		items := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			items = append(items, compactRedactedValue("", item, depth-1, options))
		}
		return items
	case []string:
		limit := min(options.MaxCollectionEntries, len(typed))
		items := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			items = append(items, redactedString(item, options.MaxStringLength))
		}
		return items
	case string:
		return truncateString(typed, options.MaxStringLength)
	case fmt.Stringer:
		return truncateString(redactedString(typed.String(), options.MaxStringLength), options.MaxStringLength)
	default:
		return value
	}
}

func evidenceBundleHash(bundle EvidenceBundle) (string, error) {
	bundle.BundleSHA256 = ""
	content, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeEvidenceBundleOptions(options EvidenceBundleOptions) EvidenceBundleOptions {
	defaults := DefaultEvidenceBundleOptions()
	if options.MaxFindings <= 0 {
		options.MaxFindings = defaults.MaxFindings
	}
	if options.MaxEventsPerFinding <= 0 {
		options.MaxEventsPerFinding = defaults.MaxEventsPerFinding
	}
	if options.MaxMetadataDepth <= 0 {
		options.MaxMetadataDepth = defaults.MaxMetadataDepth
	}
	if options.MaxCollectionEntries <= 0 {
		options.MaxCollectionEntries = defaults.MaxCollectionEntries
	}
	if options.MaxStringLength <= 0 {
		options.MaxStringLength = defaults.MaxStringLength
	}
	return options
}

func nonNilMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	return metadata
}

func metadataMapValue(metadata map[string]any, key string) map[string]any {
	value, _ := metadata[key].(map[string]any)
	return value
}

func evidenceMetadataMapSlice(metadata map[string]any, keys ...string) []map[string]any {
	if len(keys) == 0 {
		return nil
	}
	value := any(metadata)
	for _, key := range keys {
		current, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = current[key]
	}
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		items := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if mapped, ok := item.(map[string]any); ok {
				items = append(items, mapped)
			}
		}
		return items
	default:
		return nil
	}
}

func redactedString(value string, limit int) string {
	return truncateString(redaction.RedactText(redaction.RedactURL(value)), limit)
}

func redactedStrings(values []string, limit int) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, redactedString(value, limit))
	}
	return items
}

func truncateString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 20 {
		return value[:limit]
	}
	return value[:limit] + "...[TRUNCATED]"
}
