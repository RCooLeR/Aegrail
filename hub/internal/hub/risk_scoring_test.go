package hub

import (
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestApplyRiskScoringAddsStableRiskMetadata(t *testing.T) {
	now := time.Date(2026, 5, 12, 15, 0, 0, 0, time.UTC)
	finding := applyRiskScoring(domain.HubFinding{
		RuleID:       "probable-incident-chain",
		Severity:     domain.SeverityHigh,
		Confidence:   domain.ConfidenceHigh,
		EventIDs:     []domain.ID{"evt-login", "evt-file", "evt-db"},
		FirstEventAt: now,
		LastEventAt:  now.Add(8 * time.Minute),
		Metadata: map[string]any{
			"events": []map[string]any{
				{"host": "web-01"},
				{"host": "web-02"},
				{"host": "db-01"},
			},
		},
	})

	risk, ok := finding.Metadata["risk"].(map[string]any)
	if !ok {
		t.Fatalf("risk metadata = %#v, want risk map", finding.Metadata["risk"])
	}
	if risk["version"] != currentRiskScoreVersion || risk["band"] != "critical" {
		t.Fatalf("risk = %#v, want current critical risk metadata", risk)
	}
	score, ok := risk["score"].(int)
	if !ok || score < 85 {
		t.Fatalf("risk score = %#v, want critical score", risk["score"])
	}
	if risk["host_count"] != 3 || risk["event_count"] != 3 {
		t.Fatalf("risk = %#v, want host and event counts", risk)
	}
}

func TestApplyRiskScoringAddsOperatorActionMetadata(t *testing.T) {
	finding := applyRiskScoring(domain.HubFinding{
		RuleID:     "browser-script-domain-new",
		Severity:   domain.SeverityMedium,
		Confidence: domain.ConfidenceMedium,
		Title:      "New browser script domain",
		Summary:    "browser observed new script domain",
	})

	action, ok := finding.Metadata["operator_action"].(map[string]any)
	if !ok {
		t.Fatalf("metadata = %#v, want operator_action", finding.Metadata)
	}
	primary, _ := action["primary_action"].(string)
	if !strings.Contains(strings.ToLower(primary), "script") || action["recommended_status_expected"] != "acknowledged" {
		t.Fatalf("operator action = %#v, want script-specific next action and status guidance", action)
	}
	steps, ok := action["actions"].([]string)
	if !ok || len(steps) == 0 {
		t.Fatalf("operator action steps = %#v, want concrete steps", action["actions"])
	}
}

func TestApplyRiskScoringIgnoresLegacyDeploymentAdjustmentMetadata(t *testing.T) {
	input := domain.HubFinding{
		RuleID:     "browser-script-domain-new",
		Severity:   domain.SeverityLow,
		Confidence: domain.ConfidenceMedium,
		EventIDs:   []domain.ID{"evt-browser"},
	}
	baseline := applyRiskScoring(input)
	input.Metadata = map[string]any{
		"deployment_context": map[string]any{
			"active":            true,
			"severity_adjusted": true,
			"original_severity": "medium",
			"adjusted_severity": "low",
		},
	}
	withDeployment := applyRiskScoring(input)

	baselineRisk, ok := baseline.Metadata["risk"].(map[string]any)
	if !ok {
		t.Fatalf("baseline risk metadata = %#v, want risk map", baseline.Metadata["risk"])
	}
	risk, ok := withDeployment.Metadata["risk"].(map[string]any)
	if !ok {
		t.Fatalf("deployment risk metadata = %#v, want risk map", withDeployment.Metadata["risk"])
	}
	if risk["deployment_active"] != true {
		t.Fatalf("risk = %#v, want deployment context exposed", risk)
	}
	if risk["score"] != baselineRisk["score"] || risk["band"] != baselineRisk["band"] {
		t.Fatalf("deployment risk = %#v, baseline risk = %#v; context must not change score or band", risk, baselineRisk)
	}
	factors, ok := risk["factors"].([]map[string]any)
	if !ok {
		t.Fatalf("risk factors = %#v, want factor records", risk["factors"])
	}
	for _, factor := range factors {
		if factor["id"] == "context:deployment_adjusted" {
			t.Fatalf("risk factors = %#v, deployment marker must not contribute a negative factor", factors)
		}
	}
}
