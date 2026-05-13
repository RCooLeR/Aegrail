package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
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

func TestApplyRiskScoringReflectsDeploymentAdjustment(t *testing.T) {
	finding := applyRiskScoring(domain.HubFinding{
		RuleID:     "browser-script-domain-new",
		Severity:   domain.SeverityLow,
		Confidence: domain.ConfidenceMedium,
		EventIDs:   []domain.ID{"evt-browser"},
		Metadata: map[string]any{
			"deployment_context": map[string]any{
				"active":            true,
				"severity_adjusted": true,
				"original_severity": "medium",
				"adjusted_severity": "low",
			},
		},
	})

	risk, ok := finding.Metadata["risk"].(map[string]any)
	if !ok {
		t.Fatalf("risk metadata = %#v, want risk map", finding.Metadata["risk"])
	}
	if risk["band"] != "low" || risk["deployment_active"] != true {
		t.Fatalf("risk = %#v, want low risk with active deployment context", risk)
	}
	score, ok := risk["score"].(int)
	if !ok || score >= 40 {
		t.Fatalf("risk score = %#v, want deployment-adjusted score below medium", risk["score"])
	}
}
