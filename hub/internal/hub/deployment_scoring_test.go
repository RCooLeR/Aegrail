package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestAnnotateFindingWithDeploymentContextPreservesSeverity(t *testing.T) {
	startedAt := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	deployment := domain.DeploymentMarker{
		ID:        "deploy-release",
		AppID:     "app-main-web",
		Version:   "v2.4.1",
		CommitSHA: "abc1234",
		Actor:     "release-bot",
		StartedAt: startedAt,
	}

	for _, severity := range []domain.Severity{
		domain.SeverityLow,
		domain.SeverityMedium,
		domain.SeverityHigh,
		domain.SeverityCritical,
	} {
		t.Run(string(severity), func(t *testing.T) {
			finding := domain.HubFinding{
				RuleID:   "browser-script-domain-new",
				Severity: severity,
				Metadata: map[string]any{"existing": "metadata"},
			}

			annotated := annotateFindingWithDeploymentContext(finding, []domain.DeploymentMarker{deployment})
			if annotated.Severity != severity {
				t.Fatalf("severity = %q, want %q", annotated.Severity, severity)
			}
			if annotated.Metadata["existing"] != "metadata" {
				t.Fatalf("metadata = %#v, want existing metadata preserved", annotated.Metadata)
			}
			context, ok := annotated.Metadata["deployment_context"].(map[string]any)
			if !ok || context["active"] != true || context["severity_adjusted"] != false ||
				context["original_severity"] != string(severity) || context["adjusted_severity"] != string(severity) {
				t.Fatalf("deployment context = %#v, want context without severity adjustment", annotated.Metadata["deployment_context"])
			}
			deployments, ok := context["deployments"].([]map[string]any)
			if !ok || len(deployments) != 1 || deployments[0]["id"] != "deploy-release" || deployments[0]["version"] != "v2.4.1" {
				t.Fatalf("deployment records = %#v, want marker investigation details", context["deployments"])
			}

			baselineRisk := applyRiskScoring(finding).Metadata["risk"].(map[string]any)
			annotatedRisk := applyRiskScoring(annotated).Metadata["risk"].(map[string]any)
			if annotatedRisk["score"] != baselineRisk["score"] || annotatedRisk["band"] != baselineRisk["band"] {
				t.Fatalf("annotated risk = %#v, baseline risk = %#v; deployment context must not change risk", annotatedRisk, baselineRisk)
			}
		})
	}
}
