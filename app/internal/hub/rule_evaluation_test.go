package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestEvaluateBuiltInRuleFixturesPass(t *testing.T) {
	now := time.Date(2026, 5, 12, 16, 0, 0, 0, time.UTC)
	summary := EvaluateBuiltInRuleFixtures(now)

	if summary.GeneratedAt != now {
		t.Fatalf("generated at = %s, want %s", summary.GeneratedAt, now)
	}
	if summary.Failed != 0 {
		t.Fatalf("summary = %#v, want all fixtures passing", summary)
	}
	if summary.Passed != 11 || len(summary.Fixtures) != 11 {
		t.Fatalf("fixture counts = passed %d total %d, want 11", summary.Passed, len(summary.Fixtures))
	}
	if summary.Signals < 23 {
		t.Fatalf("signals = %d, want first-wave evaluation signals", summary.Signals)
	}

	byID := map[string]RuleEvaluationFixtureResult{}
	for _, fixture := range summary.Fixtures {
		byID[fixture.Fixture.ID] = fixture
	}

	clean := byID["clean-wordpress-install"]
	if len(clean.Expected) != 0 || len(clean.Actual) != 0 || !clean.Passed {
		t.Fatalf("clean fixture = %#v, want no signals", clean)
	}

	deploy := byID["deploy-window-browser-drift"]
	if len(deploy.Actual) != 1 || deploy.Actual[0].ID != "browser-script-domain-new" || deploy.Actual[0].Severity != domain.SeverityLow {
		t.Fatalf("deploy fixture = %#v, want lowered browser drift", deploy)
	}

	filePaths := byID["generic-suspicious-file-paths"]
	if len(filePaths.Actual) != 5 || !filePaths.Passed {
		t.Fatalf("generic file path fixture = %#v, want five expected file path signals", filePaths)
	}

	adminRequests := byID["admin-request-anomalies"]
	if len(adminRequests.Actual) != 3 || !adminRequests.Passed {
		t.Fatalf("admin request fixture = %#v, want three expected web request signals", adminRequests)
	}

	webTraffic := byID["web-request-traffic-and-tor"]
	if len(webTraffic.Actual) != 5 || !webTraffic.Passed {
		t.Fatalf("web traffic fixture = %#v, want five expected web request signals", webTraffic)
	}

	drift := byID["multi-host-file-drift"]
	if len(drift.Actual) != 1 || drift.Actual[0].ID != "file-baseline-drift" || drift.Actual[0].Confidence != domain.ConfidenceHigh {
		t.Fatalf("multi-host drift fixture = %#v, want high-confidence baseline signal", drift)
	}
}

func TestEvaluateRuleFixtureReportsMissingUnexpectedAndMismatchedSignals(t *testing.T) {
	fixture := RuleEvaluationFixture{ID: "test-fixture", Name: "Test Fixture", Kind: "unit"}
	result := evaluateRuleFixture(
		fixture,
		[]RuleEvaluationExpectedSignal{
			{ID: "expected-missing", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
			{ID: "expected-mismatch", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
		},
		[]RuleEvaluationSignal{
			{ID: "expected-mismatch", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
			{ID: "unexpected", Severity: domain.SeverityLow, Confidence: domain.ConfidenceMedium},
		},
	)

	if result.Passed {
		t.Fatal("fixture passed, want failure")
	}
	if len(result.Missing) != 1 || result.Missing[0].ID != "expected-missing" {
		t.Fatalf("missing = %#v, want expected-missing", result.Missing)
	}
	if len(result.Unexpected) != 1 || result.Unexpected[0].ID != "unexpected" {
		t.Fatalf("unexpected = %#v, want unexpected", result.Unexpected)
	}
	if len(result.Mismatched) != 1 || result.Mismatched[0].ID != "expected-mismatch" {
		t.Fatalf("mismatched = %#v, want expected-mismatch", result.Mismatched)
	}
}
