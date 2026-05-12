package cli

import (
	"strings"
	"testing"
)

func TestHubRulesEvaluateRunsBuiltInFixtures(t *testing.T) {
	stdout := runCLICapture(t, "aegrail", "hub", "rules", "evaluate", "--fail-on-mismatch")

	if !strings.Contains(stdout, "Rule fixture evaluation: 9 passed, 0 failed") {
		t.Fatalf("stdout = %q, want passing fixture summary", stdout)
	}
	if !strings.Contains(stdout, "generic-suspicious-file-paths") ||
		!strings.Contains(stdout, "deploy-window-browser-drift") ||
		!strings.Contains(stdout, "multi-host-file-drift") {
		t.Fatalf("stdout = %q, want deployment and multi-host fixture rows", stdout)
	}
}
