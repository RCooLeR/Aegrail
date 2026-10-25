package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestSuspiciousFilePathRuleSkipsRecognizedPrestaShopAssetGuard(t *testing.T) {
	event := testFilePathEvent("file.created", "themes/at_petstore/modules/blockreviews/views/img/btn/index.php", map[string]any{
		"file_kind":            "prestashop_asset_guard_index",
		"file_role":            "directory_guard",
		"file_role_confidence": "high",
	})
	if rule, ok := suspiciousFilePathRuleForEvent(event); ok {
		t.Fatalf("rule = %#v, want recognized PrestaShop guard to be ignored", rule)
	}
}

func TestSuspiciousFilePathRuleDowngradesUnverifiedPrestaShopAssetGuardPath(t *testing.T) {
	event := testFilePathEvent("file.created", "themes/at_petstore/modules/blockreviews/views/img/btn/index.php", nil)
	rule, ok := suspiciousFilePathRuleForEvent(event)
	if !ok {
		t.Fatalf("expected unverified guard path to remain visible as a module/theme change")
	}
	if rule.RuleID != "file-plugin-theme-module-changed" || rule.Severity != domain.SeverityMedium {
		t.Fatalf("rule = %#v, want medium module/theme rule", rule)
	}
}

func TestSuspiciousFilePathRuleStillFlagsPHPInPrestaShopAssetPath(t *testing.T) {
	event := testFilePathEvent("file.created", "themes/at_petstore/modules/blockreviews/views/img/btn/shell.php", nil)
	rule, ok := suspiciousFilePathRuleForEvent(event)
	if !ok {
		t.Fatalf("expected suspicious PHP in asset path to be flagged")
	}
	if rule.RuleID != "file-php-in-writable-path" || rule.Severity != domain.SeverityHigh {
		t.Fatalf("rule = %#v, want high writable PHP rule", rule)
	}
}

func TestSuspiciousFilePathRuleSkipsGeneratedPrestaShopThemeProfiles(t *testing.T) {
	event := testFilePathEvent("file.modified", "themes/at_petstore/profiles/id_gencode_5b02b134d274d_1526903092.tpl", nil)
	if rule, ok := suspiciousFilePathRuleForEvent(event); ok {
		t.Fatalf("rule = %#v, want generated PrestaShop theme profile to be ignored", rule)
	}
}

func TestSuspiciousFilePathRuleFlagsAgentDetectedPHPWebshellContent(t *testing.T) {
	event := testFilePathEvent("file.created", "modules/gridhtml/x.php", map[string]any{
		"file_role":             "suspicious_php",
		"security_context":      "webshell_like_php",
		"suspicious_php_reason": "post_base64_eval_webshell",
	})
	rule, ok := suspiciousFilePathRuleForEvent(event)
	if !ok {
		t.Fatalf("expected suspicious PHP content to be flagged")
	}
	if rule.RuleID != "file-suspicious-php-content" || rule.Severity != domain.SeverityHigh || rule.Confidence != domain.ConfidenceHigh {
		t.Fatalf("rule = %#v, want high-confidence suspicious PHP content rule", rule)
	}
}

func TestSuspiciousFilePathRuleFlagsPrestaShopFacetedSearchExploitArtifact(t *testing.T) {
	event := testFilePathEvent("file.created", "modules/ps_facetedsearch/ps_facetedsearch-3d2c8f50.php", nil)
	rule, ok := suspiciousFilePathRuleForEvent(event)
	if !ok {
		t.Fatalf("expected ps_facetedsearch exploit artifact to be flagged")
	}
	if rule.RuleID != "prestashop-facetedsearch-exploit-artifact" || rule.Severity != domain.SeverityHigh {
		t.Fatalf("rule = %#v, want PrestaShop faceted search exploit artifact rule", rule)
	}
}

func TestSuspiciousFilePathRuleKeepsNormalThemeProfileTemplates(t *testing.T) {
	event := testFilePathEvent("file.modified", "themes/at_petstore/profiles/layout.tpl", nil)
	rule, ok := suspiciousFilePathRuleForEvent(event)
	if !ok {
		t.Fatalf("expected normal theme profile template to remain visible")
	}
	if rule.RuleID != "file-plugin-theme-module-changed" {
		t.Fatalf("rule = %#v, want theme/module change rule", rule)
	}
}

func testFilePathEvent(eventType string, path string, payload map[string]any) domain.TimelineEvent {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["relative_path"] = path
	return domain.TimelineEvent{
		ID:        "evt-file-path",
		EventTime: time.Date(2026, 5, 16, 18, 30, 0, 0, time.UTC),
		EventType: eventType,
		Target:    path,
		Severity:  domain.SeverityInfo,
		HostSlug:  "local",
		Payload:   payload,
	}
}
