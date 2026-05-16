package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
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
