package hub

import "testing"

func TestDefaultRuleRegistryIncludesCurrentRuleMetadata(t *testing.T) {
	hub := New(Dependencies{})
	rules := hub.ListRuleDefinitions()
	if len(rules) < 50 {
		t.Fatalf("rules count = %d, want current rule set", len(rules))
	}
	seen := map[string]struct{}{}
	for _, rule := range rules {
		if rule.ID == "" || rule.Version == "" || rule.Category == "" {
			t.Fatalf("rule = %#v, want id/version/category", rule)
		}
		if _, ok := seen[rule.ID]; ok {
			t.Fatalf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	for _, id := range []string{
		"probable-incident-chain",
		"wordpress-admin-user-added",
		"prestashop-payment-configuration-changed",
		"browser-script-domain-new",
		"web-admin-success-after-failures",
		"web-request-volume-spike",
		"web-tor-admin-request",
		"file-php-in-writable-path",
	} {
		if _, ok := seen[id]; !ok {
			t.Fatalf("rule %q was not registered", id)
		}
	}
}

func TestRuleMetadataAddsVersionAndActionHints(t *testing.T) {
	metadata := ruleMetadata("browser-script-domain-new", map[string]any{"value": "cdn.example"})
	rule, ok := metadata["rule"].(map[string]any)
	if !ok {
		t.Fatalf("metadata = %#v, want rule metadata", metadata)
	}
	if rule["version"] != currentRuleVersion || rule["category"] != string(RuleCategoryBrowserScript) {
		t.Fatalf("rule metadata = %#v, want browser script rule version/category", rule)
	}
	if !ruleHasActionHint("browser-script-domain-new", RuleActionAllowBrowserScript) {
		t.Fatal("browser script domain rule missing allow_browser_script action hint")
	}
	if !ruleHasActionHint("browser-script-domain-new", RuleActionInspectDeployment) {
		t.Fatal("browser script domain rule missing inspect_deployment action hint")
	}
	if !ruleHasActionHint("wordpress-admin-user-added", RuleActionInspectDeployment) {
		t.Fatal("wordpress admin rule missing inspect_deployment action hint")
	}
	metadata = ruleMetadata("file-php-in-writable-path", nil)
	rule, ok = metadata["rule"].(map[string]any)
	if !ok || rule["category"] != string(RuleCategoryFilePath) {
		t.Fatalf("file rule metadata = %#v, want file_path category", metadata)
	}
	metadata = ruleMetadata("web-admin-success-after-failures", nil)
	rule, ok = metadata["rule"].(map[string]any)
	if !ok || rule["category"] != string(RuleCategoryWebRequest) {
		t.Fatalf("web request rule metadata = %#v, want web_request category", metadata)
	}
	if ruleHasActionHint("wordpress-admin-user-added", RuleActionAllowBrowserScript) {
		t.Fatal("wordpress admin rule should not support browser script allowlist action")
	}
}
