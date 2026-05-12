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
	if ruleHasActionHint("wordpress-admin-user-added", RuleActionAllowBrowserScript) {
		t.Fatal("wordpress admin rule should not support browser script allowlist action")
	}
}
