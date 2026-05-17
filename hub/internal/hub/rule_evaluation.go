package hub

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type RuleEvaluationFixture struct {
	ID          string
	Name        string
	Kind        string
	Description string
}

type RuleEvaluationExpectedSignal struct {
	ID         string
	Severity   domain.Severity
	Confidence domain.Confidence
}

type RuleEvaluationSignal struct {
	ID         string
	Source     string
	Severity   domain.Severity
	Confidence domain.Confidence
	Summary    string
}

type RuleEvaluationMismatch struct {
	ID                 string
	ExpectedSeverity   domain.Severity
	ActualSeverity     domain.Severity
	ExpectedConfidence domain.Confidence
	ActualConfidence   domain.Confidence
}

type RuleEvaluationFixtureResult struct {
	Fixture    RuleEvaluationFixture
	Expected   []RuleEvaluationExpectedSignal
	Actual     []RuleEvaluationSignal
	Missing    []RuleEvaluationExpectedSignal
	Unexpected []RuleEvaluationSignal
	Mismatched []RuleEvaluationMismatch
	Passed     bool
}

type RuleEvaluationSummary struct {
	GeneratedAt time.Time
	Passed      int
	Failed      int
	Signals     int
	Fixtures    []RuleEvaluationFixtureResult
}

type ruleEvaluationCase struct {
	fixture  RuleEvaluationFixture
	expected []RuleEvaluationExpectedSignal
	evaluate func(time.Time) []RuleEvaluationSignal
}

func EvaluateBuiltInRuleFixtures(now time.Time) RuleEvaluationSummary {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()

	cases := builtInRuleEvaluationCases()
	summary := RuleEvaluationSummary{
		GeneratedAt: now,
		Fixtures:    make([]RuleEvaluationFixtureResult, 0, len(cases)),
	}
	for _, evaluationCase := range cases {
		actual := evaluationCase.evaluate(now)
		result := evaluateRuleFixture(evaluationCase.fixture, evaluationCase.expected, actual)
		if result.Passed {
			summary.Passed++
		} else {
			summary.Failed++
		}
		summary.Signals += len(result.Actual)
		summary.Fixtures = append(summary.Fixtures, result)
	}
	return summary
}

func BuiltInRuleEvaluationFixtures() []RuleEvaluationFixture {
	cases := builtInRuleEvaluationCases()
	fixtures := make([]RuleEvaluationFixture, 0, len(cases))
	for _, evaluationCase := range cases {
		fixtures = append(fixtures, evaluationCase.fixture)
	}
	return fixtures
}

func builtInRuleEvaluationCases() []ruleEvaluationCase {
	return []ruleEvaluationCase{
		{
			fixture: RuleEvaluationFixture{
				ID:          "clean-wordpress-install",
				Name:        "Clean WordPress Install",
				Kind:        "clean",
				Description: "Benign coverage, access, and browser observation events should not produce findings.",
			},
			evaluate: evaluateCleanWordPressFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "compromised-wordpress-uploads",
				Name:        "Compromised WordPress Uploads",
				Kind:        "correlation",
				Description: "Suspicious admin traffic followed by PHP under uploads and a new administrator should produce an incident chain.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "probable-incident-chain", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
				{ID: "wordpress-admin-user-added", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
			},
			evaluate: evaluateCompromisedWordPressFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "generic-suspicious-file-paths",
				Name:        "Generic Suspicious File Paths",
				Kind:        "file_path",
				Description: "Standalone suspicious PHP, sensitive config, extension, and CMS extension paths should produce file path findings.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "file-php-in-writable-path", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
				{ID: "file-sensitive-config-changed", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
				{ID: "file-suspicious-path-pattern", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
				{ID: "file-plugin-theme-module-changed", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
				{ID: "file-php-changed", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
			},
			evaluate: evaluateGenericSuspiciousFilePathFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "admin-request-anomalies",
				Name:        "Admin Request Anomalies",
				Kind:        "web_request",
				Description: "Suspicious admin/login request patterns should produce deterministic web request findings.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "web-admin-success-after-failures", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceMedium},
				{ID: "web-admin-login-post-burst", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
				{ID: "web-admin-tool-probe", Severity: domain.SeverityLow, Confidence: domain.ConfidenceMedium},
			},
			evaluate: evaluateAdminRequestAnomalyFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "web-request-traffic-and-tor",
				Name:        "Web Request Traffic And Tor",
				Kind:        "web_request",
				Description: "Traffic spikes, server-error spikes, distributed admin POSTs, and Tor-marked requests should produce deterministic web request findings.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "web-request-volume-spike", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
				{ID: "web-error-rate-spike", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh},
				{ID: "web-admin-post-volume-spike", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh},
				{ID: "web-tor-admin-request", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh},
				{ID: "web-tor-request-observed", Severity: domain.SeverityLow, Confidence: domain.ConfidenceMedium},
			},
			evaluate: evaluateWebRequestTrafficAndTorFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "wordpress-admin-role-change",
				Name:        "WordPress Admin Role Change",
				Kind:        "database_snapshot",
				Description: "A WordPress user becoming an administrator should stay high severity.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "wordpress-user-became-admin", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
			},
			evaluate: evaluateWordPressAdminRoleFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "prestashop-module-drift",
				Name:        "PrestaShop Module Drift",
				Kind:        "database_snapshot",
				Description: "A newly installed PrestaShop module should produce a focused module finding.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "prestashop-module-added", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh},
			},
			evaluate: evaluatePrestaShopModuleFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "prestashop-employee-privilege-escalation",
				Name:        "PrestaShop Employee Privilege Escalation",
				Kind:        "database_snapshot",
				Description: "A PrestaShop employee becoming SuperAdmin should stay high severity.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "prestashop-employee-became-superadmin", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
			},
			evaluate: evaluatePrestaShopEmployeeFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "browser-script-injection",
				Name:        "Browser Script Injection",
				Kind:        "browser_script",
				Description: "Rendered browser observations should detect new script domains, inline hashes, and tag manager IDs.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "browser-script-domain-new", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
				{ID: "browser-inline-script-changed", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceMedium},
				{ID: "browser-tag-manager-id-new", Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh},
			},
			evaluate: evaluateBrowserScriptInjectionFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "deploy-window-browser-drift",
				Name:        "Deploy Window Browser Drift",
				Kind:        "deployment_scoring",
				Description: "A new browser script domain during a deployment should be lowered from medium to low.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "browser-script-domain-new", Severity: domain.SeverityLow, Confidence: domain.ConfidenceMedium},
			},
			evaluate: evaluateDeployWindowBrowserDriftFixture,
		},
		{
			fixture: RuleEvaluationFixture{
				ID:          "multi-host-file-drift",
				Name:        "Multi-Host File Drift",
				Kind:        "file_baseline",
				Description: "Different file hashes across production web nodes should produce a file baseline drift signal.",
			},
			expected: []RuleEvaluationExpectedSignal{
				{ID: "file-baseline-drift", Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh},
			},
			evaluate: evaluateMultiHostFileDriftFixture,
		},
	}
}

func evaluateRuleFixture(fixture RuleEvaluationFixture, expected []RuleEvaluationExpectedSignal, actual []RuleEvaluationSignal) RuleEvaluationFixtureResult {
	expected = cloneExpectedEvaluationSignals(expected)
	actual = cloneEvaluationSignals(actual)
	sortExpectedEvaluationSignals(expected)
	sortEvaluationSignals(actual)

	result := RuleEvaluationFixtureResult{
		Fixture:  fixture,
		Expected: expected,
		Actual:   actual,
	}
	usedActual := make([]bool, len(actual))
	for _, expectedSignal := range expected {
		actualIndex := findEvaluationSignal(actual, usedActual, expectedSignal.ID)
		if actualIndex < 0 {
			result.Missing = append(result.Missing, expectedSignal)
			continue
		}
		usedActual[actualIndex] = true
		actualSignal := actual[actualIndex]
		if actualSignal.Severity != expectedSignal.Severity || actualSignal.Confidence != expectedSignal.Confidence {
			result.Mismatched = append(result.Mismatched, RuleEvaluationMismatch{
				ID:                 expectedSignal.ID,
				ExpectedSeverity:   expectedSignal.Severity,
				ActualSeverity:     actualSignal.Severity,
				ExpectedConfidence: expectedSignal.Confidence,
				ActualConfidence:   actualSignal.Confidence,
			})
		}
	}
	for index, actualSignal := range actual {
		if !usedActual[index] {
			result.Unexpected = append(result.Unexpected, actualSignal)
		}
	}
	result.Passed = len(result.Missing) == 0 && len(result.Unexpected) == 0 && len(result.Mismatched) == 0
	return result
}

func findEvaluationSignal(actual []RuleEvaluationSignal, used []bool, id string) int {
	for index, signal := range actual {
		if used[index] || signal.ID != id {
			continue
		}
		return index
	}
	return -1
}

func evaluateCleanWordPressFixture(now time.Time) []RuleEvaluationSignal {
	events := []domain.TimelineEvent{
		evaluationTimelineEvent("evt-clean-access", now, "log.access", "/", domain.SeverityInfo, map[string]any{"status_code": 200, "path": "/"}),
		evaluationTimelineEvent("evt-clean-coverage", now.Add(time.Minute), "agent.config.coverage", "main-web", domain.SeverityInfo, map[string]any{"level": "strong"}),
		evaluationBrowserScriptEvent("evt-clean-browser", now.Add(2*time.Minute), "https://example.test", map[string]any{
			"source_type": "network",
			"domain":      "static.example.test",
		}),
	}
	return correlationEvaluationSignals(events, 30*time.Minute)
}

func evaluateCompromisedWordPressFixture(now time.Time) []RuleEvaluationSignal {
	events := []domain.TimelineEvent{
		evaluationTimelineEvent("evt-wp-login", now, "log.access", "/wp-login.php", domain.SeverityMedium, map[string]any{"status_code": 403, "path": "/wp-login.php"}),
		evaluationTimelineEvent("evt-wp-upload", now.Add(4*time.Minute), "file.created", "wp-content/uploads/avatar.php", domain.SeverityHigh, map[string]any{"relative_path": "wp-content/uploads/avatar.php"}),
		wordpressUserEntityEvent("evt-wp-admin", now.Add(7*time.Minute), "db.entity.added", true, false),
	}
	return correlationEvaluationSignals(events, 30*time.Minute)
}

func evaluateGenericSuspiciousFilePathFixture(now time.Time) []RuleEvaluationSignal {
	return correlationEvaluationSignals([]domain.TimelineEvent{
		evaluationTimelineEvent("evt-file-upload-php", now, "file.created", "wp-content/uploads/avatar.php", domain.SeverityInfo, map[string]any{
			"relative_path": "wp-content/uploads/avatar.php",
			"sha256":        "upload-php",
		}),
		evaluationTimelineEvent("evt-file-config", now.Add(time.Minute), "file.modified", "wp-config.php", domain.SeverityInfo, map[string]any{
			"relative_path": "wp-config.php",
			"sha256":        "config",
		}),
		evaluationTimelineEvent("evt-file-pattern", now.Add(2*time.Minute), "file.created", "assets/shell.txt", domain.SeverityInfo, map[string]any{
			"relative_path": "assets/shell.txt",
			"sha256":        "shell-name",
		}),
		evaluationTimelineEvent("evt-file-plugin", now.Add(3*time.Minute), "file.modified", "wp-content/plugins/shop/plugin.php", domain.SeverityInfo, map[string]any{
			"relative_path": "wp-content/plugins/shop/plugin.php",
			"sha256":        "plugin",
		}),
		evaluationTimelineEvent("evt-file-php", now.Add(4*time.Minute), "file.modified", "public/index.php", domain.SeverityInfo, map[string]any{
			"relative_path": "public/index.php",
			"sha256":        "php",
		}),
		evaluationTimelineEvent("evt-file-static", now.Add(5*time.Minute), "file.created", "wp-content/uploads/logo.png", domain.SeverityInfo, map[string]any{
			"relative_path": "wp-content/uploads/logo.png",
			"sha256":        "static",
		}),
	}, 30*time.Minute)
}

func evaluateAdminRequestAnomalyFixture(now time.Time) []RuleEvaluationSignal {
	return correlationEvaluationSignals([]domain.TimelineEvent{
		evaluationAdminAccessEvent("evt-admin-fail-1", now, "GET", "/wp-admin/", 403, "203.0.113.10"),
		evaluationAdminAccessEvent("evt-admin-fail-2", now.Add(time.Minute), "GET", "/wp-admin/", 403, "203.0.113.10"),
		evaluationAdminAccessEvent("evt-admin-fail-3", now.Add(2*time.Minute), "GET", "/wp-admin/", 403, "203.0.113.10"),
		evaluationAdminAccessEvent("evt-admin-success", now.Add(3*time.Minute), "POST", "/wp-login.php?redirect_to=/wp-admin/", 302, "203.0.113.10"),
		evaluationAdminAccessEvent("evt-login-post-1", now.Add(10*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		evaluationAdminAccessEvent("evt-login-post-2", now.Add(11*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		evaluationAdminAccessEvent("evt-login-post-3", now.Add(12*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		evaluationAdminAccessEvent("evt-login-post-4", now.Add(13*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		evaluationAdminAccessEvent("evt-login-post-5", now.Add(14*time.Minute), "POST", "/wp-login.php", 200, "203.0.113.20"),
		evaluationAdminAccessEvent("evt-tool-probe", now.Add(20*time.Minute), "GET", "/phpmyadmin/index.php", 404, "203.0.113.30"),
		evaluationAdminAccessEvent("evt-admin-ajax", now.Add(21*time.Minute), "POST", "/wp-admin/admin-ajax.php", 200, "203.0.113.40"),
	}, 30*time.Minute)
}

func evaluateWebRequestTrafficAndTorFixture(now time.Time) []RuleEvaluationSignal {
	events := make([]domain.TimelineEvent, 0, 38)
	for index := range 20 {
		events = append(events, evaluationAccessEvent(fmt.Sprintf("evt-volume-%02d", index), now.Add(time.Duration(index)*10*time.Second), "GET", "/catalog?page=1", 200, "198.51.100.10", nil))
	}
	for index := range 6 {
		events = append(events, evaluationAccessEvent(fmt.Sprintf("evt-error-%02d", index), now.Add(time.Minute+time.Duration(index)*10*time.Second), "GET", "/checkout", 500, fmt.Sprintf("198.51.100.%d", 20+index), nil))
	}
	for index := range 10 {
		events = append(events, evaluationAccessEvent(fmt.Sprintf("evt-admin-post-%02d", index), now.Add(2*time.Minute+time.Duration(index)*10*time.Second), "POST", "/wp-login.php", 200, fmt.Sprintf("203.0.113.%d", 10+index), nil))
	}
	events = append(events,
		evaluationAccessEvent("evt-tor-admin", now.Add(4*time.Minute), "GET", "/wp-admin/", 403, "203.0.113.200", map[string]any{"remote_is_tor": true}),
		evaluationAccessEvent("evt-tor-public", now.Add(5*time.Minute), "GET", "/", 200, "203.0.113.201", map[string]any{"remote_network": "tor_exit"}),
	)
	return correlationEvaluationSignals(events, 30*time.Minute)
}

func evaluateWordPressAdminRoleFixture(now time.Time) []RuleEvaluationSignal {
	return correlationEvaluationSignals([]domain.TimelineEvent{
		wordpressUserEntityEvent("evt-wp-role", now, "db.entity.changed", true, false),
	}, 30*time.Minute)
}

func evaluatePrestaShopModuleFixture(now time.Time) []RuleEvaluationSignal {
	return correlationEvaluationSignals([]domain.TimelineEvent{
		prestashopModuleEntityEvent("evt-ps-module", now),
	}, 30*time.Minute)
}

func evaluatePrestaShopEmployeeFixture(now time.Time) []RuleEvaluationSignal {
	return correlationEvaluationSignals([]domain.TimelineEvent{
		prestashopEmployeeEntityEvent("evt-ps-employee", now),
	}, 30*time.Minute)
}

func evaluateBrowserScriptInjectionFixture(now time.Time) []RuleEvaluationSignal {
	return browserDriftEvaluationSignals(
		[]domain.TimelineEvent{
			evaluationBrowserScriptEvent("evt-browser-baseline-domain", now.Add(-48*time.Hour), "https://example.test", map[string]any{
				"source_type": "network",
				"domain":      "static.example.test",
				"url":         "https://static.example.test/app.js",
			}),
			evaluationBrowserScriptEvent("evt-browser-baseline-inline", now.Add(-47*time.Hour), "https://example.test", map[string]any{
				"source_type": "inline",
				"sha256":      "old-inline",
			}),
			evaluationBrowserScriptEvent("evt-browser-baseline-tag", now.Add(-46*time.Hour), "https://example.test", map[string]any{
				"source_type":     "network",
				"domain":          "www.googletagmanager.com",
				"tag_manager_ids": []string{"GTM-OLD"},
			}),
		},
		[]domain.TimelineEvent{
			evaluationBrowserScriptEvent("evt-browser-new-domain", now, "https://example.test", map[string]any{
				"source_type": "network",
				"domain":      "cdn.bad.example",
				"url":         "https://cdn.bad.example/payload.js",
			}),
			evaluationBrowserScriptEvent("evt-browser-new-inline", now.Add(time.Minute), "https://example.test", map[string]any{
				"source_type": "inline",
				"sha256":      "new-inline",
			}),
			evaluationBrowserScriptEvent("evt-browser-new-tag", now.Add(2*time.Minute), "https://example.test", map[string]any{
				"source_type":     "network",
				"domain":          "www.googletagmanager.com",
				"tag_manager_ids": []string{"GTM-NEW"},
			}),
		},
	)
}

func evaluateDeployWindowBrowserDriftFixture(now time.Time) []RuleEvaluationSignal {
	drifts := detectBrowserScriptDrifts(
		[]domain.TimelineEvent{
			evaluationBrowserScriptEvent("evt-deploy-baseline-domain", now.Add(-48*time.Hour), "https://example.test", map[string]any{
				"source_type": "network",
				"domain":      "static.example.test",
			}),
		},
		[]domain.TimelineEvent{
			evaluationBrowserScriptEvent("evt-deploy-new-domain", now, "https://example.test", map[string]any{
				"source_type": "network",
				"domain":      "cdn.release.example",
			}),
		},
		nil,
	)
	findings := browserScriptDriftFindings(evaluationOrganization(), evaluationProject(), evaluationEnvironment(), evaluationApp(), drifts)
	deployment := domain.DeploymentMarker{
		ID:            "deploy-release",
		EnvironmentID: "env-production",
		AppID:         "app-main-web",
		Version:       "v1.8.2",
		Actor:         "github-actions",
		StartedAt:     now.Add(-10 * time.Minute),
	}
	signals := make([]RuleEvaluationSignal, 0, len(findings))
	for _, finding := range findings {
		signals = append(signals, findingEvaluationSignal(applyDeploymentScoring(finding, []domain.DeploymentMarker{deployment}), "hub.deployment_scoring"))
	}
	return signals
}

func evaluateMultiHostFileDriftFixture(now time.Time) []RuleEvaluationSignal {
	difference, ok := buildFileBaselineDifference("index.php", map[string]domain.FileStateObservation{
		"web-01": {
			HostSlug:     "web-01",
			EventTime:    now,
			RelativePath: "index.php",
			Path:         "/var/www/example.com/index.php",
			SHA256:       "aaa111",
			Severity:     domain.SeverityInfo,
		},
		"web-02": {
			HostSlug:     "web-02",
			EventTime:    now,
			RelativePath: "index.php",
			Path:         "/var/www/example.com/index.php",
			SHA256:       "zzz999",
			Severity:     domain.SeverityMedium,
		},
	}, 2)
	if !ok {
		return nil
	}
	return []RuleEvaluationSignal{
		{
			ID:         "file-baseline-drift",
			Source:     "hub.file_baseline",
			Severity:   difference.Severity,
			Confidence: domain.ConfidenceHigh,
			Summary:    difference.RelativePath + ": " + difference.Reason,
		},
	}
}

func correlationEvaluationSignals(events []domain.TimelineEvent, window time.Duration) []RuleEvaluationSignal {
	chains := correlateTimelineEvents(events, window)
	signals := make([]RuleEvaluationSignal, 0, len(chains))
	for _, chain := range chains {
		signals = append(signals, RuleEvaluationSignal{
			ID:         chain.RuleID,
			Source:     "hub.correlation",
			Severity:   chain.Severity,
			Confidence: chain.Confidence,
			Summary:    chain.Summary,
		})
	}
	sortEvaluationSignals(signals)
	return signals
}

func browserDriftEvaluationSignals(baseline []domain.TimelineEvent, observed []domain.TimelineEvent) []RuleEvaluationSignal {
	drifts := detectBrowserScriptDrifts(baseline, observed, nil)
	signals := make([]RuleEvaluationSignal, 0, len(drifts))
	for _, drift := range drifts {
		signals = append(signals, RuleEvaluationSignal{
			ID:         drift.RuleID,
			Source:     "hub.browser_script",
			Severity:   drift.Severity,
			Confidence: drift.Confidence,
			Summary:    drift.Description,
		})
	}
	sortEvaluationSignals(signals)
	return signals
}

func findingEvaluationSignal(finding domain.HubFinding, source string) RuleEvaluationSignal {
	return RuleEvaluationSignal{
		ID:         finding.RuleID,
		Source:     source,
		Severity:   finding.Severity,
		Confidence: finding.Confidence,
		Summary:    finding.Summary,
	}
}

func wordpressUserEntityEvent(id string, eventTime time.Time, eventType string, currentAdmin bool, previousAdmin bool) domain.TimelineEvent {
	payload := map[string]any{
		"database":    "wordpress",
		"profile":     "wordpress",
		"entity_type": "wordpress_user",
		"entity_key":  "wordpress_user:fixture",
		"current": map[string]any{
			"type":       "wordpress_user",
			"key":        "wordpress_user:fixture",
			"privileged": currentAdmin,
			"signature":  "sig-admin-current",
			"attributes": map[string]any{
				"administrator":     currentAdmin,
				"account_display":   "f***e@example.com",
				"email_masked":      "f***e@example.com",
				"email_hmac_sha256": "fingerprint-current",
			},
		},
	}
	if eventType == "db.entity.changed" || eventType == "db.entity.removed" {
		payload["previous"] = map[string]any{
			"type":       "wordpress_user",
			"key":        "wordpress_user:fixture",
			"privileged": previousAdmin,
			"signature":  "sig-admin-previous",
			"attributes": map[string]any{
				"administrator":     previousAdmin,
				"account_display":   "f***e@example.com",
				"email_masked":      "f***e@example.com",
				"email_hmac_sha256": "fingerprint-previous",
			},
		}
	}
	return evaluationTimelineEvent(id, eventTime, eventType, "wordpress:wordpress_user:wordpress_user:fixture", domain.SeverityHigh, payload)
}

func prestashopModuleEntityEvent(id string, eventTime time.Time) domain.TimelineEvent {
	return evaluationTimelineEvent(id, eventTime, "db.entity.added", "prestashop:prestashop_module:ps_checkout", domain.SeverityMedium, map[string]any{
		"database":    "prestashop",
		"profile":     "prestashop",
		"entity_type": "prestashop_module",
		"entity_key":  "prestashop_module:ps_checkout",
		"current": map[string]any{
			"type":       "prestashop_module",
			"key":        "prestashop_module:ps_checkout",
			"label":      "ps_checkout",
			"signature":  "sig-module",
			"attributes": map[string]any{"active": true, "module_name": "ps_checkout"},
		},
	})
}

func prestashopEmployeeEntityEvent(id string, eventTime time.Time) domain.TimelineEvent {
	return evaluationTimelineEvent(id, eventTime, "db.entity.changed", "prestashop:prestashop_employee:fixture", domain.SeverityHigh, map[string]any{
		"database":    "prestashop",
		"profile":     "prestashop",
		"entity_type": "prestashop_employee",
		"entity_key":  "prestashop_employee:fixture",
		"previous": map[string]any{
			"type":       "prestashop_employee",
			"key":        "prestashop_employee:fixture",
			"signature":  "sig-employee-old",
			"attributes": map[string]any{"super_admin": false},
		},
		"current": map[string]any{
			"type":       "prestashop_employee",
			"key":        "prestashop_employee:fixture",
			"signature":  "sig-employee-new",
			"attributes": map[string]any{"super_admin": true},
		},
	})
}

func evaluationTimelineEvent(id string, eventTime time.Time, eventType string, target string, severity domain.Severity, payload map[string]any) domain.TimelineEvent {
	return domain.TimelineEvent{
		ID:            domain.ID(id),
		EnvironmentID: "env-production",
		AppID:         "app-main-web",
		AppSlug:       "main-web",
		HostID:        "host-web-01",
		HostSlug:      "web-01",
		EventTime:     eventTime.UTC(),
		EventType:     eventType,
		Target:        target,
		Severity:      severity,
		Payload:       payload,
	}
}

func evaluationBrowserScriptEvent(id string, eventTime time.Time, pageURL string, payload map[string]any) domain.TimelineEvent {
	payload = cloneAnyMap(payload)
	payload["page_url"] = pageURL
	payload["final_url"] = pageURL
	return evaluationTimelineEvent(id, eventTime, "browser.script.observed", payloadStringAny(payload, "url", pageURL), domain.SeverityInfo, payload)
}

func evaluationAdminAccessEvent(id string, eventTime time.Time, method string, path string, status int, remoteAddr string) domain.TimelineEvent {
	return evaluationAccessEvent(id, eventTime, method, path, status, remoteAddr, nil)
}

func evaluationAccessEvent(id string, eventTime time.Time, method string, path string, status int, remoteAddr string, extraPayload map[string]any) domain.TimelineEvent {
	payload := map[string]any{
		"method":      method,
		"path":        path,
		"status_code": status,
		"remote_addr": remoteAddr,
	}
	for key, value := range extraPayload {
		payload[key] = value
	}
	return evaluationTimelineEvent(id, eventTime, "log.access", "access.log", domain.SeverityInfo, payload)
}

func evaluationOrganization() domain.Organization {
	return domain.Organization{ID: "org-acme", Slug: "acme", Name: "Acme"}
}

func evaluationProject() domain.Project {
	return domain.Project{ID: "project-customer-site", OrganizationID: "org-acme", Slug: "customer-site", Name: "Customer Site"}
}

func evaluationEnvironment() domain.Environment {
	return domain.Environment{ID: "env-production", ProjectID: "project-customer-site", Slug: "production", Name: "Production"}
}

func evaluationApp() domain.MonitoredApp {
	return domain.MonitoredApp{ID: "app-main-web", EnvironmentID: "env-production", Slug: "main-web", Name: "Main Web", Kind: "wordpress"}
}

func cloneExpectedEvaluationSignals(signals []RuleEvaluationExpectedSignal) []RuleEvaluationExpectedSignal {
	return append([]RuleEvaluationExpectedSignal(nil), signals...)
}

func cloneEvaluationSignals(signals []RuleEvaluationSignal) []RuleEvaluationSignal {
	return append([]RuleEvaluationSignal(nil), signals...)
}

func sortExpectedEvaluationSignals(signals []RuleEvaluationExpectedSignal) {
	slices.SortFunc(signals, func(a RuleEvaluationExpectedSignal, b RuleEvaluationExpectedSignal) int {
		return strings.Compare(a.ID, b.ID)
	})
}

func sortEvaluationSignals(signals []RuleEvaluationSignal) {
	slices.SortFunc(signals, func(a RuleEvaluationSignal, b RuleEvaluationSignal) int {
		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}
		return strings.Compare(a.Source, b.Source)
	})
}
