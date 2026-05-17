package reports

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestBuildEvidenceBundleRedactsAndCompactsFindingMetadata(t *testing.T) {
	generatedAt := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	eventTime := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	report := BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production", App: "main-web"},
		[]domain.HubFinding{
			{
				ID:           "finding-1",
				RuleID:       "browser-script-domain-new",
				RuleVersion:  "2026-05-12.1",
				DedupeKey:    "browser-drift-1",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceHigh,
				Title:        "New browser script domain",
				Summary:      "Observed https://cdn.example.test/app.js?token=abc123 on checkout",
				Description:  "Cookie: PHPSESSID=secret-session",
				EventIDs:     []domain.ID{"evt-script"},
				FirstEventAt: eventTime,
				LastEventAt:  eventTime,
				Metadata: map[string]any{
					"events": []map[string]any{
						{
							"event_id":   "evt-script",
							"event_time": eventTime.Format(time.RFC3339),
							"host":       "web-01",
							"type":       "browser.script.observed",
							"target":     "https://cdn.example.test/app.js?access_token=token-secret&safe=yes",
							"message":    "authorization=Bearer top-secret",
						},
					},
					"payload": map[string]any{
						"url":           "https://cdn.example.test/app.js?token=abc123&safe=yes",
						"Authorization": "Bearer top-secret",
						"safe":          "kept",
					},
					"risk": map[string]any{
						"score": 92,
						"band":  "critical",
						"factors": []map[string]any{
							{"id": "rule:tag_manager_new", "points": 5, "reason": "new tag manager container"},
						},
					},
					"rule": map[string]any{
						"id":        "browser-script-domain-new",
						"category":  "browser_script",
						"platforms": []string{"web"},
					},
					"deployment_context": map[string]any{
						"active": true,
						"deployments": []map[string]any{
							{"version": "v1.8.2", "actor": "github-actions"},
						},
					},
				},
				CreatedAt: eventTime,
				UpdatedAt: eventTime,
			},
		},
		generatedAt,
	)

	bundle, err := BuildEvidenceBundle(report, EvidenceBundleOptions{MaxStringLength: 120})
	if err != nil {
		t.Fatalf("BuildEvidenceBundle returned error: %v", err)
	}
	if bundle.Schema != EvidenceBundleSchema || bundle.BundleSHA256 == "" || bundle.FindingCount != 1 {
		t.Fatalf("bundle = %#v, want schema, hash, and one finding", bundle)
	}
	if bundle.Findings[0].RiskFactors[0]["id"] != "rule:tag_manager_new" {
		t.Fatalf("risk factors = %#v, want scoring factor", bundle.Findings[0].RiskFactors)
	}
	if bundle.Findings[0].MetadataExcerpt["payload"].(map[string]any)["safe"] != "kept" {
		t.Fatalf("metadata excerpt = %#v, want safe value preserved", bundle.Findings[0].MetadataExcerpt)
	}

	var encoded bytes.Buffer
	if err := WriteEvidenceBundleJSON(&encoded, bundle, true); err != nil {
		t.Fatalf("WriteEvidenceBundleJSON returned error: %v", err)
	}
	content := encoded.String()
	for _, secret := range []string{"abc123", "token-secret", "top-secret", "PHPSESSID=secret-session"} {
		if strings.Contains(content, secret) {
			t.Fatalf("bundle still contains secret %q:\n%s", secret, content)
		}
	}
	for _, expected := range []string{"[REDACTED]", "safe=yes", "finding-1", "evt-script"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("bundle missing %q:\n%s", expected, content)
		}
	}

	var decoded EvidenceBundle
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if decoded.BundleSHA256 != bundle.BundleSHA256 {
		t.Fatalf("decoded hash = %s, want %s", decoded.BundleSHA256, bundle.BundleSHA256)
	}
}

func TestBuildEvidenceBundleHashIsStable(t *testing.T) {
	generatedAt := time.Date(2026, 5, 12, 14, 0, 0, 0, time.UTC)
	report := BuildHubFindingsJSONReport(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		HubFindingsScope{Organization: "acme", Project: "customer-site", Environment: "production"},
		[]domain.HubFinding{{
			ID:           "finding-1",
			RuleID:       "file-php-in-writable-path",
			RuleVersion:  "2026-05-12.1",
			Severity:     domain.SeverityHigh,
			Confidence:   domain.ConfidenceHigh,
			Title:        "PHP executable in writable path",
			Summary:      "web-01 file.created uploads/avatar.php",
			EventIDs:     []domain.ID{"evt-file"},
			FirstEventAt: generatedAt,
			LastEventAt:  generatedAt,
			CreatedAt:    generatedAt,
			UpdatedAt:    generatedAt,
		}},
		generatedAt,
	)

	first, err := BuildEvidenceBundle(report, EvidenceBundleOptions{})
	if err != nil {
		t.Fatalf("first BuildEvidenceBundle returned error: %v", err)
	}
	second, err := BuildEvidenceBundle(report, EvidenceBundleOptions{})
	if err != nil {
		t.Fatalf("second BuildEvidenceBundle returned error: %v", err)
	}
	if first.BundleSHA256 != second.BundleSHA256 {
		t.Fatalf("hashes differ: %s != %s", first.BundleSHA256, second.BundleSHA256)
	}
}
