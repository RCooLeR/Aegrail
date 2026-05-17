package collector

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rcooler/aegrail/agent/internal/redaction"
)

type BrowserCrawlEvent struct {
	EventTime time.Time
	Type      string
	Target    string
	Severity  string
	Message   string
	Labels    map[string]string
	Payload   map[string]any
}

func BuildBrowserCrawlEvents(result BrowserCrawlResult, baseLabels map[string]string) []BrowserCrawlEvent {
	eventTime := result.FinishedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	events := make([]BrowserCrawlEvent, 0)
	for _, page := range result.Pages {
		pageURL := redactedBrowserURL(page.URL)
		finalURL := redactedBrowserURL(page.FinalURL)
		pageTarget := nonEmptyString(finalURL, pageURL)
		pageLabels := browserEventLabels(baseLabels, map[string]string{
			"collector": "browser",
			"mode":      page.Mode,
			"page_host": hostLabel(page.FinalURL),
		})
		pagePayload := map[string]any{
			"page_url":        pageURL,
			"final_url":       finalURL,
			"mode":            page.Mode,
			"user_agent":      page.UserAgent,
			"status_code":     page.StatusCode,
			"title":           page.Title,
			"canonical_url":   redactedBrowserURL(page.CanonicalURL),
			"site_icons":      browserIconPayload(page.Icons),
			"script_count":    len(page.Scripts),
			"warning_count":   len(page.Warnings),
			"run_started_at":  result.StartedAt.Format(time.RFC3339Nano),
			"run_finished_at": result.FinishedAt.Format(time.RFC3339Nano),
		}
		if len(page.Warnings) > 0 {
			pagePayload["warnings"] = page.Warnings
		}
		events = append(events, BrowserCrawlEvent{
			EventTime: eventTime,
			Type:      "browser.crawl.completed",
			Target:    pageTarget,
			Severity:  "info",
			Message:   fmt.Sprintf("Browser crawl completed for %s with %d script(s)", pageTarget, len(page.Scripts)),
			Labels:    pageLabels,
			Payload:   pagePayload,
		})

		for _, script := range page.Scripts {
			scriptTarget := scriptEventTarget(page, script)
			scriptLabels := browserEventLabels(pageLabels, map[string]string{
				"script_source_type": script.SourceType,
				"script_domain":      script.Domain,
				"tag_manager":        boolLabel(script.TagManager),
			})
			scriptURL := redactedBrowserScriptURL(script)
			payload := map[string]any{
				"page_url":           pageURL,
				"final_url":          finalURL,
				"mode":               page.Mode,
				"user_agent":         page.UserAgent,
				"source_type":        script.SourceType,
				"url":                scriptURL,
				"url_redacted":       scriptURL,
				"domain":             script.Domain,
				"path":               script.Path,
				"sha256":             script.SHA256,
				"inline_bytes":       script.InlineBytes,
				"initiator":          script.Initiator,
				"response_status":    script.ResponseStatus,
				"content_type":       script.ContentType,
				"attributes":         redactedBrowserAttributes(script.Attributes),
				"tag_manager":        script.TagManager,
				"tag_manager_ids":    script.TagManagerIDs,
				"initial_html":       script.InitialHTML,
				"dynamically_loaded": script.DynamicallyLoaded,
			}
			events = append(events, BrowserCrawlEvent{
				EventTime: eventTime,
				Type:      "browser.script.observed",
				Target:    scriptTarget,
				Severity:  "info",
				Message:   fmt.Sprintf("Browser observed %s script on %s", nonEmptyString(script.SourceType, "unknown"), pageTarget),
				Labels:    scriptLabels,
				Payload:   payload,
			})
			if script.TagManager {
				events = append(events, BrowserCrawlEvent{
					EventTime: eventTime,
					Type:      "browser.tag_manager.detected",
					Target:    scriptTarget,
					Severity:  "low",
					Message:   fmt.Sprintf("Browser crawl detected tag manager on %s", pageTarget),
					Labels:    scriptLabels,
					Payload:   payload,
				})
			}
		}

		for _, warning := range page.Warnings {
			events = append(events, BrowserCrawlEvent{
				EventTime: eventTime,
				Type:      "browser.coverage.warning",
				Target:    pageTarget,
				Severity:  browserWarningSeverity(page, warning),
				Message:   warning,
				Labels:    pageLabels,
				Payload: map[string]any{
					"page_url":    pageURL,
					"final_url":   finalURL,
					"mode":        page.Mode,
					"user_agent":  page.UserAgent,
					"status_code": page.StatusCode,
					"warning":     warning,
				},
			})
		}
	}
	return events
}

func browserIconPayload(icons []BrowserIconObservation) []map[string]string {
	if len(icons) == 0 {
		return nil
	}
	payload := make([]map[string]string, 0, len(icons))
	for _, icon := range icons {
		entry := map[string]string{
			"rel":          icon.Rel,
			"url_redacted": icon.URLRedacted,
		}
		if icon.Domain != "" {
			entry["domain"] = icon.Domain
		}
		if icon.Path != "" {
			entry["path"] = icon.Path
		}
		if icon.Sizes != "" {
			entry["sizes"] = icon.Sizes
		}
		if icon.Type != "" {
			entry["type"] = icon.Type
		}
		payload = append(payload, entry)
	}
	return payload
}

func browserEventLabels(base map[string]string, extra map[string]string) map[string]string {
	labels := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		key = strings.TrimSpace(key)
		if key != "" {
			labels[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range extra {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			labels[key] = value
		}
	}
	return labels
}

func scriptEventTarget(page BrowserPageResult, script BrowserScriptObservation) string {
	if script.URLRedacted != "" {
		return script.URLRedacted
	}
	if script.URL != "" {
		return redactedBrowserURL(script.URL)
	}
	if script.SHA256 != "" {
		return nonEmptyString(page.FinalURL, page.URL) + "#inline-" + shortBrowserHash(script.SHA256)
	}
	return nonEmptyString(page.FinalURL, page.URL) + "#inline"
}

func redactedBrowserURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return redaction.RedactURL(value)
}

func redactedBrowserScriptURL(script BrowserScriptObservation) string {
	if script.URLRedacted != "" {
		return script.URLRedacted
	}
	return redactedBrowserURL(script.URL)
}

func redactedBrowserAttributes(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	redacted := make(map[string]string, len(attrs))
	for key, value := range attrs {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		redacted[key] = redaction.RedactText(redaction.RedactURL(value))
	}
	if len(redacted) == 0 {
		return nil
	}
	return redacted
}

func shortBrowserHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func hostLabel(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func boolLabel(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func nonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func browserWarningSeverity(page BrowserPageResult, warning string) string {
	lower := strings.ToLower(warning)
	if page.StatusCode >= 500 ||
		strings.Contains(lower, "failed") ||
		strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "timeout") {
		return "medium"
	}
	return "low"
}
