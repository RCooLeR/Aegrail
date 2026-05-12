package collector

import (
	"testing"
	"time"
)

func TestBuildBrowserCrawlEventsEmitsPageScriptTagManagerAndWarnings(t *testing.T) {
	finishedAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	result := BrowserCrawlResult{
		StartedAt:  finishedAt.Add(-2 * time.Second),
		FinishedAt: finishedAt,
		Pages: []BrowserPageResult{
			{
				URL:        "https://example.test/",
				FinalURL:   "https://example.test/",
				Mode:       browserCrawlModeRendered,
				StatusCode: 200,
				Title:      "Demo",
				Scripts: []BrowserScriptObservation{
					{
						SourceType:        "dom",
						URL:               "https://www.googletagmanager.com/gtm.js?id=GTM-ABC123",
						URLRedacted:       "https://www.googletagmanager.com/gtm.js?id=GTM-ABC123",
						Domain:            "www.googletagmanager.com",
						Path:              "/gtm.js",
						ResponseStatus:    200,
						ContentType:       "application/javascript",
						TagManager:        true,
						TagManagerIDs:     []string{"GTM-ABC123"},
						DynamicallyLoaded: true,
					},
				},
				Warnings: []string{"tag manager readiness wait timed out; continuing with observed scripts"},
			},
		},
	}

	events := BuildBrowserCrawlEvents(result, map[string]string{"site": "main"})
	if len(events) != 4 {
		t.Fatalf("events = %#v, want page + script + tag manager + warning", events)
	}
	if events[0].Type != "browser.crawl.completed" || events[0].Severity != "info" {
		t.Fatalf("page event = %#v", events[0])
	}
	if events[1].Type != "browser.script.observed" || events[1].Labels["script_domain"] != "www.googletagmanager.com" {
		t.Fatalf("script event = %#v", events[1])
	}
	if events[2].Type != "browser.tag_manager.detected" || events[2].Severity != "low" {
		t.Fatalf("tag manager event = %#v", events[2])
	}
	if events[3].Type != "browser.coverage.warning" || events[3].Severity != "medium" {
		t.Fatalf("warning event = %#v", events[3])
	}
	if events[1].Payload["tag_manager_ids"] == nil {
		t.Fatalf("script payload should carry tag manager IDs: %#v", events[1].Payload)
	}
	if events[1].Payload["url"] != "https://www.googletagmanager.com/gtm.js?id=GTM-ABC123" {
		t.Fatalf("script payload URL = %#v", events[1].Payload)
	}
}
