package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrawlBrowserPagesInventoriesInitialScripts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html>
<head>
  <title>Demo Site</title>
  <link rel="canonical" href="/canonical">
  <link rel="icon" sizes="32x32" type="image/png" href="/wp-content/uploads/site-icon.png?token=secret&v=1">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <script src="/wp-content/plugins/builder/app.js?token=secret&v=1" async defer></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    window.dataLayer.push({'gtm.start': new Date().getTime(), event:'gtm.js'});
    var id = 'GTM-ABC123';
    var access_token = "should-not-leak";
  </script>
  <script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>
</head>
<body>Hello</body>
</html>`))
	}))
	defer server.Close()

	runtime := NewRuntime(Config{Name: "test"})
	result, err := runtime.CrawlBrowserPages(context.Background(), BrowserCrawlInput{
		URLs:    []string{server.URL + "/"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("CrawlBrowserPages returned error: %v", err)
	}
	if len(result.Pages) != 1 {
		t.Fatalf("pages = %d, want 1", len(result.Pages))
	}
	page := result.Pages[0]
	if page.Title != "Demo Site" {
		t.Fatalf("title = %q, want Demo Site", page.Title)
	}
	if page.CanonicalURL != server.URL+"/canonical" {
		t.Fatalf("canonical = %q", page.CanonicalURL)
	}
	if len(page.Icons) != 2 {
		t.Fatalf("icons = %#v, want 2 declared icons", page.Icons)
	}
	if page.Icons[0].Rel != "icon" || page.Icons[0].URLRedacted != server.URL+"/wp-content/uploads/site-icon.png" {
		t.Fatalf("icon URL = %#v, want origin plus path without query material", page.Icons[0])
	}
	if page.Icons[0].Sizes != "32x32" || page.Icons[0].Type != "image/png" {
		t.Fatalf("icon metadata = %#v, want size/type", page.Icons[0])
	}
	if len(page.Scripts) != 3 {
		t.Fatalf("scripts = %#v, want 3", page.Scripts)
	}
	if page.Scripts[0].Domain != "127.0.0.1" || page.Scripts[0].Path != "/wp-content/plugins/builder/app.js" {
		t.Fatalf("external script = %#v", page.Scripts[0])
	}
	if page.Scripts[0].URLRedacted == "" || page.Scripts[0].URLRedacted == page.Scripts[0].URL {
		t.Fatalf("script URL was not redacted: %#v", page.Scripts[0])
	}
	if page.Scripts[1].SourceType != "inline" || page.Scripts[1].SHA256 == "" || !page.Scripts[1].TagManager {
		t.Fatalf("inline script = %#v", page.Scripts[1])
	}
	if !strings.Contains(page.Scripts[1].InlinePreview, "window.dataLayer") || !strings.Contains(page.Scripts[1].InlinePreview, "[REDACTED]") {
		t.Fatalf("inline preview = %q, want useful redacted script", page.Scripts[1].InlinePreview)
	}
	if strings.Contains(page.Scripts[1].InlinePreview, "should-not-leak") {
		t.Fatalf("inline preview leaked sensitive material: %q", page.Scripts[1].InlinePreview)
	}
	if !page.Scripts[2].TagManager || len(page.Scripts[2].TagManagerIDs) != 1 || page.Scripts[2].TagManagerIDs[0] != "GTM-ABC123" {
		t.Fatalf("tag manager script = %#v", page.Scripts[2])
	}
	if len(page.Warnings) == 0 {
		t.Fatal("expected tag manager rendered-mode warning")
	}
	if !strings.Contains(page.UserAgent, "AegrailBot/") {
		t.Fatalf("user agent = %q, want named Aegrail bot", page.UserAgent)
	}
}

func TestCrawlBrowserPagesFallsBackWhenNamedBotIsBlocked(t *testing.T) {
	var observed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = append(observed, r.UserAgent())
		if strings.Contains(r.UserAgent(), "AegrailBot/") {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><head><title>OK</title><script src="/app.js"></script></head></html>`))
	}))
	defer server.Close()

	runtime := NewRuntime(Config{Name: "test"})
	result, err := runtime.CrawlBrowserPages(context.Background(), BrowserCrawlInput{
		FallbackUserAgents: []string{"Mozilla/5.0 TestChrome/1.0"},
		URLs:               []string{server.URL + "/"},
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("CrawlBrowserPages returned error: %v", err)
	}
	if len(observed) != 2 || !strings.Contains(observed[0], "AegrailBot/") || observed[1] != "Mozilla/5.0 TestChrome/1.0" {
		t.Fatalf("observed user agents = %#v", observed)
	}
	if len(result.Pages) != 1 || result.Pages[0].StatusCode != http.StatusOK || result.Pages[0].UserAgent != "Mozilla/5.0 TestChrome/1.0" {
		t.Fatalf("result = %#v, want successful fallback crawl", result)
	}
	if len(result.Pages[0].Warnings) == 0 || !strings.Contains(result.Pages[0].Warnings[0], "fallback used") {
		t.Fatalf("warnings = %#v, want fallback note", result.Pages[0].Warnings)
	}
}

func TestCrawlBrowserPagesRecordsBadURLWarning(t *testing.T) {
	runtime := NewRuntime(Config{Name: "test"})
	result, err := runtime.CrawlBrowserPages(context.Background(), BrowserCrawlInput{URLs: []string{"://bad"}})
	if err != nil {
		t.Fatalf("CrawlBrowserPages returned error: %v", err)
	}
	if len(result.Pages) != 1 || len(result.Pages[0].Warnings) == 0 {
		t.Fatalf("result = %#v, want warning for bad URL", result)
	}
}
