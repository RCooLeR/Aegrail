package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
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
  <script src="/wp-content/plugins/builder/app.js?token=secret&v=1" async defer></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    window.dataLayer.push({'gtm.start': new Date().getTime(), event:'gtm.js'});
    var id = 'GTM-ABC123';
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
	if !page.Scripts[2].TagManager || len(page.Scripts[2].TagManagerIDs) != 1 || page.Scripts[2].TagManagerIDs[0] != "GTM-ABC123" {
		t.Fatalf("tag manager script = %#v", page.Scripts[2])
	}
	if len(page.Warnings) == 0 {
		t.Fatal("expected tag manager rendered-mode warning")
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
