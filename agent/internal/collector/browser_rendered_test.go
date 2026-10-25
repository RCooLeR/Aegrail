package collector

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

type renderedShutdownContextKey struct{}

func TestRenderedChromeShutdownContextSurvivesParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), renderedShutdownContextKey{}, "crawl-42"))
	cancelParent()

	shutdownCtx, cancelShutdown := newRenderedChromeShutdownContext(parent)
	defer cancelShutdown()

	if err := shutdownCtx.Err(); err != nil {
		t.Fatalf("shutdown context inherited cancellation: %v", err)
	}
	if got := shutdownCtx.Value(renderedShutdownContextKey{}); got != "crawl-42" {
		t.Fatalf("shutdown context value = %v, want crawl-42", got)
	}
	deadline, ok := shutdownCtx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > renderedChromeShutdownTimeout {
		t.Fatalf("shutdown deadline = %v, want within %s", deadline, renderedChromeShutdownTimeout)
	}
}

func TestRenderedChromeRuntimeCreatesWritableDirs(t *testing.T) {
	base := t.TempDir()
	t.Setenv("AEGRAIL_BROWSER_TMP_DIR", base)

	runtime, err := newRenderedChromeRuntime()
	if err != nil {
		t.Fatalf("newRenderedChromeRuntime returned error: %v", err)
	}
	defer runtime.Cleanup()

	for _, path := range []string{runtime.Root, runtime.Home, runtime.ConfigHome, runtime.CacheHome, runtime.UserData, runtime.CrashDumps} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s returned error: %v", path, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", path)
		}
		if err := os.WriteFile(filepath.Join(path, "write-test"), []byte("ok"), 0o600); err != nil {
			t.Fatalf("%s is not writable: %v", path, err)
		}
	}
	if !strings.HasPrefix(runtime.Root, base) {
		t.Fatalf("root = %q, want under %q", runtime.Root, base)
	}
}

func TestRenderedChromeRuntimeEnvAndExecPath(t *testing.T) {
	t.Setenv("AEGRAIL_BROWSER_CHROME_PATH", "/usr/bin/chromium")
	if got := renderedChromeExecPath(); got != "/usr/bin/chromium" {
		t.Fatalf("exec path = %q, want env override", got)
	}

	runtime := renderedChromeRuntime{
		Root:       "/tmp/aegrail-chrome",
		Home:       "/tmp/aegrail-chrome/home",
		ConfigHome: "/tmp/aegrail-chrome/config",
		CacheHome:  "/tmp/aegrail-chrome/cache",
	}
	env := strings.Join(renderedChromeEnvVars(runtime), "\n")
	for _, expected := range []string{
		"HOME=/tmp/aegrail-chrome/home",
		"XDG_CONFIG_HOME=/tmp/aegrail-chrome/config",
		"XDG_CACHE_HOME=/tmp/aegrail-chrome/cache",
		"TMPDIR=/tmp/aegrail-chrome",
	} {
		if !strings.Contains(env, expected) {
			t.Fatalf("env = %q, missing %q", env, expected)
		}
	}
}

func TestConsumeRenderedNetworkEventsUpdatesObservedState(t *testing.T) {
	state := newRenderedNetworkState()
	requestID := network.RequestID("request-1")
	requestURL := "https://example.test/app.js"

	// Each CDP event type has its own typed iterator. Exercise an interleaving
	// where completion is consumed before the request so scheduling cannot leave
	// a completed request marked active or discard response metadata.
	consumeRenderedNetworkEvents(func(yield func(network.EventResponseReceived, error) bool) {
		yield(network.EventResponseReceived{
			RequestID: requestID,
			Type:      network.ResourceTypeDocument,
			Response: &network.Response{
				URL:      requestURL,
				Status:   200,
				MimeType: "application/javascript",
			},
		}, nil)
	}, state)
	consumeRenderedNetworkEvents(func(yield func(network.EventLoadingFinished, error) bool) {
		yield(network.EventLoadingFinished{RequestID: requestID}, nil)
	}, state)
	consumeRenderedNetworkEvents(func(yield func(network.EventRequestWillBeSent, error) bool) {
		yield(network.EventRequestWillBeSent{
			RequestID: requestID,
			Request:   &network.Request{URL: requestURL},
			Initiator: &network.Initiator{Type: network.InitiatorTypeParser},
		}, nil)
	}, state)

	if len(state.active) != 0 {
		t.Fatalf("active requests = %v, want none", state.active)
	}
	if got := state.documentStatus(); got != 200 {
		t.Fatalf("document status = %d, want 200", got)
	}
	if got := state.documentURL(""); got != requestURL {
		t.Fatalf("document URL = %q, want %q", got, requestURL)
	}
	script := state.scriptResponses()[requestURL]
	if script.Initiator != "parser" || script.ResponseStatus != 200 || script.ContentType != "application/javascript" {
		t.Fatalf("script observation = %#v", script)
	}
}

func TestConsumeRenderedNetworkEventsHandlesRedirectAfterEarlyCompletion(t *testing.T) {
	state := newRenderedNetworkState()
	requestID := network.RequestID("redirected-script")
	originalURL := "https://example.test/app.js"
	finalURL := "https://cdn.example.test/app.v2.js"

	consumeRenderedNetworkEvents(func(yield func(network.EventResponseReceived, error) bool) {
		yield(network.EventResponseReceived{
			RequestID: requestID,
			Type:      network.ResourceTypeScript,
			Response: &network.Response{
				URL:      finalURL,
				Status:   200,
				MimeType: "application/javascript",
			},
		}, nil)
	}, state)
	consumeRenderedNetworkEvents(func(yield func(network.EventLoadingFinished, error) bool) {
		yield(network.EventLoadingFinished{RequestID: requestID}, nil)
	}, state)
	consumeRenderedNetworkEvents(func(yield func(network.EventRequestWillBeSent, error) bool) {
		yield(network.EventRequestWillBeSent{
			RequestID: requestID,
			Type:      network.ResourceTypeScript,
			Request:   &network.Request{URL: originalURL},
			Initiator: &network.Initiator{Type: network.InitiatorTypeParser},
		}, nil)
		yield(network.EventRequestWillBeSent{
			RequestID: requestID,
			Type:      network.ResourceTypeScript,
			Request:   &network.Request{URL: finalURL},
			Initiator: &network.Initiator{Type: network.InitiatorTypeParser},
			RedirectResponse: &network.Response{
				URL:      originalURL,
				Status:   302,
				MimeType: "text/html",
			},
		}, nil)
	}, state)

	if len(state.active) != 0 {
		t.Fatalf("active requests = %v, want none", state.active)
	}
	scripts := state.scriptResponses()
	if got := scripts[originalURL].ResponseStatus; got != 302 {
		t.Fatalf("redirect response status = %d, want 302", got)
	}
	final := scripts[finalURL]
	if final.Initiator != "parser" || final.ResponseStatus != 200 || final.ContentType != "application/javascript" {
		t.Fatalf("final script observation = %#v", final)
	}
}

func TestBuildRenderedScriptObservationsMergesDOMAndNetworkScripts(t *testing.T) {
	baseURL, err := url.Parse("https://example.test/page")
	if err != nil {
		t.Fatal(err)
	}

	snapshot := renderedPageSnapshot{
		FinalURL: "https://example.test/page",
		Scripts: []renderedDOMScript{
			{
				SourceType: "dom",
				URL:        "/wp-content/plugins/builder/app.js?token=secret&v=1",
				Attributes: map[string]string{
					"src":   "/wp-content/plugins/builder/app.js?token=secret&v=1",
					"async": "",
				},
			},
			{
				SourceType: "inline",
				Text:       "window.dataLayer = window.dataLayer || []; var id = 'GTM-TEST1';",
			},
		},
		Resources: []renderedResource{
			{URL: "https://cdn.example.test/late-widget.js", Initiator: "script"},
		},
	}
	networkScripts := map[string]renderedNetworkScript{
		"https://example.test/wp-content/plugins/builder/app.js?token=secret&v=1": {
			URL:            "https://example.test/wp-content/plugins/builder/app.js?token=secret&v=1",
			Initiator:      "parser",
			ResponseStatus: 200,
			ContentType:    "application/javascript",
		},
	}

	observations := buildRenderedScriptObservations(snapshot, networkScripts, baseURL)
	if len(observations) != 3 {
		t.Fatalf("observations = %#v, want 3", observations)
	}
	if observations[0].SourceType != "dom" || observations[0].Domain != "example.test" {
		t.Fatalf("dom script = %#v", observations[0])
	}
	if observations[0].ResponseStatus != 200 || observations[0].Initiator != "parser" {
		t.Fatalf("network metadata was not merged into DOM script: %#v", observations[0])
	}
	if observations[0].URLRedacted == observations[0].URL || observations[0].URLRedacted == "" {
		t.Fatalf("rendered script URL was not redacted: %#v", observations[0])
	}
	if observations[1].SourceType != "inline" || !observations[1].TagManager || observations[1].SHA256 == "" {
		t.Fatalf("inline tag manager script = %#v", observations[1])
	}
	if !strings.Contains(observations[1].InlinePreview, "window.dataLayer") || !strings.Contains(observations[1].InlinePreview, "GTM-TEST1") {
		t.Fatalf("inline preview = %q, want rendered inline script text", observations[1].InlinePreview)
	}
	if observations[2].SourceType != "network" || observations[2].Domain != "cdn.example.test" || observations[2].Initiator != "script" {
		t.Fatalf("network-only script = %#v", observations[2])
	}
}
