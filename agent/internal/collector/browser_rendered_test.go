package collector

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
