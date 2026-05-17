package collector

import (
	"net/url"
	"testing"
)

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
	if observations[2].SourceType != "network" || observations[2].Domain != "cdn.example.test" || observations[2].Initiator != "script" {
		t.Fatalf("network-only script = %#v", observations[2])
	}
}
