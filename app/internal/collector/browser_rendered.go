package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/rcooler/aegrail/internal/redaction"
)

type renderedPageSnapshot struct {
	FinalURL        string              `json:"final_url"`
	Title           string              `json:"title"`
	CanonicalURL    string              `json:"canonical_url"`
	TagManagerReady bool                `json:"tag_manager_ready"`
	Icons           []renderedPageIcon  `json:"icons"`
	Scripts         []renderedDOMScript `json:"scripts"`
	Resources       []renderedResource  `json:"resources"`
}

type renderedPageIcon struct {
	Rel   string `json:"rel"`
	URL   string `json:"url"`
	Sizes string `json:"sizes"`
	Type  string `json:"type"`
}

type renderedDOMScript struct {
	SourceType string            `json:"source_type"`
	URL        string            `json:"url"`
	Text       string            `json:"text"`
	Attributes map[string]string `json:"attributes"`
}

type renderedResource struct {
	URL       string `json:"url"`
	Initiator string `json:"initiator"`
}

type renderedNetworkScript struct {
	URL            string
	Initiator      string
	ResponseStatus int
	ContentType    string
}

type renderedNetworkState struct {
	mu       sync.Mutex
	active   map[network.RequestID]struct{}
	requests map[network.RequestID]renderedNetworkScript
	scripts  map[string]renderedNetworkScript
	status   int
	finalURL string
	lastSeen time.Time
}

func newRenderedNetworkState() *renderedNetworkState {
	return &renderedNetworkState{
		active:   map[network.RequestID]struct{}{},
		requests: map[network.RequestID]renderedNetworkScript{},
		scripts:  map[string]renderedNetworkScript{},
		lastSeen: time.Now(),
	}
}

func crawlRenderedPage(ctx context.Context, pageURL *url.URL, input BrowserCrawlInput) (BrowserPageResult, error) {
	timeout := input.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	networkIdle := input.NetworkIdle
	if networkIdle <= 0 {
		networkIdle = 1500 * time.Millisecond
	}
	settle := input.Settle
	if settle <= 0 {
		settle = 2 * time.Second
	}
	userAgent := strings.TrimSpace(input.UserAgent)
	if userAgent == "" {
		userAgent = "aegrail-rendered-browser-crawler/dev"
	}

	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoDefaultBrowserCheck,
		chromedp.NoFirstRun,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(userAgent),
	)
	allocatorCtx, cancelAllocator := chromedp.NewExecAllocator(ctx, options...)
	defer cancelAllocator()

	browserCtx, cancelBrowser := chromedp.NewContext(allocatorCtx, chromedp.WithErrorf(func(string, ...any) {}))
	defer cancelBrowser()

	pageCtx, cancelPage := context.WithTimeout(browserCtx, timeout)
	defer cancelPage()

	networkState := newRenderedNetworkState()
	chromedp.ListenTarget(pageCtx, networkState.handleEvent)

	page := BrowserPageResult{
		URL:      pageURL.String(),
		FinalURL: pageURL.String(),
		Mode:     browserCrawlModeRendered,
		Scripts:  []BrowserScriptObservation{},
	}

	if err := chromedp.Run(pageCtx, network.Enable(), chromedp.Navigate(pageURL.String())); err != nil {
		return page, fmt.Errorf("rendered crawl failed: %w", err)
	}

	if err := chromedp.Run(pageCtx, chromedp.Poll(
		`document.readyState === "complete" || document.readyState === "interactive"`,
		nil,
		chromedp.WithPollingInterval(100*time.Millisecond),
		chromedp.WithPollingTimeout(minDuration(5*time.Second, timeout/3)),
	)); err != nil && !errors.Is(err, chromedp.ErrPollingTimeout) {
		page.Warnings = append(page.Warnings, fmt.Sprintf("document readiness wait failed: %v", err))
	}

	if input.WaitTagManager {
		if err := chromedp.Run(pageCtx, chromedp.Poll(
			renderedTagManagerReadyExpression,
			nil,
			chromedp.WithPollingInterval(250*time.Millisecond),
			chromedp.WithPollingTimeout(minDuration(10*time.Second, timeout/2)),
		)); err != nil {
			page.Warnings = append(page.Warnings, "tag manager readiness wait timed out; continuing with observed scripts")
		}
	}

	networkBudget := minDuration(8*time.Second, timeout/2)
	if err := waitForRenderedNetworkIdle(pageCtx, networkState, networkIdle, networkBudget); err != nil {
		page.Warnings = append(page.Warnings, err.Error())
	}
	if settle > 0 {
		if err := chromedp.Run(pageCtx, chromedp.Sleep(settle)); err != nil {
			page.Warnings = append(page.Warnings, fmt.Sprintf("settle wait failed: %v", err))
		}
	}

	var snapshot renderedPageSnapshot
	if err := chromedp.Run(pageCtx, chromedp.Evaluate(renderedPageSnapshotExpression, &snapshot)); err != nil {
		return page, fmt.Errorf("rendered page extraction failed: %w", err)
	}

	page.FinalURL = strings.TrimSpace(snapshot.FinalURL)
	if page.FinalURL == "" {
		page.FinalURL = networkState.documentURL(pageURL.String())
	}
	page.StatusCode = networkState.documentStatus()
	page.Title = strings.TrimSpace(snapshot.Title)
	page.CanonicalURL = strings.TrimSpace(snapshot.CanonicalURL)
	page.Icons = buildRenderedIconObservations(snapshot.Icons, pageURL)
	page.Scripts = buildRenderedScriptObservations(snapshot, networkState.scriptResponses(), pageURL)

	if len(page.Scripts) == 0 {
		page.Warnings = append(page.Warnings, "no scripts observed after rendering")
	}
	if hasTagManager(page.Scripts) && input.WaitTagManager && !snapshot.TagManagerReady {
		page.Warnings = append(page.Warnings, "tag manager script observed but runtime readiness was not confirmed")
	}
	return page, nil
}

func buildRenderedIconObservations(icons []renderedPageIcon, baseURL *url.URL) []BrowserIconObservation {
	observations := []BrowserIconObservation{}
	seen := map[string]bool{}
	for _, icon := range icons {
		attrs := map[string]string{
			"href":  icon.URL,
			"rel":   icon.Rel,
			"sizes": icon.Sizes,
			"type":  icon.Type,
		}
		observation, ok := buildIconObservation(attrs, baseURL)
		if ok && !seen[observation.URLRedacted] {
			seen[observation.URLRedacted] = true
			observations = append(observations, observation)
		}
	}
	return observations
}

func (s *renderedNetworkState) handleEvent(event any) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	switch event := event.(type) {
	case *network.EventRequestWillBeSent:
		s.lastSeen = now
		s.active[event.RequestID] = struct{}{}
		request := renderedNetworkScript{}
		if event.Request != nil {
			request.URL = event.Request.URL
		}
		if event.Initiator != nil {
			request.Initiator = event.Initiator.Type.String()
		}
		s.requests[event.RequestID] = request
	case *network.EventResponseReceived:
		s.lastSeen = now
		request := s.requests[event.RequestID]
		if event.Response != nil {
			if request.URL == "" {
				request.URL = event.Response.URL
			}
			request.ResponseStatus = int(event.Response.Status)
			request.ContentType = event.Response.MimeType
		}
		s.requests[event.RequestID] = request

		if event.Type == network.ResourceTypeDocument && event.Response != nil {
			s.status = int(event.Response.Status)
			s.finalURL = event.Response.URL
		}
		if (event.Type == network.ResourceTypeScript || isScriptLikeURL(request.URL)) && request.URL != "" {
			s.scripts[request.URL] = request
		}
	case *network.EventLoadingFinished:
		s.lastSeen = now
		delete(s.active, event.RequestID)
	case *network.EventLoadingFailed:
		s.lastSeen = now
		delete(s.active, event.RequestID)
	}
}

func (s *renderedNetworkState) idleFor(quietPeriod time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active) == 0 && time.Since(s.lastSeen) >= quietPeriod
}

func (s *renderedNetworkState) documentStatus() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *renderedNetworkState) documentURL(fallback string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(s.finalURL) == "" {
		return fallback
	}
	return s.finalURL
}

func (s *renderedNetworkState) scriptResponses() map[string]renderedNetworkScript {
	s.mu.Lock()
	defer s.mu.Unlock()

	scripts := map[string]renderedNetworkScript{}
	for key, value := range s.scripts {
		scripts[key] = value
	}
	return scripts
}

func waitForRenderedNetworkIdle(ctx context.Context, state *renderedNetworkState, quietPeriod time.Duration, budget time.Duration) error {
	if quietPeriod <= 0 || budget <= 0 {
		return nil
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		if state.idleFor(quietPeriod) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("network did not stay idle for %s within %s; continuing with observed scripts", quietPeriod, budget)
		case <-ticker.C:
		}
	}
}

func buildRenderedScriptObservations(snapshot renderedPageSnapshot, networkScripts map[string]renderedNetworkScript, baseURL *url.URL) []BrowserScriptObservation {
	finalURL := baseURL
	if parsed, err := url.Parse(strings.TrimSpace(snapshot.FinalURL)); err == nil && parsed.Host != "" {
		finalURL = parsed
	}

	observations := []BrowserScriptObservation{}
	seenURLs := map[string]bool{}
	for _, script := range snapshot.Scripts {
		observation := buildRenderedDOMScriptObservation(script, finalURL)
		if observation.URL != "" {
			if networkScript, ok := networkScripts[observation.URL]; ok {
				applyRenderedNetworkScript(&observation, networkScript)
			}
			seenURLs[observation.URL] = true
		}
		observations = append(observations, observation)
	}

	for _, resource := range snapshot.Resources {
		if strings.TrimSpace(resource.URL) == "" {
			continue
		}
		if _, ok := networkScripts[resource.URL]; ok {
			continue
		}
		networkScripts[resource.URL] = renderedNetworkScript{URL: resource.URL, Initiator: resource.Initiator}
	}

	networkURLs := make([]string, 0, len(networkScripts))
	for scriptURL := range networkScripts {
		if !seenURLs[scriptURL] {
			networkURLs = append(networkURLs, scriptURL)
		}
	}
	slices.Sort(networkURLs)
	for _, scriptURL := range networkURLs {
		observation := buildRenderedNetworkScriptObservation(networkScripts[scriptURL], finalURL)
		if observation.URL == "" {
			continue
		}
		observations = append(observations, observation)
	}
	return observations
}

func buildRenderedDOMScriptObservation(script renderedDOMScript, baseURL *url.URL) BrowserScriptObservation {
	attrs := normalizedAttributeMap(script.Attributes)
	sourceType := strings.TrimSpace(script.SourceType)
	if sourceType == "" {
		sourceType = "dom"
	}
	observation := BrowserScriptObservation{
		SourceType:        sourceType,
		Attributes:        attrs,
		DynamicallyLoaded: true,
	}

	if strings.TrimSpace(script.URL) != "" {
		applyScriptURL(&observation, baseURL, script.URL)
	} else {
		observation.SourceType = "inline"
		text := strings.TrimSpace(script.Text)
		if text != "" {
			sum := sha256.Sum256([]byte(text))
			observation.SHA256 = hex.EncodeToString(sum[:])
			observation.InlineBytes = len([]byte(text))
			observation.TagManagerIDs = append(observation.TagManagerIDs, tagManagerIDs(text)...)
		}
	}

	observation.TagManagerIDs = append(observation.TagManagerIDs, tagManagerIDs(observation.URL)...)
	for _, value := range attrs {
		observation.TagManagerIDs = append(observation.TagManagerIDs, tagManagerIDs(value)...)
	}
	compactTagManagerIDs(&observation)
	return observation
}

func buildRenderedNetworkScriptObservation(script renderedNetworkScript, baseURL *url.URL) BrowserScriptObservation {
	observation := BrowserScriptObservation{
		SourceType:        "network",
		DynamicallyLoaded: true,
	}
	applyScriptURL(&observation, baseURL, script.URL)
	applyRenderedNetworkScript(&observation, script)
	observation.TagManagerIDs = append(observation.TagManagerIDs, tagManagerIDs(observation.URL)...)
	compactTagManagerIDs(&observation)
	return observation
}

func applyRenderedNetworkScript(observation *BrowserScriptObservation, script renderedNetworkScript) {
	if strings.TrimSpace(script.Initiator) != "" {
		observation.Initiator = script.Initiator
	}
	if script.ResponseStatus > 0 {
		observation.ResponseStatus = script.ResponseStatus
	}
	if strings.TrimSpace(script.ContentType) != "" {
		observation.ContentType = script.ContentType
	}
}

func applyScriptURL(observation *BrowserScriptObservation, baseURL *url.URL, value string) {
	if resolved := resolveURL(baseURL, value); resolved != nil {
		observation.URL = resolved.String()
		observation.URLRedacted = redaction.RedactURL(resolved.String())
		observation.Domain = resolved.Hostname()
		observation.Path = resolved.EscapedPath()
		return
	}
	observation.URL = redaction.RedactURL(value)
	observation.URLRedacted = redaction.RedactURL(value)
}

func normalizedAttributeMap(attrs map[string]string) map[string]string {
	normalized := map[string]string{}
	for key, value := range attrs {
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key != "" {
			normalized[key] = value
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func compactTagManagerIDs(observation *BrowserScriptObservation) {
	if len(observation.TagManagerIDs) > 1 {
		slices.Sort(observation.TagManagerIDs)
		observation.TagManagerIDs = slices.Compact(observation.TagManagerIDs)
	}
	observation.TagManager = len(observation.TagManagerIDs) > 0 || isTagManagerURL(observation.URL)
}

func isScriptLikeURL(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, ".js") ||
		strings.Contains(lower, "googletagmanager.com") ||
		strings.Contains(lower, "google-analytics.com") ||
		strings.Contains(lower, "analytics.google.com")
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

const renderedTagManagerReadyExpression = `(() => {
  const html = document.documentElement ? document.documentElement.innerHTML : "";
  const hasTagManager =
    !!document.querySelector('script[src*="googletagmanager.com/gtm.js"],script[src*="googletagmanager.com/gtag/js"]') ||
    /GTM-[A-Z0-9-]+|G-[A-Z0-9-]+|AW-[A-Z0-9-]+/.test(html);
  if (!hasTagManager) {
    return true;
  }
  const runtimeReady = !!(window.google_tag_manager && Object.keys(window.google_tag_manager).length);
  const dataLayerReady = Array.isArray(window.dataLayer) && window.dataLayer.some((entry) => {
    return entry && typeof entry === "object" && (entry.event === "gtm.js" || entry.event === "gtm.dom" || entry.event === "gtm.load");
  });
  return runtimeReady || dataLayerReady;
})()`

const renderedPageSnapshotExpression = `(() => {
  const attributes = (element) => Array.from(element.attributes || []).reduce((acc, attr) => {
    acc[attr.name] = attr.value || "";
    return acc;
  }, {});
  const canonical = document.querySelector('link[rel~="canonical"]');
  const icons = Array.from(document.querySelectorAll('link[rel]'))
    .filter((link) => {
      const rel = (link.getAttribute("rel") || "").toLowerCase().split(/\s+/);
      return rel.some((part) => ["icon", "shortcut", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"].includes(part));
    })
    .map((link) => {
      return {
        rel: link.getAttribute("rel") || "",
        url: link.href || "",
        sizes: link.getAttribute("sizes") || "",
        type: link.getAttribute("type") || ""
      };
    });
  const scripts = Array.from(document.scripts || []).map((script) => {
    return {
      source_type: script.src ? "dom" : "inline",
      url: script.src || "",
      text: script.src ? "" : (script.textContent || ""),
      attributes: attributes(script)
    };
  });
  const resources = performance.getEntriesByType("resource")
    .filter((resource) => {
      const name = resource.name || "";
      return resource.initiatorType === "script" || /\.m?js([?#]|$)/i.test(name) || name.includes("googletagmanager.com");
    })
    .map((resource) => {
      return {
        url: resource.name || "",
        initiator: resource.initiatorType || ""
      };
    });
  const html = document.documentElement ? document.documentElement.innerHTML : "";
  const tagManagerReady =
    !!(window.google_tag_manager && Object.keys(window.google_tag_manager).length) ||
    (Array.isArray(window.dataLayer) && window.dataLayer.some((entry) => {
      return entry && typeof entry === "object" && (entry.event === "gtm.js" || entry.event === "gtm.dom" || entry.event === "gtm.load");
    }));
  return {
    final_url: location.href,
    title: document.title || "",
    canonical_url: canonical ? canonical.href : "",
    tag_manager_ready: tagManagerReady || !(/GTM-[A-Z0-9-]+|G-[A-Z0-9-]+|AW-[A-Z0-9-]+/.test(html)),
    icons,
    scripts,
    resources
  };
})()`
