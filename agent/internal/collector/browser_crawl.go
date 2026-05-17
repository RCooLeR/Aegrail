package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/agent/internal/redaction"
	"golang.org/x/net/html"
)

type BrowserCrawlInput struct {
	URLs               []string
	MaxPages           int
	Timeout            time.Duration
	UserAgent          string
	FallbackUserAgents []string
	SameHostOnly       bool
	Rendered           bool
	NetworkIdle        time.Duration
	Settle             time.Duration
	WaitTagManager     bool
}

type BrowserCrawlResult struct {
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt time.Time           `json:"finished_at"`
	Pages      []BrowserPageResult `json:"pages"`
}

type BrowserPageResult struct {
	URL          string                     `json:"url"`
	FinalURL     string                     `json:"final_url"`
	Mode         string                     `json:"mode"`
	UserAgent    string                     `json:"user_agent,omitempty"`
	StatusCode   int                        `json:"status_code"`
	Title        string                     `json:"title,omitempty"`
	CanonicalURL string                     `json:"canonical_url,omitempty"`
	Icons        []BrowserIconObservation   `json:"icons,omitempty"`
	Scripts      []BrowserScriptObservation `json:"scripts"`
	Warnings     []string                   `json:"warnings,omitempty"`
}

type BrowserIconObservation struct {
	Rel         string `json:"rel"`
	URLRedacted string `json:"url_redacted"`
	Domain      string `json:"domain,omitempty"`
	Path        string `json:"path,omitempty"`
	Sizes       string `json:"sizes,omitempty"`
	Type        string `json:"type,omitempty"`
}

type BrowserScriptObservation struct {
	SourceType        string            `json:"source_type"`
	URL               string            `json:"url,omitempty"`
	URLRedacted       string            `json:"url_redacted,omitempty"`
	Domain            string            `json:"domain,omitempty"`
	Path              string            `json:"path,omitempty"`
	SHA256            string            `json:"sha256,omitempty"`
	InlineBytes       int               `json:"inline_bytes,omitempty"`
	Initiator         string            `json:"initiator,omitempty"`
	ResponseStatus    int               `json:"response_status,omitempty"`
	ContentType       string            `json:"content_type,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
	TagManager        bool              `json:"tag_manager"`
	TagManagerIDs     []string          `json:"tag_manager_ids,omitempty"`
	InitialHTML       bool              `json:"initial_html"`
	DynamicallyLoaded bool              `json:"dynamically_loaded"`
}

const (
	browserCrawlModeStatic   = "static"
	browserCrawlModeRendered = "rendered"

	AegrailCrawlerUserAgent = "AegrailBot/0.1 (+https://aegrail.com/monitoring; Aegrail bot)"
)

var BrowserCrawlerFallbackUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
}

func (r *Runtime) CrawlBrowserPages(ctx context.Context, input BrowserCrawlInput) (BrowserCrawlResult, error) {
	timeout := input.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	maxPages := input.MaxPages
	if maxPages <= 0 || maxPages > len(input.URLs) {
		maxPages = len(input.URLs)
	}
	if maxPages > 25 {
		maxPages = 25
	}
	client := &http.Client{Timeout: timeout}
	startedAt := time.Now().UTC()
	result := BrowserCrawlResult{StartedAt: startedAt}
	allowedHosts := allowedSeedHosts(input.URLs)
	mode := browserCrawlModeStatic
	if input.Rendered {
		mode = browserCrawlModeRendered
	}

	for _, rawURL := range input.URLs[:maxPages] {
		pageURL, err := normalizeCrawlURL(rawURL)
		if err != nil {
			result.Pages = append(result.Pages, browserWarningPage(rawURL, mode, err.Error()))
			continue
		}
		if input.SameHostOnly && !allowedHosts[pageURL.Hostname()] {
			result.Pages = append(result.Pages, browserWarningPage(pageURL.String(), mode, "skipped because host is outside seed host set"))
			continue
		}
		page, err := crawlOnePage(ctx, client, pageURL, input)
		if err != nil {
			result.Pages = append(result.Pages, browserWarningPage(pageURL.String(), mode, err.Error()))
			continue
		}
		result.Pages = append(result.Pages, page)
	}
	result.FinishedAt = time.Now().UTC()
	return result, nil
}

func browserWarningPage(rawURL string, mode string, warning string) BrowserPageResult {
	return BrowserPageResult{
		URL:      rawURL,
		FinalURL: rawURL,
		Mode:     mode,
		Scripts:  []BrowserScriptObservation{},
		Warnings: []string{warning},
	}
}

func crawlOnePage(ctx context.Context, client *http.Client, pageURL *url.URL, input BrowserCrawlInput) (BrowserPageResult, error) {
	candidates := browserCrawlerUserAgentCandidates(input)
	var firstBlocked *BrowserPageResult
	var fallbackNotes []string
	for index, userAgent := range candidates {
		attempt := input
		attempt.UserAgent = userAgent
		page, err := crawlOnePageOnce(ctx, client, pageURL, attempt)
		if err != nil {
			fallbackNotes = append(fallbackNotes, fmt.Sprintf("crawler user-agent %s failed: %v", userAgentLabel(userAgent), err))
			if index == len(candidates)-1 && firstBlocked == nil {
				return BrowserPageResult{}, err
			}
			continue
		}
		if !shouldRetryCrawlerUserAgent(page) {
			if index > 0 {
				page.Warnings = append([]string{"crawler user-agent fallback used after Aegrail bot was blocked or failed"}, page.Warnings...)
			}
			return page, nil
		}
		if firstBlocked == nil {
			blocked := page
			firstBlocked = &blocked
		}
		fallbackNotes = append(fallbackNotes, fmt.Sprintf("crawler user-agent %s returned HTTP status %d", userAgentLabel(userAgent), page.StatusCode))
	}
	if firstBlocked != nil {
		firstBlocked.Warnings = append(firstBlocked.Warnings, fallbackNotes...)
		return *firstBlocked, nil
	}
	return BrowserPageResult{}, fmt.Errorf("browser crawl failed before a page could be captured")
}

func crawlOnePageOnce(ctx context.Context, client *http.Client, pageURL *url.URL, input BrowserCrawlInput) (BrowserPageResult, error) {
	if input.Rendered {
		return crawlRenderedPage(ctx, pageURL, input)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
	if err != nil {
		return BrowserPageResult{}, err
	}
	userAgent := input.UserAgent
	if strings.TrimSpace(userAgent) == "" {
		userAgent = AegrailCrawlerUserAgent
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")

	response, err := client.Do(request)
	if err != nil {
		return BrowserPageResult{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 5*1024*1024))
	if err != nil {
		return BrowserPageResult{}, err
	}
	finalURL := pageURL
	if response.Request != nil && response.Request.URL != nil {
		finalURL = response.Request.URL
	}
	page := BrowserPageResult{
		URL:        pageURL.String(),
		FinalURL:   finalURL.String(),
		Mode:       browserCrawlModeStatic,
		UserAgent:  userAgent,
		StatusCode: response.StatusCode,
		Scripts:    []BrowserScriptObservation{},
	}
	if response.StatusCode >= 400 {
		page.Warnings = append(page.Warnings, fmt.Sprintf("HTTP status %d", response.StatusCode))
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "html") {
		page.Warnings = append(page.Warnings, "response content type is not HTML")
	}

	document, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return page, err
	}
	page.Title = strings.TrimSpace(firstText(document, "title"))
	page.CanonicalURL = findCanonicalURL(document, finalURL)
	page.Icons = collectPageIcons(document, finalURL)
	page.Scripts = collectScripts(document, finalURL)
	if len(page.Scripts) == 0 {
		page.Warnings = append(page.Warnings, "no scripts observed in initial HTML")
	}
	if hasTagManager(page.Scripts) {
		page.Warnings = append(page.Warnings, "tag manager observed; rendered browser mode is needed to observe scripts injected after initial HTML")
	}
	return page, nil
}

func browserCrawlerUserAgentCandidates(input BrowserCrawlInput) []string {
	candidates := []string{strings.TrimSpace(input.UserAgent)}
	if candidates[0] == "" {
		candidates[0] = AegrailCrawlerUserAgent
	}
	fallbacks := input.FallbackUserAgents
	if len(fallbacks) == 0 {
		fallbacks = BrowserCrawlerFallbackUserAgents
	}
	candidates = append(candidates, fallbacks...)

	seen := map[string]struct{}{}
	clean := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		clean = append(clean, candidate)
	}
	return clean
}

func shouldRetryCrawlerUserAgent(page BrowserPageResult) bool {
	switch page.StatusCode {
	case http.StatusForbidden, http.StatusNotAcceptable, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func userAgentLabel(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return "empty"
	}
	if strings.Contains(userAgent, "AegrailBot/") {
		return "Aegrail bot"
	}
	for _, marker := range []string{"Chrome/", "Firefox/", "Version/"} {
		if index := strings.Index(userAgent, marker); index >= 0 {
			end := strings.Index(userAgent[index:], " ")
			if end >= 0 {
				return userAgent[index : index+end]
			}
			return userAgent[index:]
		}
	}
	return userAgent
}

func collectScripts(root *html.Node, baseURL *url.URL) []BrowserScriptObservation {
	scripts := []BrowserScriptObservation{}
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "script") {
			scripts = append(scripts, buildScriptObservation(node, baseURL))
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return scripts
}

func collectPageIcons(root *html.Node, baseURL *url.URL) []BrowserIconObservation {
	icons := []BrowserIconObservation{}
	seen := map[string]bool{}
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "link") {
			attrs := htmlAttrs(node)
			if isIconRel(attrs["rel"]) {
				if icon, ok := buildIconObservation(attrs, baseURL); ok && !seen[icon.URLRedacted] {
					seen[icon.URLRedacted] = true
					icons = append(icons, icon)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return icons
}

func buildIconObservation(attrs map[string]string, baseURL *url.URL) (BrowserIconObservation, bool) {
	href := strings.TrimSpace(attrs["href"])
	if href == "" {
		return BrowserIconObservation{}, false
	}
	resolved := resolveURL(baseURL, href)
	if resolved == nil || !isHTTPURL(resolved) {
		return BrowserIconObservation{}, false
	}
	return BrowserIconObservation{
		Rel:         strings.ToLower(strings.TrimSpace(attrs["rel"])),
		URLRedacted: sanitizeBrowserIconURL(resolved),
		Domain:      resolved.Hostname(),
		Path:        resolved.EscapedPath(),
		Sizes:       strings.TrimSpace(attrs["sizes"]),
		Type:        strings.TrimSpace(attrs["type"]),
	}, true
}

func buildScriptObservation(node *html.Node, baseURL *url.URL) BrowserScriptObservation {
	attrs := htmlAttrs(node)
	observation := BrowserScriptObservation{
		SourceType:  "html",
		Attributes:  attrs,
		InitialHTML: true,
	}
	if src := strings.TrimSpace(attrs["src"]); src != "" {
		if resolved := resolveURL(baseURL, src); resolved != nil {
			observation.URL = resolved.String()
			observation.URLRedacted = redaction.RedactURL(resolved.String())
			observation.Domain = resolved.Hostname()
			observation.Path = resolved.EscapedPath()
		} else {
			observation.URL = redaction.RedactURL(src)
			observation.URLRedacted = redaction.RedactURL(src)
		}
	} else {
		observation.SourceType = "inline"
		text := strings.TrimSpace(nodeText(node))
		if text != "" {
			sum := sha256.Sum256([]byte(text))
			observation.SHA256 = hex.EncodeToString(sum[:])
			observation.InlineBytes = len([]byte(text))
			observation.TagManagerIDs = tagManagerIDs(text)
		}
	}
	if observation.URL != "" {
		observation.TagManagerIDs = tagManagerIDs(observation.URL)
	}
	observation.TagManager = len(observation.TagManagerIDs) > 0 || isTagManagerURL(observation.URL)
	if len(observation.TagManagerIDs) > 1 {
		slices.Sort(observation.TagManagerIDs)
		observation.TagManagerIDs = slices.Compact(observation.TagManagerIDs)
	}
	return observation
}

func firstText(root *html.Node, tagName string) string {
	var found string
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if found != "" {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, tagName) {
			found = nodeText(node)
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return found
}

func findCanonicalURL(root *html.Node, baseURL *url.URL) string {
	var canonical string
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if canonical != "" {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "link") {
			attrs := htmlAttrs(node)
			if strings.EqualFold(attrs["rel"], "canonical") {
				if resolved := resolveURL(baseURL, attrs["href"]); resolved != nil {
					canonical = resolved.String()
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return canonical
}

func htmlAttrs(node *html.Node) map[string]string {
	attrs := map[string]string{}
	for _, attr := range node.Attr {
		attrs[strings.ToLower(attr.Key)] = strings.TrimSpace(attr.Val)
	}
	return attrs
}

func nodeText(node *html.Node) string {
	var builder strings.Builder
	var visit func(*html.Node)
	visit = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(node)
	return builder.String()
}

func resolveURL(baseURL *url.URL, value string) *url.URL {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil
	}
	return baseURL.ResolveReference(parsed)
}

func isHTTPURL(parsed *url.URL) bool {
	return parsed != nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func sanitizeBrowserIconURL(parsed *url.URL) string {
	clean := *parsed
	clean.User = nil
	clean.RawQuery = ""
	clean.Fragment = ""
	return redaction.RedactURL(clean.String())
}

func isIconRel(value string) bool {
	parts := strings.Fields(strings.ToLower(value))
	for _, part := range parts {
		switch part {
		case "icon", "shortcut", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon":
			return true
		}
	}
	return false
}

func normalizeCrawlURL(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("url host is required")
	}
	return parsed, nil
}

func allowedSeedHosts(values []string) map[string]bool {
	hosts := map[string]bool{}
	for _, value := range values {
		parsed, err := normalizeCrawlURL(value)
		if err == nil {
			hosts[parsed.Hostname()] = true
		}
	}
	return hosts
}

func hasTagManager(scripts []BrowserScriptObservation) bool {
	for _, script := range scripts {
		if script.TagManager {
			return true
		}
	}
	return false
}

func isTagManagerURL(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "googletagmanager.com") ||
		strings.Contains(lower, "gtm.js") ||
		strings.Contains(lower, "gtag/js")
}

func tagManagerIDs(value string) []string {
	var ids []string
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
	})
	for _, part := range parts {
		if strings.HasPrefix(part, "GTM-") || strings.HasPrefix(part, "G-") || strings.HasPrefix(part, "AW-") {
			ids = append(ids, part)
		}
	}
	return ids
}
