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

	"github.com/rcooler/aegrail/internal/redaction"
	"golang.org/x/net/html"
)

type BrowserCrawlInput struct {
	URLs           []string
	MaxPages       int
	Timeout        time.Duration
	UserAgent      string
	SameHostOnly   bool
	Rendered       bool
	NetworkIdle    time.Duration
	Settle         time.Duration
	WaitTagManager bool
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
	StatusCode   int                        `json:"status_code"`
	Title        string                     `json:"title,omitempty"`
	CanonicalURL string                     `json:"canonical_url,omitempty"`
	Scripts      []BrowserScriptObservation `json:"scripts"`
	Warnings     []string                   `json:"warnings,omitempty"`
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
)

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
	if input.Rendered {
		return crawlRenderedPage(ctx, pageURL, input)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL.String(), nil)
	if err != nil {
		return BrowserPageResult{}, err
	}
	userAgent := input.UserAgent
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "aegrail-browser-crawler/dev"
	}
	request.Header.Set("User-Agent", userAgent)

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
	page.Scripts = collectScripts(document, finalURL)
	if len(page.Scripts) == 0 {
		page.Warnings = append(page.Warnings, "no scripts observed in initial HTML")
	}
	if hasTagManager(page.Scripts) {
		page.Warnings = append(page.Warnings, "tag manager observed; rendered browser mode is needed to observe scripts injected after initial HTML")
	}
	return page, nil
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
