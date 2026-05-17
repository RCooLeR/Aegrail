package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	defaultTorExitListURL          = "https://check.torproject.org/torbulkexitlist"
	defaultTorExitListTTL          = 6 * time.Hour
	defaultTorExitListFetchTimeout = 5 * time.Second
	torExitCacheSchema             = "aegrail.agent.tor_exit_list.v1"
)

type torExitMatcher interface {
	Contains(remote string) bool
	Metadata() torExitMetadata
}

type torExitMetadata struct {
	Source    string
	CheckedAt time.Time
	Size      int
}

type torExitSet struct {
	ips       map[string]struct{}
	source    string
	checkedAt time.Time
}

type torExitRuntimeCache struct {
	matcher   *torExitSet
	cachePath string
	sourceURL string
	ttl       time.Duration
	loadedAt  time.Time
	failedAt  time.Time
}

type torExitOptions struct {
	Enabled   bool
	SourceURL string
	CachePath string
	TTL       time.Duration
}

type torExitCacheFile struct {
	Schema    string    `json:"schema"`
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
	IPs       []string  `json:"ips"`
}

func (set *torExitSet) Contains(remote string) bool {
	if set == nil || len(set.ips) == 0 {
		return false
	}
	ip, ok := normalizeRemoteIP(remote)
	if !ok {
		return false
	}
	_, ok = set.ips[ip]
	return ok
}

func (set *torExitSet) Metadata() torExitMetadata {
	if set == nil {
		return torExitMetadata{}
	}
	return torExitMetadata{
		Source:    set.source,
		CheckedAt: set.checkedAt,
		Size:      len(set.ips),
	}
}

func (r *Runtime) loadTorExitMatcher(ctx context.Context, queueDir string) torExitMatcher {
	options := torExitOptionsFromEnv(queueDir)
	if !options.Enabled {
		return nil
	}
	now := r.now().UTC()
	if r.torExitCache.matcher != nil &&
		r.torExitCache.cachePath == options.CachePath &&
		r.torExitCache.sourceURL == options.SourceURL &&
		r.torExitCache.ttl == options.TTL &&
		now.Sub(r.torExitCache.loadedAt) < options.TTL {
		return r.torExitCache.matcher
	}

	if matcher, ok := loadTorExitCacheFile(options.CachePath, options.TTL, false, now); ok {
		r.rememberTorExitMatcher(matcher, options, now)
		return matcher
	}

	if !r.torExitCache.failedAt.IsZero() &&
		now.Sub(r.torExitCache.failedAt) < minDurationAgent(5*time.Minute, options.TTL/2) {
		return r.torExitCache.matcher
	}

	fetchCtx, cancel := context.WithTimeout(ctx, defaultTorExitListFetchTimeout)
	defer cancel()
	matcher, err := fetchTorExitList(fetchCtx, r.client, options.SourceURL, now)
	if err == nil && matcher != nil {
		_ = saveTorExitCacheFile(options.CachePath, matcher)
		r.rememberTorExitMatcher(matcher, options, now)
		return matcher
	}

	r.torExitCache.failedAt = now
	if matcher, ok := loadTorExitCacheFile(options.CachePath, options.TTL, true, now); ok {
		r.rememberTorExitMatcher(matcher, options, now)
		r.torExitCache.failedAt = now
		return matcher
	}
	return r.torExitCache.matcher
}

func (r *Runtime) rememberTorExitMatcher(matcher *torExitSet, options torExitOptions, loadedAt time.Time) {
	r.torExitCache.matcher = matcher
	r.torExitCache.cachePath = options.CachePath
	r.torExitCache.sourceURL = options.SourceURL
	r.torExitCache.ttl = options.TTL
	r.torExitCache.loadedAt = loadedAt
}

func torExitOptionsFromEnv(queueDir string) torExitOptions {
	enabled := true
	if envBoolFalse(os.Getenv("AEGRAIL_TOR_CHECK")) || envBoolTrue(os.Getenv("AEGRAIL_DISABLE_TOR_CHECK")) {
		enabled = false
	}
	sourceURL := strings.TrimSpace(os.Getenv("AEGRAIL_TOR_EXIT_LIST_URL"))
	if sourceURL == "" {
		sourceURL = defaultTorExitListURL
	}
	ttl := defaultTorExitListTTL
	if raw := strings.TrimSpace(os.Getenv("AEGRAIL_TOR_EXIT_LIST_TTL")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			ttl = parsed
		}
	}
	cachePath := strings.TrimSpace(os.Getenv("AEGRAIL_TOR_EXIT_LIST_CACHE"))
	if cachePath == "" {
		if strings.TrimSpace(queueDir) == "" {
			queueDir = ".aegrail/queue"
		}
		cachePath = filepath.Join(filepath.Dir(queueDir), "state", "tor-exit-list.json")
	}
	return torExitOptions{
		Enabled:   enabled,
		SourceURL: sourceURL,
		CachePath: cachePath,
		TTL:       ttl,
	}
}

func fetchTorExitList(ctx context.Context, client *http.Client, sourceURL string, checkedAt time.Time) (*torExitSet, error) {
	sourceURL = strings.TrimSpace(sourceURL)
	if sourceURL == "" {
		return nil, errors.New("tor exit list url is empty")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("tor exit list returned HTTP %d", response.StatusCode)
	}
	ips, err := parseTorExitList(response.Body)
	if err != nil {
		return nil, err
	}
	return &torExitSet{ips: ips, source: sourceURL, checkedAt: checkedAt.UTC()}, nil
}

func loadTorExitCacheFile(path string, ttl time.Duration, allowStale bool, now time.Time) (*torExitSet, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached torExitCacheFile
	if err := json.Unmarshal(content, &cached); err != nil {
		return nil, false
	}
	if cached.Schema != torExitCacheSchema || cached.FetchedAt.IsZero() || len(cached.IPs) == 0 {
		return nil, false
	}
	if !allowStale && ttl > 0 && now.Sub(cached.FetchedAt) > ttl {
		return nil, false
	}
	ips := make(map[string]struct{}, len(cached.IPs))
	for _, raw := range cached.IPs {
		ip, ok := normalizeRemoteIP(raw)
		if ok {
			ips[ip] = struct{}{}
		}
	}
	if len(ips) == 0 {
		return nil, false
	}
	return &torExitSet{ips: ips, source: cached.Source, checkedAt: cached.FetchedAt.UTC()}, true
}

func saveTorExitCacheFile(path string, matcher *torExitSet) error {
	if matcher == nil || len(matcher.ips) == 0 {
		return nil
	}
	ips := make([]string, 0, len(matcher.ips))
	for ip := range matcher.ips {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	content, err := json.MarshalIndent(torExitCacheFile{
		Schema:    torExitCacheSchema,
		Source:    matcher.source,
		FetchedAt: matcher.checkedAt.UTC(),
		IPs:       ips,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}

func parseTorExitList(reader interface{ Read([]byte) (int, error) }) (map[string]struct{}, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	ips := map[string]struct{}{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		candidate := fields[0]
		if strings.EqualFold(candidate, "ExitAddress") && len(fields) >= 2 {
			candidate = fields[1]
		}
		ip, ok := normalizeRemoteIP(candidate)
		if ok {
			ips[ip] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

func normalizeRemoteIP(value string) (string, bool) {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if value == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}
	if strings.Count(value, ":") == 1 {
		if host, _, ok := strings.Cut(value, ":"); ok {
			value = host
		}
	}
	parsed := net.ParseIP(value)
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}

func envBoolFalse(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "off", "disable", "disabled":
		return true
	default:
		return false
	}
}

func envBoolTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true
	default:
		return false
	}
}

func minDurationAgent(a time.Duration, b time.Duration) time.Duration {
	if b <= 0 || a < b {
		return a
	}
	return b
}
