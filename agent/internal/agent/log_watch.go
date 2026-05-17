package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/redaction"
)

const LogWatchStateSchema = "aegrail.agent.log_watch_state.v1"

const (
	maxLogLineBytes     = 64 << 10
	maxLogReadBytes     = 1 << 20
	maxLogEventsPerScan = 500
)

type LogWatchOptions struct {
	Paths     []string
	StatePath string
	NoEvents  bool
	App       string
	Service   string
	Region    string
	Labels    map[string]string
}

type LogWatchResult struct {
	WatchedLogs int
	Queued      int
	Baselined   bool
	Rotated     int
	StatePath   string
}

type logWatchState struct {
	Schema    string                  `json:"schema"`
	UpdatedAt time.Time               `json:"updated_at"`
	Logs      map[string]logFileState `json:"logs"`
}

type logFileState struct {
	Path      string    `json:"path"`
	Offset    int64     `json:"offset"`
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

type logTarget struct {
	Path      string
	SizeBytes int64
	ModTime   time.Time
}

type logLine struct {
	Offset    int64
	Bytes     int
	Text      string
	Truncated bool
}

func (r *Runtime) ScanLogPaths(ctx context.Context, options LogWatchOptions) (LogWatchResult, error) {
	identity, err := r.LoadIdentity(ctx)
	if err != nil {
		return LogWatchResult{}, err
	}
	paths := ResolveLogWatchPaths(options)
	if len(paths) == 0 {
		return LogWatchResult{}, errors.New("at least one log path is required")
	}
	statePath := strings.TrimSpace(options.StatePath)
	if statePath == "" {
		statePath = r.logWatchStatePath(identity)
	}
	unlock, err := acquireWatchLock(statePath)
	if err != nil {
		return LogWatchResult{}, err
	}
	defer unlock()

	previous, hadState, err := loadLogWatchState(statePath)
	if err != nil {
		return LogWatchResult{}, err
	}
	targets, err := resolveLogTargets(paths, identity.QueueDir)
	if err != nil {
		return LogWatchResult{}, err
	}
	var torMatcher torExitMatcher
	if !options.NoEvents {
		torMatcher = r.loadTorExitMatcher(ctx, identity.QueueDir)
	}

	current := make(map[string]logFileState, len(targets))
	result := LogWatchResult{
		WatchedLogs: len(targets),
		Baselined:   !hadState,
		StatePath:   statePath,
	}
	for _, target := range targets {
		offset := target.SizeBytes
		if hadState {
			previousState, ok := previous.Logs[target.Path]
			start := target.SizeBytes
			if ok {
				start = previousState.Offset
				if target.SizeBytes < previousState.Offset {
					start = 0
					result.Rotated++
				}
			}
			if options.NoEvents {
				current[target.Path] = logFileState{
					Path:      target.Path,
					Offset:    target.SizeBytes,
					SizeBytes: target.SizeBytes,
					ModTime:   target.ModTime,
				}
				continue
			}
			lines, nextOffset, err := readNewLogLines(target.Path, start)
			if err != nil {
				return LogWatchResult{}, err
			}
			offset = nextOffset
			for _, line := range lines {
				event := logLineEvent(target.Path, line)
				enrichAccessLogEventWithTor(&event, torMatcher)
				event.App = options.App
				event.Service = options.Service
				event.Region = options.Region
				event.Labels = mergeStringMaps(event.Labels, options.Labels)
				if shouldDropNoisyLogEvent(event) {
					continue
				}
				if _, _, err := r.EnqueueEvent(ctx, event); err != nil {
					return LogWatchResult{}, err
				}
				result.Queued++
			}
		}
		current[target.Path] = logFileState{
			Path:      target.Path,
			Offset:    offset,
			SizeBytes: target.SizeBytes,
			ModTime:   target.ModTime,
		}
	}
	if hadState && !options.NoEvents && len(targets) > 0 && result.Queued == 0 {
		event := logScanCompletedEvent(len(targets), false, result.Rotated)
		event.App = options.App
		event.Service = options.Service
		event.Region = options.Region
		event.Labels = mergeStringMaps(event.Labels, options.Labels)
		if _, _, err := r.EnqueueEvent(ctx, event); err != nil {
			return LogWatchResult{}, err
		}
		result.Queued++
	}
	if !hadState && !options.NoEvents && len(targets) > 0 {
		event := logBaselineCreatedEvent(len(targets))
		event.App = options.App
		event.Service = options.Service
		event.Region = options.Region
		event.Labels = mergeStringMaps(event.Labels, options.Labels)
		if _, _, err := r.EnqueueEvent(ctx, event); err != nil {
			return LogWatchResult{}, err
		}
		result.Queued++
	}

	if err := saveLogWatchState(statePath, logWatchState{
		Schema:    LogWatchStateSchema,
		UpdatedAt: r.now().UTC(),
		Logs:      current,
	}); err != nil {
		return LogWatchResult{}, err
	}
	return result, nil
}

func logBaselineCreatedEvent(watchedLogs int) EnqueueEventInput {
	return EnqueueEventInput{
		Type:     "log.baseline.created",
		Severity: string(domain.SeverityInfo),
		Message:  fmt.Sprintf("Log baseline created with %d watched log file(s)", watchedLogs),
		Labels: map[string]string{
			"watcher":   "log",
			"collector": "logs",
		},
		Payload: map[string]any{
			"watched_logs": watchedLogs,
			"baselined":    true,
		},
	}
}

func logScanCompletedEvent(watchedLogs int, baselined bool, rotated int) EnqueueEventInput {
	payload := map[string]any{
		"watched_logs": watchedLogs,
		"baselined":    baselined,
	}
	if rotated > 0 {
		payload["rotated"] = rotated
	}
	return EnqueueEventInput{
		Type:     "log.scan.completed",
		Severity: string(domain.SeverityInfo),
		Message:  fmt.Sprintf("Log scan completed with %d watched log file(s)", watchedLogs),
		Labels: map[string]string{
			"watcher":   "log",
			"collector": "logs",
		},
		Payload: payload,
	}
}

func ResolveLogWatchPaths(options LogWatchOptions) []string {
	seen := map[string]struct{}{}
	var paths []string
	for _, value := range options.Paths {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		cleaned := filepath.Clean(value)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		paths = append(paths, cleaned)
	}
	sortStrings(paths)
	return paths
}

func (r *Runtime) logWatchStatePath(identity Identity) string {
	return filepath.Join(filepath.Dir(identity.QueueDir), "state", "log-watch.json")
}

func loadLogWatchState(path string) (logWatchState, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return logWatchState{Logs: map[string]logFileState{}}, false, nil
	}
	if err != nil {
		return logWatchState{}, false, err
	}
	var state logWatchState
	if err := json.Unmarshal(content, &state); err != nil {
		return logWatchState{}, false, err
	}
	if state.Logs == nil {
		state.Logs = map[string]logFileState{}
	}
	return state, true, nil
}

func saveLogWatchState(path string, state logWatchState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}

func resolveLogTargets(paths []string, queueDir string) ([]logTarget, error) {
	var targets []logTarget
	seen := map[string]struct{}{}
	queueAbs, _ := filepath.Abs(queueDir)
	for _, path := range paths {
		if err := resolveLogPath(path, queueAbs, seen, &targets); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(targets, func(a logTarget, b logTarget) int {
		return strings.Compare(a.Path, b.Path)
	})
	return targets, nil
}

func resolveLogPath(path string, queueAbs string, seen map[string]struct{}, targets *[]logTarget) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() {
			addLogTarget(path, info, seen, targets)
		}
		return nil
	}
	return filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == path {
			return nil
		}
		if entry.IsDir() {
			if shouldSkipDir(current, queueAbs) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isLikelyLogFile(current) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			addLogTarget(current, info, seen, targets)
		}
		return nil
	})
}

func addLogTarget(path string, info fs.FileInfo, seen map[string]struct{}, targets *[]logTarget) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	cleaned := filepath.Clean(abs)
	if _, ok := seen[cleaned]; ok {
		return
	}
	seen[cleaned] = struct{}{}
	*targets = append(*targets, logTarget{
		Path:      cleaned,
		SizeBytes: info.Size(),
		ModTime:   info.ModTime().UTC(),
	})
}

func isLikelyLogFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(base))
	return ext == ".log" ||
		ext == ".err" ||
		ext == ".out" ||
		strings.Contains(base, "access") ||
		strings.Contains(base, "error") ||
		strings.Contains(base, "php")
}

func readNewLogLines(path string, start int64) ([]logLine, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, start, err
	}
	defer file.Close()
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, start, err
	}

	reader := bufio.NewReaderSize(file, 32<<10)
	offset := start
	readBytes := 0
	var lines []logLine
	for len(lines) < maxLogEventsPerScan && readBytes < maxLogReadBytes {
		chunk, err := reader.ReadString('\n')
		if len(chunk) > 0 {
			remaining := maxLogReadBytes - readBytes
			truncatedByScanLimit := len(chunk) > remaining
			if truncatedByScanLimit {
				chunk = chunk[:remaining]
			}
			lineOffset := offset
			offset += int64(len(chunk))
			readBytes += len(chunk)
			text := strings.TrimRight(chunk, "\r\n")
			truncatedLine := len(text) > maxLogLineBytes
			if truncatedLine {
				text = text[:maxLogLineBytes]
			}
			if strings.TrimSpace(text) != "" {
				lines = append(lines, logLine{
					Offset:    lineOffset,
					Bytes:     len(chunk),
					Text:      text,
					Truncated: truncatedLine || truncatedByScanLimit,
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, offset, err
		}
	}
	return lines, offset, nil
}

func logLineEvent(path string, line logLine) EnqueueEventInput {
	redactedLine := redaction.RedactText(line.Text)
	payload := map[string]any{
		"path":        path,
		"byte_offset": line.Offset,
		"bytes":       line.Bytes,
		"line":        redactedLine,
		"line_sha256": sha256Hex(line.Text),
		"truncated":   line.Truncated,
	}
	eventType := "log.line"
	severity := classifyLogSeverity(line.Text)
	message := fmt.Sprintf("log line observed: %s", path)
	eventTime := time.Time{}
	labels := map[string]string{
		"watcher": "log",
	}
	if parsed, ok := parseStructuredLogEvent(path, line.Text); ok {
		eventType = parsed.Type
		severity = parsed.Severity
		message = parsed.Message
		eventTime = parsed.EventTime
		labels["parser"] = parsed.Parser
		for key, value := range parsed.Payload {
			payload[key] = value
		}
	}
	return EnqueueEventInput{
		BatchID:   logLineBatchID(path, line),
		EventTime: eventTime,
		Type:      eventType,
		Target:    path,
		Severity:  severity,
		Message:   message,
		Labels:    labels,
		Payload:   payload,
	}
}

func logLineBatchID(path string, line logLine) string {
	return "log-" + sha256Hex(fmt.Sprintf("%s\n%d\n%s", path, line.Offset, line.Text))[:24]
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func classifyLogSeverity(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "php fatal error"),
		strings.Contains(lower, "fatal error"),
		strings.Contains(lower, "segmentation fault"),
		strings.Contains(lower, "emergency"),
		strings.Contains(lower, "critical"):
		return string(domain.SeverityHigh)
	case commonLogStatus(line) >= 500:
		return string(domain.SeverityMedium)
	case strings.Contains(lower, "failed password"),
		strings.Contains(lower, "authentication failure"),
		strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "error"):
		return string(domain.SeverityMedium)
	case commonLogStatus(line) >= 400,
		strings.Contains(lower, "warning"),
		strings.Contains(lower, "deprecated"):
		return string(domain.SeverityLow)
	default:
		return string(domain.SeverityInfo)
	}
}

func enrichAccessLogEventWithTor(event *EnqueueEventInput, matcher torExitMatcher) {
	if event == nil || matcher == nil || event.Type != "log.access" || event.Payload == nil {
		return
	}
	remote := payloadString(event.Payload, "remote_addr")
	if remote == "" || !matcher.Contains(remote) {
		return
	}
	metadata := matcher.Metadata()
	event.Payload["remote_is_tor"] = true
	event.Payload["remote_network"] = "tor_exit"
	event.Payload["remote_addr_sha256"] = sha256Hex(remote)
	event.Payload["remote_tags"] = appendPayloadStringTag(event.Payload["remote_tags"], "tor_exit")
	event.Payload["tor_exit_list_source"] = metadata.Source
	event.Payload["tor_exit_list_size"] = metadata.Size
	if !metadata.CheckedAt.IsZero() {
		event.Payload["tor_exit_list_checked_at"] = metadata.CheckedAt.UTC().Format(time.RFC3339)
	}
	minSeverity := string(domain.SeverityLow)
	if isSensitiveAccessPath(payloadString(event.Payload, "path")) {
		minSeverity = string(domain.SeverityMedium)
	}
	event.Severity = maxAgentSeverity(event.Severity, minSeverity)
	if !strings.Contains(strings.ToLower(event.Message), "tor") {
		event.Message = strings.TrimSpace(event.Message + " from Tor exit")
	}
}

func shouldDropNoisyLogEvent(event EnqueueEventInput) bool {
	if event.Type != "log.access" {
		return false
	}
	siteKind := strings.ToLower(strings.TrimSpace(event.Labels["site_kind"]))
	path := strings.ToLower(strings.TrimSpace(payloadString(event.Payload, "path")))
	method := strings.ToUpper(strings.TrimSpace(payloadString(event.Payload, "method")))
	status := payloadInt(event.Payload, "status_code")
	if path == "" {
		return false
	}
	if siteKind == "yii2-rbac" {
		return shouldDropNoisyYii2RBACAccessPath(path, method, status)
	}
	if siteKind == "laravel" {
		return shouldDropNoisyLaravelAccessPath(path, method, status)
	}
	if siteKind != "mautic" {
		return false
	}
	routePath := mauticRoutePath(path)
	if isMauticImportantAccessPath(routePath) {
		return false
	}
	if isMauticStaticAssetPath(path) {
		return status < 500
	}
	if isMauticRoutineTrackingPath(routePath) {
		return status < 500
	}
	if method == "GET" && status > 0 && status < 400 && isMauticLowSignalPublicPath(routePath) {
		return true
	}
	return false
}

func shouldDropNoisyYii2RBACAccessPath(path string, method string, status int) bool {
	if isYii2RBACImportantAccessPath(path) {
		return false
	}
	if status >= 500 {
		return false
	}
	if isYii2RBACStaticAssetPath(path) {
		return true
	}
	return method == "GET" && status > 0 && status < 400 && isYii2RBACLowSignalPublicPath(path)
}

func isYii2RBACImportantAccessPath(path string) bool {
	if strings.Contains(path, ".php") && !strings.HasSuffix(path, "/index.php") {
		return true
	}
	for _, marker := range []string{"/login", "/logout", "/admin", "/user", "/profile", "/rbac", "/debug", "/gii"} {
		if path == marker || strings.HasPrefix(path, marker+"/") {
			return true
		}
	}
	return false
}

func isYii2RBACStaticAssetPath(path string) bool {
	if strings.Contains(path, "/assets/") || strings.Contains(path, "/app-assets/") ||
		strings.Contains(path, "/css/") || strings.Contains(path, "/js/") ||
		strings.Contains(path, "/favicon/") {
		return true
	}
	for _, suffix := range []string{".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isYii2RBACLowSignalPublicPath(path string) bool {
	switch path {
	case "/", "/robots.txt", "/favicon.ico":
		return true
	default:
		return false
	}
}

func shouldDropNoisyLaravelAccessPath(path string, method string, status int) bool {
	path = laravelRoutePath(path)
	if isLaravelImportantAccessPath(path) {
		return false
	}
	if status >= 500 {
		return false
	}
	if isLaravelStaticAssetPath(path) {
		return true
	}
	return method == "GET" && status > 0 && status < 400 && isLaravelLowSignalPublicPath(path)
}

func laravelRoutePath(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "/index.php/") {
		return strings.TrimPrefix(path, "/index.php")
	}
	return path
}

func isLaravelImportantAccessPath(path string) bool {
	if strings.Contains(path, ".php") && !strings.HasPrefix(path, "/index.php") {
		return true
	}
	for _, marker := range []string{
		"/admin", "/api", "/dashboard", "/horizon", "/import", "/login", "/logout",
		"/permissions", "/profile", "/reports", "/roles", "/shortener", "/telescope", "/users",
	} {
		if path == marker || strings.HasPrefix(path, marker+"/") {
			return true
		}
	}
	return false
}

func isLaravelStaticAssetPath(path string) bool {
	if strings.Contains(path, "/build/") || strings.Contains(path, "/assets/") ||
		strings.Contains(path, "/vendor/") || strings.Contains(path, "/favicon/") ||
		strings.Contains(path, "/css/") || strings.Contains(path, "/js/") ||
		strings.Contains(path, "/images/") || strings.Contains(path, "/fonts/") {
		return true
	}
	for _, suffix := range []string{".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isLaravelLowSignalPublicPath(path string) bool {
	switch path {
	case "/", "/robots.txt", "/favicon.ico", "/favicon.png":
		return true
	default:
		return false
	}
}

func mauticRoutePath(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "/index.php/") {
		return strings.TrimPrefix(path, "/index.php")
	}
	return path
}

func isMauticImportantAccessPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if strings.Contains(path, ".php") && !strings.HasPrefix(path, "/index.php") {
		return true
	}
	for _, prefix := range []string{
		"/s/",
		"/api/",
		"/oauth/",
		"/installer",
		"/upgrade.php",
		"/index_dev.php",
		"/admin",
		"/login",
		"/logout",
	} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isMauticRoutineTrackingPath(path string) bool {
	for _, prefix := range []string{
		"/r/",
		"/email/",
		"/mtc/",
		"/asset/",
		"/download/",
		"/page/",
		"/form/submit",
	} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	switch path {
	case "/mtracking.gif", "/mtc.js":
		return true
	default:
		return false
	}
}

func isMauticLowSignalPublicPath(path string) bool {
	if path == "/" || path == "/index.php" {
		return true
	}
	return strings.HasPrefix(path, "/form/") ||
		strings.HasPrefix(path, "/focus/") ||
		strings.HasPrefix(path, "/campaign/")
}

func isMauticStaticAssetPath(path string) bool {
	clean := strings.Split(path, "?")[0]
	switch strings.ToLower(filepath.Ext(clean)) {
	case ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mp3", ".mp4", ".ogg", ".otf", ".pdf", ".png", ".svg", ".ttf", ".txt", ".wav", ".webm", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func payloadInt(payload map[string]any, key string) int {
	if payload == nil {
		return 0
	}
	switch value := payload[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(value))
		return parsed
	default:
		return 0
	}
}

func payloadString(payload map[string]any, key string) string {
	value, ok := payload[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func appendPayloadStringTag(value any, tag string) []string {
	seen := map[string]struct{}{}
	var tags []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		tags = append(tags, value)
	}
	switch typed := value.(type) {
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				add(text)
			}
		}
	case string:
		add(typed)
	}
	add(tag)
	return tags
}

func isSensitiveAccessPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	return path == "/wp-login.php" ||
		path == "/xmlrpc.php" ||
		strings.HasPrefix(path, "/wp-admin") ||
		strings.HasPrefix(path, "/admin") ||
		strings.HasPrefix(path, "/administrator") ||
		strings.Contains(path, "/phpmyadmin") ||
		strings.Contains(path, "/adminer") ||
		strings.Contains(path, "/manager") ||
		strings.Contains(path, "/login")
}

func maxAgentSeverity(current string, minimum string) string {
	if agentSeverityRank(current) >= agentSeverityRank(minimum) {
		return current
	}
	return minimum
}

func agentSeverityRank(value string) int {
	switch domain.Severity(strings.ToLower(strings.TrimSpace(value))) {
	case domain.SeverityCritical:
		return 4
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 1
	default:
		return 0
	}
}
