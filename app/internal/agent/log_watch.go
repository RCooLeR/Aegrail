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
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/redaction"
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
				event.App = options.App
				event.Service = options.Service
				event.Region = options.Region
				event.Labels = mergeStringMaps(event.Labels, options.Labels)
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

	if err := saveLogWatchState(statePath, logWatchState{
		Schema:    LogWatchStateSchema,
		UpdatedAt: r.now().UTC(),
		Logs:      current,
	}); err != nil {
		return LogWatchResult{}, err
	}
	return result, nil
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
