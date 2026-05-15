package agent

import (
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
)

const WatchStateSchema = "aegrail.agent.watch_state.v1"
const maxWatchedHashBytes = 64 << 20
const watchLockStaleAfter = 5 * time.Minute
const watchFullHashEvery = time.Hour

type WatchOptions struct {
	Paths     []string
	Root      string
	Profiles  []string
	Exclude   []string
	StatePath string
	NoEvents  bool
	App       string
	Service   string
	Region    string
	Labels    map[string]string
}

type WatchResult struct {
	WatchedFiles int
	Queued       int
	Baselined    bool
	StatePath    string
	HashedFiles  int
	ReusedHashes int
}

type watchState struct {
	Schema         string               `json:"schema"`
	UpdatedAt      time.Time            `json:"updated_at"`
	LastFullHashAt time.Time            `json:"last_full_hash_at,omitempty"`
	Files          map[string]fileState `json:"files"`
}

type fileState struct {
	Path         string    `json:"path"`
	RelativePath string    `json:"relative_path,omitempty"`
	SizeBytes    int64     `json:"size_bytes"`
	ModTime      time.Time `json:"mod_time"`
	SHA256       string    `json:"sha256,omitempty"`
	HashSkipped  bool      `json:"hash_skipped,omitempty"`
}

func (r *Runtime) ScanWatchedPaths(ctx context.Context, options WatchOptions) (WatchResult, error) {
	identity, err := r.LoadIdentity(ctx)
	if err != nil {
		return WatchResult{}, err
	}
	paths, err := ResolveWatchPaths(options)
	if err != nil {
		return WatchResult{}, err
	}
	if len(paths) == 0 {
		return WatchResult{}, errors.New("at least one watch path is required")
	}
	statePath := strings.TrimSpace(options.StatePath)
	if statePath == "" {
		statePath = r.watchStatePath(identity)
	}
	unlock, err := acquireWatchLock(statePath)
	if err != nil {
		return WatchResult{}, err
	}
	defer unlock()

	previous, hadState, err := loadWatchState(statePath)
	if err != nil {
		return WatchResult{}, err
	}
	now := r.now().UTC()
	forceFullHash, err := shouldForceFullWatchHash(previous, hadState, now)
	if err != nil {
		return WatchResult{}, err
	}
	scan, err := scanPaths(paths, identity.QueueDir, options.Root, options.Exclude, previous.Files, forceFullHash)
	if err != nil {
		return WatchResult{}, err
	}
	current := scan.Files

	result := WatchResult{
		WatchedFiles: len(current),
		Baselined:    !hadState,
		StatePath:    statePath,
		HashedFiles:  scan.HashedFiles,
		ReusedHashes: scan.ReusedHashes,
	}
	if hadState {
		events := diffWatchState(previous.Files, current)
		if options.NoEvents {
			return result, saveWatchState(statePath, watchState{
				Schema:         WatchStateSchema,
				UpdatedAt:      now,
				LastFullHashAt: watchLastFullHashAt(previous, forceFullHash, now),
				Files:          current,
			})
		}
		for _, event := range events {
			event.App = options.App
			event.Service = options.Service
			event.Region = options.Region
			event.Labels = mergeStringMaps(event.Labels, options.Labels)
			if _, _, err := r.EnqueueEvent(ctx, event); err != nil {
				return WatchResult{}, err
			}
			result.Queued++
		}
		if len(events) == 0 {
			heartbeat := fileScanCompletedEvent(len(current), false)
			heartbeat.App = options.App
			heartbeat.Service = options.Service
			heartbeat.Region = options.Region
			heartbeat.Labels = mergeStringMaps(heartbeat.Labels, options.Labels)
			if _, _, err := r.EnqueueEvent(ctx, heartbeat); err != nil {
				return WatchResult{}, err
			}
			result.Queued++
		}
	}
	if err := saveWatchState(statePath, watchState{
		Schema:         WatchStateSchema,
		UpdatedAt:      now,
		LastFullHashAt: watchLastFullHashAt(previous, forceFullHash, now),
		Files:          current,
	}); err != nil {
		return WatchResult{}, err
	}
	return result, nil
}

func shouldForceFullWatchHash(previous watchState, hadState bool, now time.Time) (bool, error) {
	if !hadState {
		return true, nil
	}
	interval, err := watchFullHashInterval()
	if err != nil {
		return false, err
	}
	if interval <= 0 {
		return false, nil
	}
	if previous.LastFullHashAt.IsZero() {
		return true, nil
	}
	return !now.Before(previous.LastFullHashAt.Add(interval)), nil
}

func watchLastFullHashAt(previous watchState, forceFullHash bool, now time.Time) time.Time {
	if forceFullHash {
		return now
	}
	return previous.LastFullHashAt
}

func watchFullHashInterval() (time.Duration, error) {
	if value := strings.TrimSpace(os.Getenv("AEGRAIL_WATCH_FULL_HASH_INTERVAL")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("invalid AEGRAIL_WATCH_FULL_HASH_INTERVAL value: %w", err)
		}
		return parsed, nil
	}
	return watchFullHashEvery, nil
}

func ResolveWatchPaths(options WatchOptions) ([]string, error) {
	seen := map[string]struct{}{}
	var paths []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		cleaned := filepath.Clean(value)
		if _, ok := seen[cleaned]; ok {
			return
		}
		seen[cleaned] = struct{}{}
		paths = append(paths, cleaned)
	}
	for _, path := range options.Paths {
		add(path)
	}
	root := strings.TrimSpace(options.Root)
	if root != "" {
		for _, profile := range options.Profiles {
			profilePaths := profileWatchPaths(root, profile)
			if len(profilePaths) == 0 {
				return nil, fmt.Errorf("unknown watch profile %q", profile)
			}
			for _, path := range profilePaths {
				add(path)
			}
		}
	}
	if root != "" && len(options.Profiles) == 0 && len(paths) == 0 {
		add(root)
	}
	sortStrings(paths)
	return paths, nil
}

func profileWatchPaths(root string, profile string) []string {
	root = filepath.Clean(root)
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "wordpress", "wp", "woocommerce":
		return []string{
			filepath.Join(root, "wp-config.php"),
			filepath.Join(root, "wp-config-local.php"),
			filepath.Join(root, "wp-content", "uploads"),
			filepath.Join(root, "wp-content", "plugins"),
			filepath.Join(root, "wp-content", "themes"),
		}
	case "prestashop", "ps":
		return []string{
			filepath.Join(root, "app", "config"),
			filepath.Join(root, "config"),
			filepath.Join(root, "img"),
			filepath.Join(root, "modules"),
			filepath.Join(root, "themes"),
			filepath.Join(root, "upload"),
			filepath.Join(root, "var", "logs"),
		}
	default:
		return nil
	}
}

func (r *Runtime) watchStatePath(identity Identity) string {
	return filepath.Join(filepath.Dir(identity.QueueDir), "state", "file-watch.json")
}

func acquireWatchLock(statePath string) (func(), error) {
	base := strings.TrimSuffix(filepath.Base(statePath), filepath.Ext(statePath))
	lockPath := filepath.Join(filepath.Dir(statePath), base+".lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	if err := tryRecoverWatchLock(lockPath); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("watch state is locked by another agent process: %s", lockPath)
	}
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(file, "pid=%d\ncreated_at=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	if err := file.Close(); err != nil {
		_ = os.Remove(lockPath)
		return nil, err
	}
	return func() {
		_ = os.Remove(lockPath)
	}, nil
}

func watchLockTTL() (time.Duration, error) {
	if value := strings.TrimSpace(os.Getenv("AEGRAIL_WATCH_LOCK_STALE_AFTER")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	}
	return watchLockStaleAfter, nil
}

func tryRecoverWatchLock(lockPath string) error {
	info, err := os.Stat(lockPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	staleAfter, err := watchLockTTL()
	if err != nil {
		return fmt.Errorf("invalid AEGRAIL_WATCH_LOCK_STALE_AFTER value: %w", err)
	}
	if staleAfter <= 0 {
		return nil
	}
	if time.Since(info.ModTime()) <= staleAfter {
		return nil
	}
	if err := os.Remove(lockPath); err != nil {
		return fmt.Errorf("failed to reclaim stale watch lock %s: %w", lockPath, err)
	}
	return nil
}

func loadWatchState(path string) (watchState, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return watchState{Files: map[string]fileState{}}, false, nil
	}
	if err != nil {
		return watchState{}, false, err
	}
	var state watchState
	if err := json.Unmarshal(content, &state); err != nil {
		return watchState{}, false, err
	}
	if state.Files == nil {
		state.Files = map[string]fileState{}
	}
	return state, true, nil
}

func saveWatchState(path string, state watchState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}

type watchScanResult struct {
	Files        map[string]fileState
	HashedFiles  int
	ReusedHashes int
}

func scanPaths(paths []string, queueDir string, root string, exclude []string, previous map[string]fileState, forceFullHash bool) (watchScanResult, error) {
	result := watchScanResult{Files: map[string]fileState{}}
	queueAbs, _ := filepath.Abs(queueDir)
	rootAbs := ""
	if strings.TrimSpace(root) != "" {
		rootAbs, _ = filepath.Abs(root)
	}
	excludeAbs := resolveExcludePaths(exclude)
	for _, path := range paths {
		if err := scanPath(path, queueAbs, rootAbs, excludeAbs, previous, forceFullHash, &result); err != nil {
			return watchScanResult{}, err
		}
	}
	return result, nil
}

func scanPath(path string, queueAbs string, rootAbs string, excludeAbs []string, previous map[string]fileState, forceFullHash bool, result *watchScanResult) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if isExcludedPath(path, excludeAbs) {
		return nil
	}
	if !info.IsDir() {
		if shouldSkipNoisyPath(path) {
			return nil
		}
		state, err := buildFileState(path, info, rootAbs, previous, forceFullHash, result)
		if err != nil {
			return err
		}
		result.Files[state.Path] = state
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
			if shouldSkipDir(current, queueAbs) || isExcludedPath(current, excludeAbs) {
				return filepath.SkipDir
			}
			return nil
		}
		if isExcludedPath(current, excludeAbs) {
			return nil
		}
		if shouldSkipNoisyPath(current) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		state, err := buildFileState(current, info, rootAbs, previous, forceFullHash, result)
		if err != nil {
			return err
		}
		result.Files[state.Path] = state
		return nil
	})
}

func resolveExcludePaths(exclude []string) []string {
	paths := make([]string, 0, len(exclude))
	for _, value := range exclude {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		abs, err := filepath.Abs(value)
		if err != nil {
			continue
		}
		paths = append(paths, filepath.Clean(abs))
	}
	sortStrings(paths)
	return paths
}

func isExcludedPath(path string, excludeAbs []string) bool {
	if len(excludeAbs) == 0 {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	cleaned := filepath.Clean(abs)
	for _, exclude := range excludeAbs {
		if cleaned == exclude || strings.HasPrefix(cleaned, exclude+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func shouldSkipDir(path string, queueAbs string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == ".git" || base == ".aegrail" || isNoisyRuntimeDir(base) {
		return true
	}
	abs, err := filepath.Abs(path)
	if err == nil && queueAbs != "" && strings.HasPrefix(abs, queueAbs) {
		return true
	}
	return false
}

func isNoisyRuntimeDir(base string) bool {
	switch {
	case strings.EqualFold(strings.TrimSpace(base), ".cache"), strings.EqualFold(strings.TrimSpace(base), "cache"):
		return true
	case isNoisyCacheDir(base), strings.EqualFold(strings.TrimSpace(base), "tmp"), strings.EqualFold(strings.TrimSpace(base), "temp"):
		return true
	default:
		return false
	}
}

func shouldSkipNoisyPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	if hasNoisyPathSegment(normalized) {
		return true
	}
	if !isWritableAssetPath(normalized) {
		return false
	}
	switch filepath.Ext(normalized) {
	case ".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".mp3", ".mp4", ".ogg", ".pdf", ".png", ".wav", ".webm", ".webp":
		return true
	default:
		return false
	}
}

func isNoisyCacheDir(base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	if base == "" {
		return false
	}
	if strings.HasPrefix(base, ".cache") {
		suffix := strings.TrimPrefix(base, ".cache")
		if suffix == "" {
			return true
		}
		switch suffix[0] {
		case '_', '-', '.':
			return true
		}
	}
	if !strings.HasPrefix(base, "cache") {
		return false
	}
	if base == "cache" {
		return true
	}
	suffix := strings.TrimPrefix(base, "cache")
	if len(suffix) == 0 {
		return true
	}
	switch suffix[0] {
	case '_', '-', '.':
		return true
	default:
		return false
	}
}

func hasNoisyPathSegment(path string) bool {
	path = strings.ToLower(filepath.ToSlash(path))
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if isNoisyCacheDir(part) || part == ".cache" {
			return true
		}
	}
	return false
}

func isWritableAssetPath(path string) bool {
	return hasPathSegment(path, "uploads") ||
		hasPathSegment(path, "upload") ||
		hasPathSegment(path, "img")
}

func hasPathSegment(path string, segment string) bool {
	segment = strings.ToLower(strings.Trim(segment, "/"))
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part == segment {
			return true
		}
	}
	return false
}

func buildFileState(path string, info fs.FileInfo, rootAbs string, previous map[string]fileState, forceFullHash bool, scan *watchScanResult) (fileState, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fileState{}, err
	}
	cleaned := filepath.Clean(abs)
	state := fileState{
		Path:      cleaned,
		SizeBytes: info.Size(),
		ModTime:   info.ModTime().UTC(),
	}
	if rootAbs != "" {
		if relativePath, ok := appRelativePath(rootAbs, cleaned); ok {
			state.RelativePath = relativePath
		}
	}
	if previousState, ok := previous[state.Path]; !forceFullHash && ok && canReuseFileHash(previousState, state) {
		state.SHA256 = previousState.SHA256
		state.HashSkipped = previousState.HashSkipped
		scan.ReusedHashes++
		return state, nil
	}
	if info.Size() > maxWatchedHashBytes {
		state.HashSkipped = true
		return state, nil
	}
	hash, err := hashFile(path)
	if err != nil {
		return fileState{}, err
	}
	state.SHA256 = hash
	scan.HashedFiles++
	return state, nil
}

func canReuseFileHash(previous fileState, current fileState) bool {
	if previous.Path == "" || previous.Path != current.Path {
		return false
	}
	if previous.SizeBytes != current.SizeBytes || !previous.ModTime.Equal(current.ModTime) {
		return false
	}
	if previous.HashSkipped {
		return true
	}
	return previous.SHA256 != ""
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func diffWatchState(previous map[string]fileState, current map[string]fileState) []EnqueueEventInput {
	var events []EnqueueEventInput
	for path, currentState := range current {
		previousState, ok := previous[path]
		if !ok {
			events = append(events, fileEvent("file.created", currentState, fileState{}))
			continue
		}
		if fileChanged(previousState, currentState) {
			events = append(events, fileEvent("file.modified", currentState, previousState))
		}
	}
	for path, previousState := range previous {
		if _, ok := current[path]; !ok {
			if shouldSkipNoisyPath(previousState.Path) {
				continue
			}
			events = append(events, fileEvent("file.deleted", previousState, fileState{}))
		}
	}
	slices.SortFunc(events, func(a EnqueueEventInput, b EnqueueEventInput) int {
		return strings.Compare(a.Target, b.Target)
	})
	return events
}

func fileScanCompletedEvent(watchedFiles int, baselined bool) EnqueueEventInput {
	return EnqueueEventInput{
		Type:     "file.scan.completed",
		Severity: string(domain.SeverityInfo),
		Message:  fmt.Sprintf("File scan completed with %d watched file(s)", watchedFiles),
		Labels: map[string]string{
			"watcher":   "file",
			"collector": "files",
		},
		Payload: map[string]any{
			"watched_files": watchedFiles,
			"baselined":     baselined,
		},
	}
}

func fileChanged(previous fileState, current fileState) bool {
	if previous.HashSkipped != current.HashSkipped {
		return true
	}
	if !current.HashSkipped && previous.SHA256 != "" && current.SHA256 != "" {
		return previous.SHA256 != current.SHA256
	}
	return previous.SizeBytes != current.SizeBytes ||
		!previous.ModTime.Equal(current.ModTime) ||
		previous.SHA256 != current.SHA256
}

func fileEvent(eventType string, current fileState, previous fileState) EnqueueEventInput {
	severity := classifyFileSeverity(eventType, current.Path)
	relativePath := current.RelativePath
	if relativePath == "" {
		relativePath = previous.RelativePath
	}
	eventPath := current.Path
	if relativePath != "" {
		eventPath = relativePath
	}
	payload := map[string]any{
		"path":         eventPath,
		"size_bytes":   current.SizeBytes,
		"mod_time":     current.ModTime.Format(time.RFC3339Nano),
		"hash_skipped": current.HashSkipped,
	}
	if current.SHA256 != "" {
		payload["sha256"] = current.SHA256
	}
	if relativePath != "" {
		payload["relative_path"] = relativePath
	}
	if previous.Path != "" {
		payload["previous_size_bytes"] = previous.SizeBytes
		payload["previous_mod_time"] = previous.ModTime.Format(time.RFC3339Nano)
		if previous.SHA256 != "" {
			payload["previous_sha256"] = previous.SHA256
		}
	}
	return EnqueueEventInput{
		BatchID:  fileEventBatchID(eventType, current, previous),
		Type:     eventType,
		Target:   eventPath,
		Severity: severity,
		Message:  fileEventMessage(eventType, eventPath),
		Labels: map[string]string{
			"watcher": "file",
		},
		Payload: payload,
	}
}

func fileEventBatchID(eventType string, current fileState, previous fileState) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(
		hash,
		"%s\n%s\n%d\n%s\n%s\n%t\n%d\n%s\n%s\n%t",
		eventType,
		current.Path,
		current.SizeBytes,
		current.ModTime.Format(time.RFC3339Nano),
		current.SHA256,
		current.HashSkipped,
		previous.SizeBytes,
		previous.ModTime.Format(time.RFC3339Nano),
		previous.SHA256,
		previous.HashSkipped,
	)
	return "file-" + hex.EncodeToString(hash.Sum(nil))[:24]
}

func classifyFileSeverity(eventType string, path string) string {
	path = strings.ToLower(filepath.ToSlash(path))
	if eventType == "file.deleted" {
		return string(domain.SeverityLow)
	}
	if strings.HasSuffix(path, "/wp-config.php") ||
		strings.HasSuffix(path, "/wp-config-local.php") ||
		strings.Contains(path, "/config/settings.inc.php") ||
		strings.Contains(path, "/app/config/parameters.php") ||
		strings.HasSuffix(path, "/.env") {
		return string(domain.SeverityHigh)
	}
	if strings.HasSuffix(path, ".php") || strings.HasSuffix(path, ".phtml") || strings.HasSuffix(path, ".phar") {
		if strings.Contains(path, "/uploads/") || strings.Contains(path, "/upload/") || strings.Contains(path, "/img/") {
			return string(domain.SeverityHigh)
		}
		return string(domain.SeverityMedium)
	}
	if strings.Contains(path, "/wp-content/plugins/") ||
		strings.Contains(path, "/wp-content/themes/") ||
		strings.Contains(path, "/modules/") ||
		strings.Contains(path, "/themes/") {
		return string(domain.SeverityMedium)
	}
	return string(domain.SeverityInfo)
}

func fileEventMessage(eventType string, path string) string {
	switch eventType {
	case "file.created":
		return fmt.Sprintf("file created: %s", path)
	case "file.modified":
		return fmt.Sprintf("file modified: %s", path)
	case "file.deleted":
		return fmt.Sprintf("file deleted: %s", path)
	default:
		return fmt.Sprintf("file event: %s", path)
	}
}

func sortStrings(values []string) {
	slices.Sort(values)
}

func appRelativePath(rootAbs string, pathAbs string) (string, bool) {
	relativePath, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || relativePath == "." || strings.HasPrefix(relativePath, "..") || filepath.IsAbs(relativePath) {
		return "", false
	}
	return filepath.ToSlash(relativePath), true
}
