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

	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/fsutil"
)

const WatchStateSchema = "aegrail.agent.watch_state.v1"
const maxWatchedHashBytes = 64 << 20
const maxKnownPHPGuardBytes = 64 << 10
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
	SkippedFiles int
}

type watchState struct {
	Schema         string               `json:"schema"`
	UpdatedAt      time.Time            `json:"updated_at"`
	LastFullHashAt time.Time            `json:"last_full_hash_at,omitempty"`
	Files          map[string]fileState `json:"files"`
}

type fileState struct {
	Path             string    `json:"path"`
	RelativePath     string    `json:"relative_path,omitempty"`
	SizeBytes        int64     `json:"size_bytes"`
	ModTime          time.Time `json:"mod_time"`
	StatusChangeTime time.Time `json:"status_change_time,omitempty"`
	BirthTime        time.Time `json:"birth_time,omitempty"`
	ObservedAt       time.Time `json:"observed_at,omitempty"`
	SHA256           string    `json:"sha256,omitempty"`
	HashSkipped      bool      `json:"hash_skipped,omitempty"`
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
		SkippedFiles: scan.SkippedFiles,
	}
	if hadState {
		events := diffWatchState(previous.Files, current, now)
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
			if !forceFullHash && len(previous.Files) == len(current) {
				return result, nil
			}
		}
	} else if !options.NoEvents && len(current) > 0 {
		baseline := fileBaselineCreatedEvent(len(current))
		baseline.App = options.App
		baseline.Service = options.Service
		baseline.Region = options.Region
		baseline.Labels = mergeStringMaps(baseline.Labels, options.Labels)
		if _, _, err := r.EnqueueEvent(ctx, baseline); err != nil {
			return WatchResult{}, err
		}
		result.Queued++
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
	case "mautic":
		return []string{
			filepath.Join(root, ".env"),
			filepath.Join(root, "app", "config"),
			filepath.Join(root, "config"),
			filepath.Join(root, "media"),
			filepath.Join(root, "plugins"),
			filepath.Join(root, "themes"),
		}
	case "yii2-rbac":
		return []string{
			filepath.Join(root, "composer.json"),
			filepath.Join(root, "composer.lock"),
			filepath.Join(root, "yii"),
			filepath.Join(root, "requirements.php"),
			filepath.Join(root, "firewall.php"),
			filepath.Join(root, "config"),
			filepath.Join(root, "components"),
			filepath.Join(root, "controllers"),
			filepath.Join(root, "helpers"),
			filepath.Join(root, "models"),
			filepath.Join(root, "migrations"),
			filepath.Join(root, "traits"),
			filepath.Join(root, "widgets"),
			filepath.Join(root, "mail"),
			filepath.Join(root, "mailer"),
			filepath.Join(root, "views"),
			filepath.Join(root, "commands"),
			filepath.Join(root, "web", "index.php"),
			filepath.Join(root, "web", "index-dev.php"),
			filepath.Join(root, "web", "index-test.php"),
			filepath.Join(root, "web", ".htaccess"),
		}
	case "laravel":
		return []string{
			filepath.Join(root, ".env"),
			filepath.Join(root, "artisan"),
			filepath.Join(root, "composer.json"),
			filepath.Join(root, "composer.lock"),
			filepath.Join(root, "package.json"),
			filepath.Join(root, "package-lock.json"),
			filepath.Join(root, "vite.config.js"),
			filepath.Join(root, "tailwind.config.js"),
			filepath.Join(root, "postcss.config.js"),
			filepath.Join(root, "app"),
			filepath.Join(root, "bootstrap", "app.php"),
			filepath.Join(root, "bootstrap", "providers.php"),
			filepath.Join(root, "config"),
			filepath.Join(root, "database", "migrations"),
			filepath.Join(root, "database", "seeders"),
			filepath.Join(root, "resources", "views"),
			filepath.Join(root, "resources", "js"),
			filepath.Join(root, "resources", "css"),
			filepath.Join(root, "routes"),
			filepath.Join(root, "public", "index.php"),
			filepath.Join(root, "public", ".htaccess"),
		}
	case "static", "static-site", "static-html":
		return []string{
			root,
		}
	case "react":
		return []string{
			filepath.Join(root, ".env"),
			filepath.Join(root, ".env.local"),
			filepath.Join(root, "package.json"),
			filepath.Join(root, "package-lock.json"),
			filepath.Join(root, "pnpm-lock.yaml"),
			filepath.Join(root, "yarn.lock"),
			filepath.Join(root, "vite.config.js"),
			filepath.Join(root, "vite.config.ts"),
			filepath.Join(root, "webpack.config.js"),
			filepath.Join(root, "webpack.config.ts"),
			filepath.Join(root, "next.config.js"),
			filepath.Join(root, "next.config.mjs"),
			filepath.Join(root, "tailwind.config.js"),
			filepath.Join(root, "tailwind.config.ts"),
			filepath.Join(root, "postcss.config.js"),
			filepath.Join(root, "tsconfig.json"),
			filepath.Join(root, "src"),
			filepath.Join(root, "app"),
			filepath.Join(root, "pages"),
			filepath.Join(root, "components"),
			filepath.Join(root, "public"),
			filepath.Join(root, "index.html"),
		}
	case "node", "nodejs", "node.js":
		return []string{
			filepath.Join(root, ".env"),
			filepath.Join(root, ".env.local"),
			filepath.Join(root, "package.json"),
			filepath.Join(root, "package-lock.json"),
			filepath.Join(root, "pnpm-lock.yaml"),
			filepath.Join(root, "yarn.lock"),
			filepath.Join(root, "server.js"),
			filepath.Join(root, "server.ts"),
			filepath.Join(root, "index.js"),
			filepath.Join(root, "index.ts"),
			filepath.Join(root, "app.js"),
			filepath.Join(root, "app.ts"),
			filepath.Join(root, "src"),
			filepath.Join(root, "app"),
			filepath.Join(root, "config"),
			filepath.Join(root, "routes"),
			filepath.Join(root, "controllers"),
			filepath.Join(root, "middleware"),
			filepath.Join(root, "models"),
			filepath.Join(root, "prisma"),
			filepath.Join(root, "migrations"),
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
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomicSync(path, append(content, '\n'), 0o600)
}

type watchScanResult struct {
	Files        map[string]fileState
	StartedAt    time.Time
	HashedFiles  int
	ReusedHashes int
	SkippedFiles int
}

func scanPaths(paths []string, queueDir string, root string, exclude []string, previous map[string]fileState, forceFullHash bool) (watchScanResult, error) {
	result := watchScanResult{Files: map[string]fileState{}, StartedAt: time.Now().UTC()}
	queueAbs, err := filepath.Abs(queueDir)
	if err != nil {
		queueAbs = queueDir
	}
	rootAbs := ""
	if strings.TrimSpace(root) != "" {
		rootAbs, err = filepath.Abs(root)
		if err != nil {
			rootAbs = root
		}
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
			result.SkippedFiles++
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
	if err == nil && queueAbs != "" && pathWithinOrEqual(queueAbs, abs) {
		return true
	}
	return false
}

func pathWithinOrEqual(parent string, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == "" || child == "" {
		return false
	}
	return child == parent || strings.HasPrefix(child, parent+string(filepath.Separator))
}

func isNoisyRuntimeDir(base string) bool {
	switch {
	case strings.EqualFold(strings.TrimSpace(base), ".cache"), strings.EqualFold(strings.TrimSpace(base), "cache"):
		return true
	case isNoisyCacheDir(base),
		strings.EqualFold(strings.TrimSpace(base), "logs"),
		strings.EqualFold(strings.TrimSpace(base), "sessions"),
		strings.EqualFold(strings.TrimSpace(base), "spool"),
		strings.EqualFold(strings.TrimSpace(base), "tmp"),
		strings.EqualFold(strings.TrimSpace(base), "temp"),
		strings.EqualFold(strings.TrimSpace(base), "var"):
		return true
	default:
		return false
	}
}

func shouldSkipNoisyPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	if hasNoisyPathSegment(normalized) || isKnownRuntimePath(normalized) || isLowSignalGeneratedAssetPath(normalized) {
		return true
	}
	if !isWritableAssetPath(normalized) {
		return isLowSignalStaticAssetPath(normalized)
	}
	switch filepath.Ext(normalized) {
	case ".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".mp3", ".mp4", ".ogg", ".pdf", ".png", ".wav", ".webm", ".webp":
		return true
	default:
		return false
	}
}

func isLowSignalStaticAssetPath(path string) bool {
	if !isCodePackagePath(path) && !isStaticAssetTreePath(path) {
		return false
	}
	switch filepath.Ext(path) {
	case ".avif", ".bmp", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".map", ".mp3", ".mp4", ".ogg", ".otf", ".pdf", ".png", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func isLowSignalGeneratedAssetPath(path string) bool {
	if !isGeneratedAssetPath(path) {
		return false
	}
	switch filepath.Ext(path) {
	case ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".json", ".map", ".mp3", ".mp4", ".ogg", ".otf", ".pdf", ".png", ".svg", ".ttf", ".txt", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xml":
		return true
	default:
		return false
	}
}

func isStaticAssetTreePath(path string) bool {
	return hasPathSegment(path, "assets") ||
		hasPathSegment(path, "asset") ||
		hasPathSegment(path, "images") ||
		hasPathSegment(path, "image") ||
		hasPathSegment(path, "img") ||
		hasPathSegment(path, "fonts") ||
		hasPathSegment(path, "font") ||
		hasPathSegment(path, "media") ||
		hasPathSegment(path, "videos") ||
		hasPathSegment(path, "video")
}

func isGeneratedAssetPath(path string) bool {
	path = "/" + strings.Trim(strings.ToLower(filepath.ToSlash(path)), "/") + "/"
	return strings.Contains(path, "/public/build/") ||
		strings.Contains(path, "/public/vendor/") ||
		strings.Contains(path, "/build/") ||
		strings.Contains(path, "/dist/") ||
		strings.Contains(path, "/node_modules/") ||
		strings.Contains(path, "/bower_components/") ||
		strings.Contains(path, "/modern-admin-html-template/")
}

func isCodePackagePath(path string) bool {
	return strings.Contains(path, "/wp-content/plugins/") ||
		strings.Contains(path, "/wp-content/themes/") ||
		strings.Contains(path, "/modules/") ||
		strings.Contains(path, "/plugins/") ||
		strings.Contains(path, "/themes/")
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
		if isNoisyCacheDir(part) || part == ".cache" || isDependencyInstallSegment(part) {
			return true
		}
	}
	return false
}

func isDependencyInstallSegment(part string) bool {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "node_modules", "bower_components":
		return true
	default:
		return false
	}
}

func isKnownRuntimePath(path string) bool {
	path = "/" + strings.Trim(strings.ToLower(filepath.ToSlash(path)), "/") + "/"
	return strings.Contains(path, "/storage/framework/") ||
		strings.Contains(path, "/storage/logs/") ||
		strings.Contains(path, "/storage/debugbar/") ||
		strings.Contains(path, "/bootstrap/cache/") ||
		strings.Contains(path, "/var/cache/") ||
		strings.Contains(path, "/var/log/") ||
		strings.Contains(path, "/var/logs/") ||
		strings.Contains(path, "/app/cache/") ||
		strings.Contains(path, "/app/logs/") ||
		strings.Contains(path, "/modules/") && strings.Contains(path, "/logs/") ||
		strings.Contains(path, "/plugins/") && strings.Contains(path, "/logs/") ||
		strings.Contains(path, "/themes/") && strings.Contains(path, "/logs/")
}

func isWritableAssetPath(path string) bool {
	return hasPathSegment(path, "uploads") ||
		hasPathSegment(path, "upload") ||
		hasPathSegment(path, "img") ||
		hasPathSegment(path, "media")
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
	times := fileTimestampEvidence(info)
	observedAt := scan.StartedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	state := fileState{
		Path:             cleaned,
		SizeBytes:        info.Size(),
		ModTime:          times.ModTime,
		StatusChangeTime: times.StatusChangeTime,
		BirthTime:        times.BirthTime,
		ObservedAt:       observedAt.UTC(),
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
	if !previous.StatusChangeTime.IsZero() && !current.StatusChangeTime.IsZero() && !previous.StatusChangeTime.Equal(current.StatusChangeTime) {
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

func diffWatchState(previous map[string]fileState, current map[string]fileState, observedAt time.Time) []EnqueueEventInput {
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
			if observedAt.IsZero() {
				observedAt = time.Now().UTC()
			}
			previousState.ObservedAt = observedAt.UTC()
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

func fileBaselineCreatedEvent(watchedFiles int) EnqueueEventInput {
	return EnqueueEventInput{
		Type:     "file.baseline.created",
		Severity: string(domain.SeverityInfo),
		Message:  fmt.Sprintf("File baseline created with %d watched file(s)", watchedFiles),
		Labels: map[string]string{
			"watcher":   "file",
			"collector": "files",
		},
		Payload: map[string]any{
			"watched_files": watchedFiles,
			"baselined":     true,
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
	statusChangeComparable := !previous.StatusChangeTime.IsZero() && !current.StatusChangeTime.IsZero()
	return previous.SizeBytes != current.SizeBytes ||
		!previous.ModTime.Equal(current.ModTime) ||
		(statusChangeComparable && !previous.StatusChangeTime.Equal(current.StatusChangeTime)) ||
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
	timing := fileEventTiming(eventType, current, previous)
	payload := map[string]any{
		"path":         eventPath,
		"size_bytes":   current.SizeBytes,
		"mod_time":     current.ModTime.Format(time.RFC3339Nano),
		"hash_skipped": current.HashSkipped,
	}
	addFileTimePayload(payload, "observed_at", current.ObservedAt)
	addFileTimePayload(payload, "status_change_time", current.StatusChangeTime)
	addFileTimePayload(payload, "birth_time", current.BirthTime)
	addFileTimePayload(payload, "event_time", timing.EventTime)
	payload["event_time_source"] = timing.Source
	payload["event_time_confidence"] = timing.Confidence
	if timing.Backdated {
		payload["timestamp_backdated"] = true
		payload["timestamp_note"] = timing.Note
	}
	if timing.Future {
		payload["timestamp_future"] = true
		payload["timestamp_note"] = timing.Note
	}
	if current.SHA256 != "" {
		payload["sha256"] = current.SHA256
	}
	if relativePath != "" {
		payload["relative_path"] = relativePath
	}
	addFileFrameworkEvidence(payload, eventPath)
	if kind, ok := detectKnownBenignPHPGuard(eventType, current.Path, current.SizeBytes); ok {
		severity = string(domain.SeverityInfo)
		payload["file_kind"] = kind
		payload["file_role"] = "directory_guard"
		payload["file_role_confidence"] = "high"
	}
	if previous.Path != "" {
		payload["previous_size_bytes"] = previous.SizeBytes
		payload["previous_mod_time"] = previous.ModTime.Format(time.RFC3339Nano)
		addFileTimePayload(payload, "previous_status_change_time", previous.StatusChangeTime)
		addFileTimePayload(payload, "previous_birth_time", previous.BirthTime)
		if previous.SHA256 != "" {
			payload["previous_sha256"] = previous.SHA256
		}
	}
	return EnqueueEventInput{
		BatchID:   fileEventBatchID(eventType, current, previous),
		EventTime: timing.EventTime,
		Type:      eventType,
		Target:    eventPath,
		Severity:  severity,
		Message:   fileEventMessage(eventType, eventPath),
		Labels: map[string]string{
			"watcher": "file",
		},
		Payload: payload,
	}
}

type fileEvidenceDetails struct {
	Platform        string
	Area            string
	Component       string
	DeployEvidence  bool
	SecurityContext string
}

func addFileFrameworkEvidence(payload map[string]any, path string) {
	evidence := detectFileEvidence(path)
	if evidence.Platform != "" {
		payload["platform_hint"] = evidence.Platform
	}
	if evidence.Area != "" {
		payload["file_area"] = evidence.Area
	}
	if evidence.Component != "" {
		payload["framework_component"] = evidence.Component
	}
	if evidence.DeployEvidence {
		payload["deploy_evidence"] = true
	}
	if evidence.SecurityContext != "" {
		payload["security_context"] = evidence.SecurityContext
	}
}

func detectFileEvidence(path string) fileEvidenceDetails {
	normalized := strings.Trim(strings.ToLower(filepath.ToSlash(path)), "/")
	padded := "/" + normalized + "/"
	base := filepath.Base(normalized)
	ext := filepath.Ext(normalized)
	isPHP := ext == ".php" || ext == ".phtml" || ext == ".phar"

	if isDependencyManifest(base) {
		return fileEvidenceDetails{Area: "dependency_manifest", DeployEvidence: true}
	}
	if isBuildConfig(base) {
		return fileEvidenceDetails{Area: "build_config", DeployEvidence: true}
	}
	if base == ".env" {
		return fileEvidenceDetails{Area: "config", Component: "environment", DeployEvidence: true}
	}
	if isReactEntrypoint(normalized, base) {
		return fileEvidenceDetails{Platform: "react", Area: "frontend_source", Component: "entrypoint", DeployEvidence: true}
	}
	if isStaticEntrypoint(normalized, base) {
		return fileEvidenceDetails{Platform: "static", Area: "public_entrypoint", Component: "document", DeployEvidence: true}
	}
	if isNodeJSSourcePath(padded, base, ext) {
		return fileEvidenceDetails{Platform: "nodejs", Area: "backend_source", Component: nodeJSComponentForPath(padded, base), DeployEvidence: true}
	}

	switch {
	case strings.Contains(padded, "/wp-content/plugins/"):
		return fileEvidenceDetails{Platform: "wordpress", Area: "extension", Component: "plugin", DeployEvidence: true}
	case strings.Contains(padded, "/wp-content/themes/"):
		return fileEvidenceDetails{Platform: "wordpress", Area: "extension", Component: "theme", DeployEvidence: true}
	case strings.Contains(padded, "/wp-content/uploads/"):
		return writableAssetEvidence("wordpress", isPHP)
	case strings.HasSuffix(normalized, "wp-config.php") || strings.HasSuffix(normalized, "wp-config-local.php"):
		return fileEvidenceDetails{Platform: "wordpress", Area: "config", Component: "core_config", DeployEvidence: true}
	}

	switch {
	case strings.Contains(padded, "/modules/"):
		return fileEvidenceDetails{Platform: "prestashop", Area: "extension", Component: "module", DeployEvidence: true}
	case strings.Contains(padded, "/themes/"):
		return fileEvidenceDetails{Area: "extension", Component: "theme", DeployEvidence: true}
	case strings.Contains(padded, "/upload/") || strings.Contains(padded, "/img/"):
		return writableAssetEvidence("", isPHP)
	case strings.HasSuffix(normalized, "config/settings.inc.php") ||
		strings.HasSuffix(normalized, "app/config/parameters.php") ||
		strings.HasSuffix(normalized, "app/config/config.php"):
		return fileEvidenceDetails{Platform: "prestashop", Area: "config", Component: "config", DeployEvidence: true}
	}

	switch {
	case strings.Contains(padded, "/routes/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "route", Component: "routes", DeployEvidence: true}
	case strings.Contains(padded, "/app/http/controllers/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "source", Component: "controller", DeployEvidence: true}
	case strings.Contains(padded, "/app/http/middleware/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "source", Component: "middleware", DeployEvidence: true}
	case strings.Contains(padded, "/app/models/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "source", Component: "model", DeployEvidence: true}
	case strings.Contains(padded, "/database/migrations/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "migration", Component: "migration", DeployEvidence: true}
	case strings.Contains(padded, "/database/seeders/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "source", Component: "seeder", DeployEvidence: true}
	case strings.Contains(padded, "/resources/views/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "view", Component: "blade_view", DeployEvidence: true}
	case strings.Contains(padded, "/resources/js/") || strings.Contains(padded, "/resources/css/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "frontend_source", Component: "frontend_asset", DeployEvidence: true}
	case strings.Contains(padded, "/config/"):
		return fileEvidenceDetails{Area: "config", Component: "config", DeployEvidence: true}
	case strings.HasSuffix(normalized, "public/index.php"):
		return fileEvidenceDetails{Platform: "laravel", Area: "public_entrypoint", Component: "front_controller", DeployEvidence: true}
	case strings.Contains(padded, "/bootstrap/"):
		return fileEvidenceDetails{Platform: "laravel", Area: "bootstrap", Component: "bootstrap", DeployEvidence: true}
	}

	switch {
	case strings.Contains(padded, "/controllers/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "source", Component: "controller", DeployEvidence: true}
	case strings.Contains(padded, "/models/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "source", Component: "model", DeployEvidence: true}
	case strings.Contains(padded, "/migrations/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "migration", Component: "migration", DeployEvidence: true}
	case strings.Contains(padded, "/views/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "view", Component: "view", DeployEvidence: true}
	case strings.Contains(padded, "/commands/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "source", Component: "command", DeployEvidence: true}
	case strings.Contains(padded, "/components/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "source", Component: "component", DeployEvidence: true}
	case strings.Contains(padded, "/config/"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "config", Component: "config", DeployEvidence: true}
	case strings.HasSuffix(normalized, "web/index.php") || strings.HasSuffix(normalized, "web/index-dev.php") || strings.HasSuffix(normalized, "web/index-test.php"):
		return fileEvidenceDetails{Platform: "yii2-rbac", Area: "public_entrypoint", Component: "front_controller", DeployEvidence: true}
	}

	switch {
	case strings.Contains(padded, "/plugins/"):
		return fileEvidenceDetails{Platform: "mautic", Area: "extension", Component: "plugin", DeployEvidence: true}
	case strings.Contains(padded, "/media/"):
		return writableAssetEvidence("mautic", isPHP)
	case strings.Contains(padded, "/app/config/") || strings.Contains(padded, "/config/"):
		return fileEvidenceDetails{Area: "config", Component: "config", DeployEvidence: true}
	}

	if isWritableAssetPath(padded) {
		return writableAssetEvidence("", isPHP)
	}
	if isPHP {
		return fileEvidenceDetails{Area: "source", DeployEvidence: true}
	}
	return fileEvidenceDetails{}
}

func writableAssetEvidence(platform string, isPHP bool) fileEvidenceDetails {
	evidence := fileEvidenceDetails{Platform: platform, Area: "writable_asset"}
	if isPHP {
		evidence.SecurityContext = "writable_php"
	}
	return evidence
}

func isDependencyManifest(base string) bool {
	switch strings.ToLower(strings.TrimSpace(base)) {
	case "composer.json", "composer.lock", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock":
		return true
	default:
		return false
	}
}

func isBuildConfig(base string) bool {
	switch strings.ToLower(strings.TrimSpace(base)) {
	case "vite.config.js", "vite.config.ts", "tailwind.config.js", "tailwind.config.ts", "postcss.config.js", "webpack.config.js", "webpack.config.ts", "next.config.js", "next.config.mjs", "tsconfig.json":
		return true
	default:
		return false
	}
}

func isReactEntrypoint(path string, base string) bool {
	if base == "index.html" || base == "main.jsx" || base == "main.tsx" || base == "app.jsx" || base == "app.tsx" {
		return true
	}
	return strings.HasPrefix(path, "src/") && (strings.HasSuffix(path, ".jsx") || strings.HasSuffix(path, ".tsx"))
}

func isStaticEntrypoint(path string, base string) bool {
	if base == "index.html" || base == "service-worker.js" || base == "sw.js" || base == "manifest.json" || base == "robots.txt" {
		return true
	}
	return strings.HasSuffix(path, ".html")
}

func isNodeJSSourcePath(padded string, base string, ext string) bool {
	if ext != ".js" && ext != ".mjs" && ext != ".cjs" && ext != ".ts" {
		return false
	}
	switch base {
	case "server.js", "server.ts", "index.js", "index.ts", "app.js", "app.ts":
		return true
	}
	return strings.Contains(padded, "/src/") ||
		strings.Contains(padded, "/routes/") ||
		strings.Contains(padded, "/controllers/") ||
		strings.Contains(padded, "/middleware/") ||
		strings.Contains(padded, "/models/") ||
		strings.Contains(padded, "/config/")
}

func nodeJSComponentForPath(padded string, base string) string {
	switch {
	case base == "server.js" || base == "server.ts" || base == "app.js" || base == "app.ts" || base == "index.js" || base == "index.ts":
		return "entrypoint"
	case strings.Contains(padded, "/routes/"):
		return "route"
	case strings.Contains(padded, "/controllers/"):
		return "controller"
	case strings.Contains(padded, "/middleware/"):
		return "middleware"
	case strings.Contains(padded, "/models/"):
		return "model"
	case strings.Contains(padded, "/config/"):
		return "config"
	default:
		return "source"
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
	_, _ = fmt.Fprintf(hash, "\n%s\n%s\n%s\n%s",
		current.StatusChangeTime.Format(time.RFC3339Nano),
		current.BirthTime.Format(time.RFC3339Nano),
		previous.StatusChangeTime.Format(time.RFC3339Nano),
		previous.BirthTime.Format(time.RFC3339Nano),
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
		strings.Contains(path, "/config/db.php") ||
		strings.Contains(path, "/config/web.php") ||
		strings.Contains(path, "/config/web_prod.php") ||
		strings.Contains(path, "/config/console.php") ||
		strings.Contains(path, "/config/console_prod.php") ||
		strings.Contains(path, "/config/app.php") ||
		strings.Contains(path, "/config/auth.php") ||
		strings.Contains(path, "/config/cache.php") ||
		strings.Contains(path, "/config/database.php") ||
		strings.Contains(path, "/config/filesystems.php") ||
		strings.Contains(path, "/config/horizon.php") ||
		strings.Contains(path, "/config/logging.php") ||
		strings.Contains(path, "/config/mail.php") ||
		strings.Contains(path, "/config/permission.php") ||
		strings.Contains(path, "/config/queue.php") ||
		strings.Contains(path, "/config/services.php") ||
		strings.Contains(path, "/config/session.php") ||
		strings.Contains(path, "/config/telescope.php") ||
		strings.Contains(path, "/config/settings.inc.php") ||
		strings.Contains(path, "/app/config/parameters.php") ||
		strings.Contains(path, "/app/config/local.php") ||
		strings.Contains(path, "/app/config/config.php") ||
		strings.HasSuffix(path, "/.env") {
		return string(domain.SeverityHigh)
	}
	if strings.HasSuffix(path, ".php") || strings.HasSuffix(path, ".phtml") || strings.HasSuffix(path, ".phar") {
		if strings.Contains(path, "/uploads/") ||
			strings.Contains(path, "/upload/") ||
			strings.Contains(path, "/img/") ||
			strings.Contains(path, "/media/") {
			return string(domain.SeverityHigh)
		}
		return string(domain.SeverityMedium)
	}
	if strings.Contains(path, "/wp-content/plugins/") ||
		strings.Contains(path, "/wp-content/themes/") ||
		strings.Contains(path, "/modules/") ||
		strings.Contains(path, "/plugins/") ||
		strings.Contains(path, "/themes/") {
		return string(domain.SeverityMedium)
	}
	return string(domain.SeverityInfo)
}

func detectKnownBenignPHPGuard(eventType string, path string, sizeBytes int64) (string, bool) {
	if eventType == "file.deleted" || sizeBytes <= 0 || sizeBytes > maxKnownPHPGuardBytes {
		return "", false
	}
	if !isPrestaShopAssetGuardPath(path) {
		return "", false
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	if !looksLikePHPRedirectGuard(string(content)) {
		return "", false
	}
	return "prestashop_asset_guard_index", true
}

func isPrestaShopAssetGuardPath(path string) bool {
	path = strings.ToLower(filepath.ToSlash(path))
	if !strings.HasSuffix(path, "/index.php") && path != "index.php" {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for index := 0; index < len(parts); index++ {
		if parts[index] == "modules" && index+3 < len(parts) &&
			parts[index+2] == "views" && isPrestaShopAssetViewDir(parts[index+3]) {
			return true
		}
		if parts[index] == "themes" && index+5 < len(parts) &&
			parts[index+2] == "modules" && parts[index+4] == "views" &&
			isPrestaShopAssetViewDir(parts[index+5]) {
			return true
		}
	}
	return false
}

func isPrestaShopAssetViewDir(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "css", "font", "fonts", "img", "image", "images", "js":
		return true
	default:
		return false
	}
}

func looksLikePHPRedirectGuard(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))
	if !strings.Contains(lower, "<?php") {
		return false
	}
	compact := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(lower)
	hasRedirect := strings.Contains(compact, `header("location:../")`) ||
		strings.Contains(compact, `header('location:../')`) ||
		strings.Contains(compact, `header("location:./")`) ||
		strings.Contains(compact, `header('location:./')`)
	hasExit := strings.Contains(compact, "exit;") ||
		strings.Contains(compact, "exit();") ||
		strings.Contains(compact, "die;") ||
		strings.Contains(compact, "die();")
	if !hasRedirect || !hasExit {
		return false
	}
	for _, marker := range []string{
		"$_cookie",
		"$_files",
		"$_get",
		"$_post",
		"$_request",
		"assert(",
		"base64_decode(",
		"curl_exec(",
		"eval(",
		"exec(",
		"file_put_contents(",
		"fopen(",
		"include(",
		"move_uploaded_file(",
		"passthru(",
		"preg_replace(",
		"require(",
		"shell_exec(",
		"system(",
	} {
		if strings.Contains(compact, marker) {
			return false
		}
	}
	return true
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
	if err != nil || relativePath == "." || relativePath == ".." ||
		strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) || filepath.IsAbs(relativePath) {
		return "", false
	}
	return filepath.ToSlash(relativePath), true
}
