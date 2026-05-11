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

type WatchOptions struct {
	Paths    []string
	Root     string
	Profiles []string
}

type WatchResult struct {
	WatchedFiles int
	Queued       int
	Baselined    bool
	StatePath    string
}

type watchState struct {
	Schema    string               `json:"schema"`
	UpdatedAt time.Time            `json:"updated_at"`
	Files     map[string]fileState `json:"files"`
}

type fileState struct {
	Path        string    `json:"path"`
	SizeBytes   int64     `json:"size_bytes"`
	ModTime     time.Time `json:"mod_time"`
	SHA256      string    `json:"sha256,omitempty"`
	HashSkipped bool      `json:"hash_skipped,omitempty"`
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
	statePath := r.watchStatePath(identity)
	unlock, err := acquireWatchLock(statePath)
	if err != nil {
		return WatchResult{}, err
	}
	defer unlock()

	previous, hadState, err := loadWatchState(statePath)
	if err != nil {
		return WatchResult{}, err
	}
	current, err := scanPaths(paths, identity.QueueDir)
	if err != nil {
		return WatchResult{}, err
	}

	result := WatchResult{
		WatchedFiles: len(current),
		Baselined:    !hadState,
		StatePath:    statePath,
	}
	if hadState {
		events := diffWatchState(previous.Files, current)
		for _, event := range events {
			if _, _, err := r.EnqueueEvent(ctx, event); err != nil {
				return WatchResult{}, err
			}
			result.Queued++
		}
	}
	if err := saveWatchState(statePath, watchState{
		Schema:    WatchStateSchema,
		UpdatedAt: r.now().UTC(),
		Files:     current,
	}); err != nil {
		return WatchResult{}, err
	}
	return result, nil
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
	lockPath := filepath.Join(filepath.Dir(statePath), "file-watch.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
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

func scanPaths(paths []string, queueDir string) (map[string]fileState, error) {
	result := map[string]fileState{}
	queueAbs, _ := filepath.Abs(queueDir)
	for _, path := range paths {
		if err := scanPath(path, queueAbs, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func scanPath(path string, queueAbs string, result map[string]fileState) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		state, err := buildFileState(path, info)
		if err != nil {
			return err
		}
		result[state.Path] = state
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
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		state, err := buildFileState(current, info)
		if err != nil {
			return err
		}
		result[state.Path] = state
		return nil
	})
}

func shouldSkipDir(path string, queueAbs string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == ".git" || base == ".aegrail" {
		return true
	}
	abs, err := filepath.Abs(path)
	if err == nil && queueAbs != "" && strings.HasPrefix(abs, queueAbs) {
		return true
	}
	return false
}

func buildFileState(path string, info fs.FileInfo) (fileState, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fileState{}, err
	}
	state := fileState{
		Path:      filepath.Clean(abs),
		SizeBytes: info.Size(),
		ModTime:   info.ModTime().UTC(),
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
	return state, nil
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
			events = append(events, fileEvent("file.deleted", previousState, fileState{}))
		}
	}
	slices.SortFunc(events, func(a EnqueueEventInput, b EnqueueEventInput) int {
		return strings.Compare(a.Target, b.Target)
	})
	return events
}

func fileChanged(previous fileState, current fileState) bool {
	return previous.SizeBytes != current.SizeBytes ||
		!previous.ModTime.Equal(current.ModTime) ||
		previous.SHA256 != current.SHA256 ||
		previous.HashSkipped != current.HashSkipped
}

func fileEvent(eventType string, current fileState, previous fileState) EnqueueEventInput {
	severity := classifyFileSeverity(eventType, current.Path)
	payload := map[string]any{
		"path":         current.Path,
		"size_bytes":   current.SizeBytes,
		"mod_time":     current.ModTime.Format(time.RFC3339Nano),
		"hash_skipped": current.HashSkipped,
	}
	if current.SHA256 != "" {
		payload["sha256"] = current.SHA256
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
		Target:   current.Path,
		Severity: severity,
		Message:  fileEventMessage(eventType, current.Path),
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
	if strings.HasSuffix(path, ".php") || strings.HasSuffix(path, ".phtml") || strings.HasSuffix(path, ".phar") {
		if strings.Contains(path, "/uploads/") || strings.Contains(path, "/upload/") || strings.Contains(path, "/img/") {
			return string(domain.SeverityHigh)
		}
		return string(domain.SeverityMedium)
	}
	if strings.HasSuffix(path, "/wp-config.php") ||
		strings.Contains(path, "/config/settings.inc.php") ||
		strings.Contains(path, "/app/config/parameters.php") ||
		strings.HasSuffix(path, "/.env") {
		return string(domain.SeverityHigh)
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
