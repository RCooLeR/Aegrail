package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadNewLogLinesLeavesIncompleteTailForNextScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	first := "complete line\n"
	partial := "partial"
	if err := os.WriteFile(path, []byte(first+partial), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	lines, offset, err := readNewLogLines(path, 0)
	if err != nil {
		t.Fatalf("first readNewLogLines returned error: %v", err)
	}
	if len(lines) != 1 || lines[0].Text != "complete line" || offset != int64(len(first)) {
		t.Fatalf("first scan lines=%#v offset=%d, want one complete line at offset %d", lines, offset, len(first))
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	if _, err := file.WriteString(" remainder\n"); err != nil {
		file.Close()
		t.Fatalf("WriteString returned error: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	lines, nextOffset, err := readNewLogLines(path, offset)
	if err != nil {
		t.Fatalf("second readNewLogLines returned error: %v", err)
	}
	if len(lines) != 1 || lines[0].Text != "partial remainder" || nextOffset != int64(len(first+partial+" remainder\n")) {
		t.Fatalf("second scan lines=%#v offset=%d, want completed tail", lines, nextOffset)
	}
}

func TestReadNewLogLinesKeepsUpBeyondLegacyFiveHundredLineLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	const lineCount = 1_200
	var content strings.Builder
	for index := 0; index < lineCount; index++ {
		fmt.Fprintf(&content, "198.51.100.42 - - [29/Jul/2026:12:00:%02d +0000] \"GET / HTTP/1.1\" 200 123\n", index%60)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	lines, offset, err := readNewLogLines(path, 0)
	if err != nil {
		t.Fatalf("readNewLogLines returned error: %v", err)
	}
	if len(lines) != lineCount {
		t.Fatalf("read %d lines, want %d so the watcher does not fall behind busy logs", len(lines), lineCount)
	}
	if offset != int64(content.Len()) {
		t.Fatalf("offset = %d, want end of file %d", offset, content.Len())
	}
}

func TestScanLogPathsReadsRenameCreateReplacementFromBeginningWhenItOutgrowsOldOffset(t *testing.T) {
	root, runtime, logPath := newRotationTestRuntime(t)
	writeRotationTestLines(t, logPath, "old", 2)
	baselineLogWatch(t, runtime, logPath)

	stateBefore, ok, err := loadLogWatchState(filepath.Join(root, "state", "log-watch.json"))
	if err != nil || !ok {
		t.Fatalf("loadLogWatchState before rotation = ok %v, err %v", ok, err)
	}
	previous := stateBefore.Logs[filepath.Clean(logPath)]
	if previous.FileIdentity == "" {
		t.Fatal("baseline state has no file identity")
	}

	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatalf("Rename returned error: %v", err)
	}
	writeRotationTestLines(t, logPath, "replacement", 12)

	result, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("ScanLogPaths after rename-create returned error: %v", err)
	}
	if result.Rotated != 1 || result.Queued != 12 {
		t.Fatalf("result = %+v, want one rotation and all 12 replacement lines", result)
	}

	lines, generations := queuedRotationTestLines(t, filepath.Join(root, "queue", "pending"))
	if len(lines) != 12 {
		t.Fatalf("queued log lines = %d, want 12; lines=%v", len(lines), lines)
	}
	for _, line := range lines {
		if !strings.Contains(line, "replacement") {
			t.Fatalf("queued line %q came from the wrong generation", line)
		}
	}
	for _, generation := range generations {
		if generation != 2 {
			t.Fatalf("log_generation = %v, want 2", generation)
		}
	}

	stateAfter, _, err := loadLogWatchState(filepath.Join(root, "state", "log-watch.json"))
	if err != nil {
		t.Fatalf("loadLogWatchState after rotation returned error: %v", err)
	}
	current := stateAfter.Logs[filepath.Clean(logPath)]
	if current.FileIdentity == previous.FileIdentity {
		t.Fatalf("file identity did not change across rename-create: %q", current.FileIdentity)
	}
	if current.Generation != 2 {
		t.Fatalf("generation = %d, want 2", current.Generation)
	}
}

func TestScanLogPathsReadsCopytruncateRewriteFromBeginningWhenItOutgrowsOldOffset(t *testing.T) {
	root, runtime, logPath := newRotationTestRuntime(t)
	writeRotationTestLines(t, logPath, "old", 3)
	baselineLogWatch(t, runtime, logPath)

	stateBefore, _, err := loadLogWatchState(filepath.Join(root, "state", "log-watch.json"))
	if err != nil {
		t.Fatalf("loadLogWatchState before copytruncate returned error: %v", err)
	}
	previous := stateBefore.Logs[filepath.Clean(logPath)]

	writeRotationTestLines(t, logPath, "copytruncate", 15)

	result, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("ScanLogPaths after copytruncate returned error: %v", err)
	}
	if result.Rotated != 1 || result.Queued != 15 {
		t.Fatalf("result = %+v, want one rotation and all 15 rewritten lines", result)
	}

	stateAfter, _, err := loadLogWatchState(filepath.Join(root, "state", "log-watch.json"))
	if err != nil {
		t.Fatalf("loadLogWatchState after copytruncate returned error: %v", err)
	}
	current := stateAfter.Logs[filepath.Clean(logPath)]
	if current.FileIdentity != previous.FileIdentity {
		t.Fatalf("copytruncate changed identity from %q to %q", previous.FileIdentity, current.FileIdentity)
	}
	if current.Generation != 2 {
		t.Fatalf("generation = %d, want 2", current.Generation)
	}

	lines, generations := queuedRotationTestLines(t, filepath.Join(root, "queue", "pending"))
	if len(lines) != 15 {
		t.Fatalf("queued log lines = %d, want 15; lines=%v", len(lines), lines)
	}
	for _, line := range lines {
		if !strings.Contains(line, "copytruncate") {
			t.Fatalf("queued line %q came from content before copytruncate", line)
		}
	}
	for _, generation := range generations {
		if generation != 2 {
			t.Fatalf("log_generation = %v, want 2", generation)
		}
	}
}

func TestScanLogPathsReadsReappearingPathFromBeginning(t *testing.T) {
	root, runtime, logPath := newRotationTestRuntime(t)
	writeRotationTestLines(t, logPath, "old", 2)
	baselineLogWatch(t, runtime, logPath)

	if err := os.Remove(logPath); err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}
	if _, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}}); err != nil {
		t.Fatalf("ScanLogPaths while path was absent returned error: %v", err)
	}
	missingState, _, err := loadLogWatchState(filepath.Join(root, "state", "log-watch.json"))
	if err != nil {
		t.Fatalf("loadLogWatchState while path absent returned error: %v", err)
	}
	if !missingState.Logs[filepath.Clean(logPath)].Missing {
		t.Fatal("temporarily missing configured log did not retain a missing cursor")
	}

	writeRotationTestLines(t, logPath, "reappeared", 8)
	result, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("ScanLogPaths after path reappeared returned error: %v", err)
	}
	if result.Rotated != 1 || result.Queued != 8 {
		t.Fatalf("result = %+v, want one new generation and all eight lines from the reappearing path", result)
	}
	reappearedState, _, err := loadLogWatchState(filepath.Join(root, "state", "log-watch.json"))
	if err != nil {
		t.Fatalf("loadLogWatchState after path reappeared returned error: %v", err)
	}
	current := reappearedState.Logs[filepath.Clean(logPath)]
	if current.Missing || current.Generation != 2 {
		t.Fatalf("reappeared state = %+v, want present generation 2", current)
	}
}

func newRotationTestRuntime(t *testing.T) (string, *Runtime, string) {
	t.Helper()
	t.Setenv("AEGRAIL_TOR_CHECK", "0")
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	runtime := NewRuntime(Config{
		ConfigPath: filepath.Join(root, "agent.json"),
		QueueDir:   filepath.Join(root, "queue"),
	})
	if _, err := runtime.Install(context.Background(), Identity{
		HubURL:      "http://127.0.0.1:8787",
		QueueDir:    filepath.Join(root, "queue"),
		Org:         "acme",
		Project:     "customer-site",
		Environment: "production",
		App:         "main-web",
		Service:     "frontend",
		Host:        "web-01",
		AgentID:     "agt_web_01",
	}); err != nil {
		t.Fatalf("Install returned error: %v", err)
	}
	return root, runtime, filepath.Join(logDir, "access.log")
}

func baselineLogWatch(t *testing.T, runtime *Runtime, logPath string) {
	t.Helper()
	result, err := runtime.ScanLogPaths(context.Background(), LogWatchOptions{Paths: []string{logPath}})
	if err != nil {
		t.Fatalf("baseline ScanLogPaths returned error: %v", err)
	}
	if !result.Baselined {
		t.Fatalf("baseline result = %+v, want Baselined", result)
	}
}

func writeRotationTestLines(t *testing.T, path string, marker string, count int) {
	t.Helper()
	var content strings.Builder
	for index := 0; index < count; index++ {
		fmt.Fprintf(&content, "ERROR %s log generation line %02d with enough content to vary the checkpoint\n", marker, index)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
}

func queuedRotationTestLines(t *testing.T, pendingDir string) ([]string, []float64) {
	t.Helper()
	paths, err := queueFiles(pendingDir)
	if err != nil {
		t.Fatalf("queueFiles returned error: %v", err)
	}
	var lines []string
	var generations []float64
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}
		var batch QueuedBatch
		if err := json.Unmarshal(content, &batch); err != nil {
			t.Fatalf("Unmarshal returned error: %v", err)
		}
		for _, event := range batch.Events {
			line, ok := event.Payload["line"].(string)
			if !ok {
				continue
			}
			lines = append(lines, line)
			generation, _ := event.Payload["log_generation"].(float64)
			generations = append(generations, generation)
		}
	}
	return lines, generations
}
