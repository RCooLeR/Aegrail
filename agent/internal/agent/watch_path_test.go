package agent

import (
	"path/filepath"
	"testing"
)

func TestShouldSkipDirHonorsQueuePathBoundary(t *testing.T) {
	root := t.TempDir()
	queue := filepath.Join(root, "queue")

	if !shouldSkipDir(filepath.Join(queue, "pending"), queue) {
		t.Fatal("shouldSkipDir returned false for a directory inside the queue")
	}
	if shouldSkipDir(filepath.Join(root, "queue-old"), queue) {
		t.Fatal("shouldSkipDir returned true for a queue path sibling")
	}
}

func TestAppRelativePathAllowsDotPrefixedChildName(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "..not-parent", "file.php")

	relativePath, ok := appRelativePath(root, path)
	if !ok {
		t.Fatal("appRelativePath returned false for a child path whose name starts with dots")
	}
	if relativePath != "..not-parent/file.php" {
		t.Fatalf("relativePath = %q, want %q", relativePath, "..not-parent/file.php")
	}
}
