package cli

import (
	"bytes"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func runCLICapture(t *testing.T, args ...string) string {
	t.Helper()
	app := New(domain.AppMeta{Name: "Aegrail Hub", Binary: "hub", Version: "test"})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr
	if err := app.Run(args); err != nil {
		t.Fatalf("Run(%v) returned error: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}
