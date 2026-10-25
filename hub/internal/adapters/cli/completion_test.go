package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestRootCommandGeneratesBashCompletion(t *testing.T) {
	command := New(domain.AppMeta{Name: "Aegrail Hub", Binary: "hub", Version: "test"})
	var output bytes.Buffer
	command.Writer = &output
	command.ErrWriter = &output

	if err := command.Run(context.Background(), []string{"hub", "completion", "bash"}); err != nil {
		t.Fatalf("generate bash completion: %v", err)
	}
	if script := output.String(); !strings.Contains(script, "--generate-shell-completion") || !strings.Contains(script, "__hub_") {
		t.Fatalf("completion output does not target the hub command: %q", script)
	}
}
