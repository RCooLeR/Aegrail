package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rcooler/aegrail/agent/internal/domain"
)

func TestRootCommandGeneratesBashCompletion(t *testing.T) {
	command := New(domain.AppMeta{Name: "Aegrail Agent", Binary: "agent", Version: "test"})
	var output bytes.Buffer
	command.Writer = &output
	command.ErrWriter = &output

	if err := command.Run(context.Background(), []string{"agent", "completion", "bash"}); err != nil {
		t.Fatalf("generate bash completion: %v", err)
	}
	if script := output.String(); !strings.Contains(script, "--generate-shell-completion") || !strings.Contains(script, "__agent_") {
		t.Fatalf("completion output does not target the agent command: %q", script)
	}
}
