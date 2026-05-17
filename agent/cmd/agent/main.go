// Command agent runs the standalone Aegrail Agent app.
package main

import (
	"fmt"
	"os"

	"github.com/rcooler/aegrail/agent/internal/adapters/cli"
	"github.com/rcooler/aegrail/agent/internal/domain"
)

var (
	version = "dev"
	commit  = "local"
	date    = "unknown"
)

func main() {
	meta := domain.AppMeta{
		Name:      "Aegrail Agent",
		Binary:    "agent",
		Version:   version,
		Commit:    commit,
		BuildDate: date,
	}

	if err := cli.New(meta).Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
}
