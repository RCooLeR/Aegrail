// Command aegrail-agent runs a per-server Aegrail Agent: file/log scans,
// browser crawls, database collectors, queue replay, and signed Hub ingest.
package main

import (
	"fmt"
	"os"

	"github.com/rcooler/aegrail/internal/adapters/cli"
	"github.com/rcooler/aegrail/internal/domain"
)

var (
	version = "dev"
	commit  = "local"
	date    = "unknown"
)

func main() {
	meta := domain.AppMeta{
		Name:      "Aegrail Agent",
		Binary:    "aegrail-agent",
		Version:   version,
		Commit:    commit,
		BuildDate: date,
	}

	if err := cli.NewAgent(meta).Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "aegrail-agent: %v\n", err)
		os.Exit(1)
	}
}
