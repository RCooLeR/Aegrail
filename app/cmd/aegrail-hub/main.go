// Command aegrail-hub runs the central Aegrail Hub: HTTP API, database
// migrations, ingest, findings, rules, baseline, correlation, inventory, and
// reports.
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
		Name:      "Aegrail Hub",
		Binary:    "aegrail-hub",
		Version:   version,
		Commit:    commit,
		BuildDate: date,
	}

	if err := cli.NewHub(meta).Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "aegrail-hub: %v\n", err)
		os.Exit(1)
	}
}
