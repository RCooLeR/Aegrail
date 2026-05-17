// Command hub runs the standalone Aegrail Hub app.
package main

import (
	"fmt"
	"os"

	"github.com/rcooler/aegrail/hub/internal/adapters/cli"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

var (
	version = "dev"
	commit  = "local"
	date    = "unknown"
)

func main() {
	meta := domain.AppMeta{
		Name:      "Aegrail Hub",
		Binary:    "hub",
		Version:   version,
		Commit:    commit,
		BuildDate: date,
	}

	if err := cli.New(meta).Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "hub: %v\n", err)
		os.Exit(1)
	}
}
