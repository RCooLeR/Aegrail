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
		Name:      "Aegrail",
		Binary:    "aegrail",
		Version:   version,
		Commit:    commit,
		BuildDate: date,
	}

	if err := cli.New(meta).Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "aegrail: %v\n", err)
		os.Exit(1)
	}
}
