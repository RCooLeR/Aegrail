// Command hub runs the standalone Aegrail Hub app.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.New(meta).Run(ctx, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "hub: %v\n", err)
		os.Exit(1)
	}
}
