// Command agent runs the standalone Aegrail Agent app.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.New(meta).Run(ctx, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
}
