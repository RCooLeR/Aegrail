package cli

import (
	"fmt"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
	urfavecli "github.com/urfave/cli/v2"
)

func hubModelAnalysisCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "model-analysis",
		Usage: "run Hub model-analysis workflows",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "queue",
				Usage: "generate missing model analysis reports for open findings",
				Flags: []urfavecli.Flag{
					&urfavecli.IntFlag{Name: "limit", Value: 5, Usage: "maximum open findings to check"},
					&urfavecli.StringFlag{Name: "model", Usage: "override investigation model"},
					&urfavecli.IntFlag{Name: "max-events", Value: 8, Usage: "maximum compact evidence events per finding"},
					&urfavecli.IntFlag{Name: "max-metadata-depth", Value: 4, Usage: "maximum nested metadata depth"},
					&urfavecli.IntFlag{Name: "max-string-length", Value: 500, Usage: "maximum string length in redacted metadata"},
				},
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					result, err := container.Hub.AnalyzeModelAnalysisQueue(c.Context, hubapp.AnalyzeModelAnalysisQueueInput{
						Limit:               c.Int("limit"),
						Model:               c.String("model"),
						MaxEventsPerFinding: c.Int("max-events"),
						MaxMetadataDepth:    c.Int("max-metadata-depth"),
						MaxStringLength:     c.Int("max-string-length"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(
						c.App.Writer,
						"Model analysis queue checked %d finding(s) across %d scope(s); generated %d, skipped %d, failed %d.\n",
						result.Findings,
						result.Scopes,
						result.Generated,
						result.Skipped,
						result.Failed,
					)
					for _, message := range result.Errors {
						fmt.Fprintf(c.App.Writer, "  warning: %s\n", message)
					}
					return nil
				},
			},
		},
	}
}
