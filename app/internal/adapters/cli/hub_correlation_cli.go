package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
	urfavecli "github.com/urfave/cli/v2"
)

func hubCorrelationCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:    "correlate",
		Aliases: []string{"correlation"},
		Usage:   "run deterministic Hub event correlation rules",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "events",
				Usage: "correlate recent Hub ingest events",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
					&urfavecli.StringFlag{Name: "since", Value: "24h", Usage: "lookback window such as 24h, 7d, or an RFC3339 timestamp"},
					&urfavecli.DurationFlag{Name: "window", Value: 30 * time.Minute, Usage: "maximum time between correlated events"},
					&urfavecli.IntFlag{Name: "limit", Value: 1000, Usage: "maximum timeline events to inspect"},
				),
				Action: func(c *urfavecli.Context) error {
					since, err := parseLookback(c.String("since"), time.Now)
					if err != nil {
						return err
					}
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					result, err := container.Hub.CorrelateEvents(c.Context, hubapp.CorrelateEventsInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						Since:            since,
						Window:           c.Duration("window"),
						Limit:            c.Int("limit"),
					})
					if err != nil {
						return err
					}
					if len(result.Chains) == 0 {
						fmt.Fprintf(c.App.Writer, "No correlation chains found across %d event(s) since %s.\n", result.Events, since.Format(time.RFC3339))
						return nil
					}

					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "CHAIN\tSEVERITY\tCONFIDENCE\tRULE\tEVENTS\tSUMMARY")
					for index, chain := range result.Chains {
						fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%d\t%s\n", index+1, chain.Severity, chain.Confidence, chain.RuleID, len(chain.Events), chain.Summary)
					}
					fmt.Fprintln(writer)
					fmt.Fprintln(writer, "CHAIN\tTIME\tHOST\tTYPE\tTARGET")
					for index, chain := range result.Chains {
						for _, event := range chain.Events {
							fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\n", index+1, event.EventTime.Format(time.RFC3339), event.HostSlug, event.EventType, event.Target)
						}
					}
					return writer.Flush()
				},
			},
		},
	}
}
