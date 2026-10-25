package cli

import (
	"context"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	urfavecli "github.com/urfave/cli/v3"
)

func hubCorrelationCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:    "correlate",
		Aliases: []string{"correlation"},
		Usage:   "run deterministic Hub event correlation rules",
		Commands: []*urfavecli.Command{
			{
				Name:  "events",
				Usage: "correlate recent Hub ingest events",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
					&urfavecli.StringFlag{Name: "since", Value: "24h", Usage: "lookback window such as 24h, 7d, or an RFC3339 timestamp"},
					&urfavecli.DurationFlag{Name: "window", Value: 30 * time.Minute, Usage: "maximum time between correlated events"},
					&urfavecli.IntFlag{Name: "limit", Value: 1000, Usage: "maximum timeline events to inspect"},
					&urfavecli.BoolFlag{Name: "save", Usage: "save or refresh matching Hub findings"},
				),
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					since, err := parseLookback(c.String("since"), time.Now)
					if err != nil {
						return err
					}
					container, cleanup, err := newDatabaseContainer(ctx, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					result, err := container.Hub.CorrelateEvents(ctx, hubapp.CorrelateEventsInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						Since:            since,
						Window:           c.Duration("window"),
						Limit:            c.Int("limit"),
						SaveFindings:     c.Bool("save"),
					})
					if err != nil {
						return err
					}
					if len(result.Chains) == 0 {
						fmt.Fprintf(c.Root().Writer, "No correlation chains found across %d event(s) since %s.\n", result.Events, since.Format(time.RFC3339))
						return nil
					}

					if c.Bool("save") {
						fmt.Fprintf(c.Root().Writer, "Saved or refreshed %d finding(s).\n", len(result.Findings))
					}
					writer := tabwriter.NewWriter(c.Root().Writer, 0, 0, 2, ' ', 0)
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
			{
				Name:  "browser-scripts",
				Usage: "detect browser script drift from Hub event history",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Required: true, Usage: "monitored app slug"},
					&urfavecli.StringFlag{Name: "baseline", Value: "30d", Usage: "baseline lookback window such as 30d or an RFC3339 timestamp"},
					&urfavecli.StringFlag{Name: "since", Value: "24h", Usage: "observation lookback window such as 24h, 7d, or an RFC3339 timestamp"},
					&urfavecli.IntFlag{Name: "limit", Value: 5000, Usage: "maximum browser timeline events to inspect"},
					&urfavecli.BoolFlag{Name: "save", Usage: "save or refresh matching Hub findings"},
				),
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					observeSince, err := parseLookback(c.String("since"), time.Now)
					if err != nil {
						return err
					}
					baselineSince, err := parseLookback(c.String("baseline"), time.Now)
					if err != nil {
						return err
					}
					container, cleanup, err := newDatabaseContainer(ctx, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					result, err := container.Hub.AnalyzeBrowserScriptDrift(ctx, hubapp.AnalyzeBrowserScriptDriftInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						BaselineSince:    baselineSince,
						ObserveSince:     observeSince,
						Limit:            c.Int("limit"),
						SaveFindings:     c.Bool("save"),
					})
					if err != nil {
						return err
					}
					if len(result.Drifts) == 0 {
						fmt.Fprintf(
							c.Root().Writer,
							"No browser script drift found across %d observed event(s); baseline had %d event(s) since %s.\n",
							result.ObservedEvents,
							result.BaselineEvents,
							result.BaselineSince.Format(time.RFC3339),
						)
						return nil
					}
					if c.Bool("save") {
						fmt.Fprintf(c.Root().Writer, "Saved or refreshed %d browser drift finding(s).\n", len(result.Findings))
					}
					writer := tabwriter.NewWriter(c.Root().Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "TIME\tSEVERITY\tCONFIDENCE\tRULE\tPAGE\tVALUE\tEVENT")
					for _, drift := range result.Drifts {
						fmt.Fprintf(
							writer,
							"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
							drift.EventTime.Format(time.RFC3339),
							drift.Severity,
							drift.Confidence,
							drift.RuleID,
							drift.PageURL,
							drift.Value,
							drift.EventID,
						)
					}
					return writer.Flush()
				},
			},
		},
	}
}
