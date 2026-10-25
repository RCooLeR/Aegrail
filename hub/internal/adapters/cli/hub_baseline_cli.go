package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	urfavecli "github.com/urfave/cli/v3"
)

func hubBaselineCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "baseline",
		Usage: "compare Hub baselines across reporting hosts",
		Commands: []*urfavecli.Command{
			{
				Name:  "compare-files",
				Usage: "compare latest app file observations across hosts",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Required: true},
					&urfavecli.StringFlag{Name: "since", Value: "24h", Usage: "lookback window such as 24h, 7d, or an RFC3339 timestamp"},
					&urfavecli.IntFlag{Name: "limit", Value: 1000, Usage: "maximum file events to inspect"},
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

					result, err := container.Hub.CompareFileBaselines(ctx, hubapp.CompareFileBaselinesInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						Since:            since,
						Limit:            c.Int("limit"),
					})
					if err != nil {
						return err
					}

					if len(result.Differences) == 0 {
						fmt.Fprintf(c.Root().Writer, "No cross-host file differences observed for app %s since %s across %d reporting host(s).\n", result.App.Slug, since.Format(time.RFC3339), len(result.ObservedHosts))
						return nil
					}

					writer := tabwriter.NewWriter(c.Root().Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "PATH\tSEVERITY\tREASON\tHOST\tSTATE\tSHA256\tEVENT_TIME")
					for _, difference := range result.Differences {
						for _, state := range difference.Hosts {
							fmt.Fprintf(
								writer,
								"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
								difference.RelativePath,
								difference.Severity,
								difference.Reason,
								state.HostSlug,
								state.EventType,
								shortHash(stateHash(state)),
								state.EventTime.Format(time.RFC3339),
							)
						}
					}
					return writer.Flush()
				},
			},
		},
	}
}

func parseLookback(value string, now func() time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "24h"
	}
	if before, ok := strings.CutSuffix(value, "d"); ok {
		days, err := strconv.ParseFloat(before, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("lookback %q must be a duration or RFC3339 timestamp: %w", value, err)
		}
		return now().UTC().Add(-time.Duration(days * float64(24*time.Hour))), nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return now().UTC().Add(-duration), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("lookback %q must be a duration or RFC3339 timestamp", value)
	}
	return parsed.UTC(), nil
}

func stateHash(state hubapp.FileBaselineHostState) string {
	if state.Deleted {
		return "deleted"
	}
	if state.HashSkipped {
		return "hash-skipped"
	}
	return state.SHA256
}

func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
