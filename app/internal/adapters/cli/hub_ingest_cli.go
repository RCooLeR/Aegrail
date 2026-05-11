package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
	urfavecli "github.com/urfave/cli/v2"
)

func hubIngestCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "ingest",
		Usage: "accept normalized Hub event batches",
		Subcommands: []*urfavecli.Command{
			hubIngestEventCommand(meta),
			hubIngestBatchCommand(meta),
		},
	}
}

func hubIngestEventCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "event",
		Usage: "store one normalized event as an ingest batch",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app"},
			&urfavecli.StringFlag{Name: "service"},
			&urfavecli.StringFlag{Name: "host", Required: true},
			&urfavecli.StringFlag{Name: "agent-id", Required: true},
			&urfavecli.StringFlag{Name: "batch-id", Required: true},
			&urfavecli.StringFlag{Name: "source", Value: "cli"},
			&urfavecli.StringFlag{Name: "type", Required: true},
			&urfavecli.StringFlag{Name: "target"},
			&urfavecli.StringFlag{Name: "severity", Value: string(domain.SeverityInfo)},
			&urfavecli.StringFlag{Name: "message"},
			&urfavecli.StringFlag{Name: "event-time"},
			&urfavecli.StringFlag{Name: "region"},
			&urfavecli.StringSliceFlag{Name: "label"},
			&urfavecli.StringSliceFlag{Name: "payload"},
		),
		Action: func(c *urfavecli.Context) error {
			eventTime, err := parseOptionalTime(c.String("event-time"))
			if err != nil {
				return err
			}
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			result, err := container.Hub.IngestEvents(c.Context, hubapp.IngestEventsInput{
				OrganizationSlug: c.String("org"),
				ProjectSlug:      c.String("project"),
				EnvironmentSlug:  c.String("env"),
				AppSlug:          c.String("app"),
				ServiceSlug:      c.String("service"),
				HostSlug:         c.String("host"),
				AgentID:          c.String("agent-id"),
				ExternalBatchID:  c.String("batch-id"),
				Source:           c.String("source"),
				Region:           c.String("region"),
				Labels:           parseLabels(c.StringSlice("label")),
				Events: []hubapp.IngestEventInput{
					{
						EventTime: eventTime,
						Type:      c.String("type"),
						Target:    c.String("target"),
						Severity:  c.String("severity"),
						Message:   c.String("message"),
						Region:    c.String("region"),
						Payload:   parsePayload(c.StringSlice("payload")),
					},
				},
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(c.App.Writer, "Stored ingest batch %s with %d event(s)\n", result.Batch.ExternalID, len(result.Events))
			return nil
		},
	}
}

func hubIngestBatchCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "batch",
		Usage: "inspect Hub ingest batches",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "list",
				Usage: "list recent ingest batches for an environment",
				Flags: append(environmentPathFlags(),
					&urfavecli.IntFlag{Name: "limit", Value: 20},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					items, err := container.Hub.ListIngestBatches(c.Context, c.String("org"), c.String("project"), c.String("env"), c.Int("limit"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "BATCH_ID\tSOURCE\tSTATUS\tEVENTS\tRECEIVED_AT\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\t%d\t%s\t%s\n", item.ExternalID, item.Source, item.Status, item.EventCount, item.ReceivedAt.Format(time.RFC3339), item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func parsePayload(values []string) map[string]any {
	payload := make(map[string]any)
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		payload[key] = strings.TrimSpace(val)
	}
	return payload
}
