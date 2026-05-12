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

func hubFindingsCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "findings",
		Usage: "inspect persisted Hub findings",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "list",
				Usage: "list recent Hub findings for an environment",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
					&urfavecli.IntFlag{Name: "limit", Value: 20},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					findings, err := container.Hub.ListHubFindings(c.Context, hubapp.ListHubFindingsInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						Limit:            c.Int("limit"),
					})
					if err != nil {
						return err
					}
					if len(findings) == 0 {
						fmt.Fprintln(c.App.Writer, "No Hub findings found.")
						return nil
					}

					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "TIME\tSEVERITY\tCONFIDENCE\tSTATUS\tRULE\tEVENTS\tTITLE\tSUMMARY\tID")
					for _, finding := range findings {
						fmt.Fprintf(
							writer,
							"%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
							finding.FirstEventAt.Format(time.RFC3339),
							finding.Severity,
							finding.Confidence,
							hubFindingStatusText(finding),
							finding.RuleID,
							len(finding.EventIDs),
							finding.Title,
							compactText(finding.Summary, 120),
							finding.ID,
						)
					}
					return writer.Flush()
				},
			},
			{
				Name:  "status",
				Usage: "update a Hub finding triage status",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "id", Required: true, Usage: "Hub finding id"},
					&urfavecli.StringFlag{Name: "status", Required: true, Usage: "open, acknowledged, false_positive, or resolved"},
					&urfavecli.StringFlag{Name: "reason", Usage: "short status reason"},
					&urfavecli.StringFlag{Name: "note", Usage: "operator note"},
					&urfavecli.StringFlag{Name: "actor", Usage: "operator identity"},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					finding, err := container.Hub.UpdateHubFindingStatus(c.Context, hubapp.UpdateHubFindingStatusInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						FindingID:        c.String("id"),
						Status:           c.String("status"),
						Reason:           c.String("reason"),
						Note:             c.String("note"),
						Actor:            c.String("actor"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Finding %s status is now %s.\n", finding.ID, hubFindingStatusText(finding))
					return nil
				},
			},
		},
	}
}

func hubFindingStatusText(finding domain.HubFinding) string {
	if strings.TrimSpace(finding.Status) == "" {
		return "open"
	}
	return finding.Status
}

func compactText(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if max <= 0 || len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}
