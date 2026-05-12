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
					fmt.Fprintln(writer, "TIME\tSEVERITY\tCONFIDENCE\tRULE\tEVENTS\tTITLE\tSUMMARY\tID")
					for _, finding := range findings {
						fmt.Fprintf(
							writer,
							"%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
							finding.FirstEventAt.Format(time.RFC3339),
							finding.Severity,
							finding.Confidence,
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
		},
	}
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
