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

func hubBrowserScriptsCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "browser-scripts",
		Usage: "review browser script drift allowlists",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "allow",
				Usage: "approve a browser script drift value",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Required: true, Usage: "monitored app slug"},
					&urfavecli.StringFlag{Name: "page", Usage: "page URL; omit to allow this value for all pages in the app"},
					&urfavecli.StringFlag{Name: "kind", Required: true, Usage: "domain, inline_hash, or tag_manager_id"},
					&urfavecli.StringFlag{Name: "value", Required: true, Usage: "approved domain, inline hash, or tag-manager id"},
					&urfavecli.StringFlag{Name: "reason", Usage: "review note explaining why this value is accepted"},
					&urfavecli.StringFlag{Name: "approved-by", Usage: "reviewer identity"},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					entry, err := container.Hub.AllowBrowserScript(c.Context, hubapp.AllowBrowserScriptInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						PageURL:          c.String("page"),
						Kind:             c.String("kind"),
						Value:            c.String("value"),
						Reason:           c.String("reason"),
						ApprovedBy:       c.String("approved-by"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Allowed browser script %s %q for %s\n", entry.Kind, entry.Value, browserAllowlistPageLabel(entry.PageURL))
					return nil
				},
			},
			{
				Name:  "allowlist",
				Usage: "list approved browser script drift values",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Required: true, Usage: "monitored app slug"},
					&urfavecli.StringFlag{Name: "kind", Usage: "optional kind filter"},
					&urfavecli.StringFlag{Name: "page", Usage: "optional page URL filter"},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					entries, err := container.Hub.ListBrowserScriptAllowlist(c.Context, hubapp.ListBrowserScriptAllowlistInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
					})
					if err != nil {
						return err
					}
					entries = filterBrowserAllowlistEntries(entries, c.String("kind"), c.String("page"))
					if len(entries) == 0 {
						fmt.Fprintln(c.App.Writer, "No browser script allowlist entries found.")
						return nil
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "PAGE\tKIND\tVALUE\tSTATUS\tAPPROVED_BY\tUPDATED_AT\tREASON\tID")
					for _, entry := range entries {
						fmt.Fprintf(
							writer,
							"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
							browserAllowlistPageLabel(entry.PageURL),
							entry.Kind,
							entry.Value,
							entry.Status,
							entry.ApprovedBy,
							entry.UpdatedAt.Format(time.RFC3339),
							compactText(entry.Reason, 80),
							entry.ID,
						)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func filterBrowserAllowlistEntries(entries []domain.BrowserScriptAllowlistEntry, kind string, page string) []domain.BrowserScriptAllowlistEntry {
	kind = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(kind, "-", "_")))
	page = strings.TrimRight(strings.TrimSpace(page), "/")
	filtered := make([]domain.BrowserScriptAllowlistEntry, 0, len(entries))
	for _, entry := range entries {
		if kind != "" && strings.ToLower(entry.Kind) != kind {
			continue
		}
		if page != "" && strings.TrimRight(entry.PageURL, "/") != page {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func browserAllowlistPageLabel(page string) string {
	page = strings.TrimSpace(page)
	if page == "" {
		return "*"
	}
	return page
}
