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
					&urfavecli.StringFlag{Name: "status", Usage: "optional status filter: active or disabled"},
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
						PageURL:          c.String("page"),
						Kind:             c.String("kind"),
						Status:           c.String("status"),
					})
					if err != nil {
						return err
					}
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
			{
				Name:  "status",
				Usage: "enable or disable a browser script allowlist entry",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app", Required: true, Usage: "monitored app slug"},
					&urfavecli.StringFlag{Name: "id", Required: true, Usage: "allowlist entry id"},
					&urfavecli.StringFlag{Name: "status", Required: true, Usage: "active or disabled"},
					&urfavecli.StringFlag{Name: "reason", Usage: "review note explaining the status change"},
					&urfavecli.StringFlag{Name: "approved-by", Usage: "reviewer identity"},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					entry, err := container.Hub.UpdateBrowserScriptAllowlistStatus(c.Context, hubapp.UpdateBrowserScriptAllowlistStatusInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						EntryID:          c.String("id"),
						Status:           c.String("status"),
						Reason:           c.String("reason"),
						ApprovedBy:       c.String("approved-by"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Browser script allowlist entry %s is now %s.\n", entry.ID, entry.Status)
					return nil
				},
			},
		},
	}
}

func browserAllowlistPageLabel(page string) string {
	page = strings.TrimSpace(page)
	if page == "" {
		return "*"
	}
	return page
}
