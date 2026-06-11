package cli

import (
	"fmt"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	urfavecli "github.com/urfave/cli/v2"
)

func hubUsersCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "users",
		Usage: "inspect Hub users and authentication events",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "auth-events",
				Usage: "list recent Hub authentication audit events",
				Flags: []urfavecli.Flag{
					&urfavecli.StringFlag{Name: "email", Usage: "filter by normalized user email"},
					&urfavecli.DurationFlag{Name: "since", Usage: "lookback window", Value: 24 * time.Hour},
					&urfavecli.IntFlag{Name: "limit", Usage: "maximum rows", Value: 100},
				},
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					events, err := container.Hub.ListHubAuthEvents(c.Context, hubapp.ListHubAuthEventsInput{
						Email: c.String("email"),
						Since: time.Now().UTC().Add(-c.Duration("since")),
						Limit: c.Int("limit"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintln(c.App.Writer, "time\tevent\temail\tuser_id\tremote_ip\tuser_agent")
					for _, event := range events {
						fmt.Fprintf(
							c.App.Writer,
							"%s\t%s\t%s\t%s\t%s\t%s\n",
							event.CreatedAt.UTC().Format(time.RFC3339),
							event.Event,
							event.EmailNormalized,
							event.UserID,
							event.RemoteIP,
							event.UserAgent,
						)
					}
					return nil
				},
			},
		},
	}
}
