package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	urfavecli "github.com/urfave/cli/v3"
)

func hubUsersCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "users",
		Usage: "inspect Hub users and authentication events",
		Commands: []*urfavecli.Command{
			{
				Name:  "auth-events",
				Usage: "list recent Hub authentication audit events",
				Flags: []urfavecli.Flag{
					&urfavecli.StringFlag{Name: "email", Usage: "filter by normalized user email"},
					&urfavecli.DurationFlag{Name: "since", Usage: "lookback window", Value: 24 * time.Hour},
					&urfavecli.IntFlag{Name: "limit", Usage: "maximum rows", Value: 100},
				},
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					container, cleanup, err := newDatabaseContainer(ctx, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					events, err := container.Hub.ListHubAuthEvents(ctx, hubapp.ListHubAuthEventsInput{
						Email: c.String("email"),
						Since: time.Now().UTC().Add(-c.Duration("since")),
						Limit: c.Int("limit"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintln(c.Root().Writer, "time\tevent\temail\tuser_id\tremote_ip\tuser_agent")
					for _, event := range events {
						fmt.Fprintf(
							c.Root().Writer,
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
