package cli

import (
	"context"
	"fmt"

	webpush "github.com/SherClockHolmes/webpush-go"
	urfavecli "github.com/urfave/cli/v3"
)

func notificationsCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "notifications",
		Usage: "manage Hub notification settings helpers",
		Commands: []*urfavecli.Command{
			{
				Name:  "vapid-keys",
				Usage: "generate browser push VAPID keys",
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
					if err != nil {
						return err
					}
					fmt.Fprintf(c.Root().Writer, "AEGRAIL_NOTIFICATION_PUSH_VAPID_PUBLIC_KEY=%s\n", publicKey)
					fmt.Fprintf(c.Root().Writer, "AEGRAIL_NOTIFICATION_PUSH_VAPID_PRIVATE_KEY=%s\n", privateKey)
					return nil
				},
			},
		},
	}
}
