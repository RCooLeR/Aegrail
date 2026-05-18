package cli

import (
	"fmt"

	webpush "github.com/SherClockHolmes/webpush-go"
	urfavecli "github.com/urfave/cli/v2"
)

func notificationsCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "notifications",
		Usage: "manage Hub notification settings helpers",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "vapid-keys",
				Usage: "generate browser push VAPID keys",
				Action: func(c *urfavecli.Context) error {
					privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "AEGRAIL_NOTIFICATION_PUSH_VAPID_PUBLIC_KEY=%s\n", publicKey)
					fmt.Fprintf(c.App.Writer, "AEGRAIL_NOTIFICATION_PUSH_VAPID_PRIVATE_KEY=%s\n", privateKey)
					return nil
				},
			},
		},
	}
}
