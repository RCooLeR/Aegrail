package cli

import (
	"fmt"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/agent"
	"github.com/rcooler/aegrail/internal/domain"
	urfavecli "github.com/urfave/cli/v2"
)

func agentInstallCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "install",
		Usage: "install local Agent configuration",
		Flags: append(agentConfigFlags(),
			&urfavecli.StringFlag{Name: "hub-url", Required: true},
			&urfavecli.StringFlag{Name: "org", Required: true},
			&urfavecli.StringFlag{Name: "project", Required: true},
			&urfavecli.StringFlag{Name: "env", Required: true},
			&urfavecli.StringFlag{Name: "app"},
			&urfavecli.StringFlag{Name: "service"},
			&urfavecli.StringFlag{Name: "host", Required: true},
			&urfavecli.StringFlag{Name: "agent-id", Required: true},
			&urfavecli.StringFlag{Name: "region"},
			&urfavecli.StringSliceFlag{Name: "label"},
		),
		Action: func(c *urfavecli.Context) error {
			runtime := newAgentRuntime(c)
			identity, err := runtime.Install(c.Context, agent.Identity{
				HubURL:      c.String("hub-url"),
				QueueDir:    c.String("queue-dir"),
				Org:         c.String("org"),
				Project:     c.String("project"),
				Environment: c.String("env"),
				App:         c.String("app"),
				Service:     c.String("service"),
				Host:        c.String("host"),
				AgentID:     c.String("agent-id"),
				Region:      c.String("region"),
				Labels:      parseLabels(c.StringSlice("label")),
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.App.Writer, "Installed agent %s for host %s\n", identity.AgentID, identity.Host)
			fmt.Fprintf(c.App.Writer, "Config: %s\n", runtime.Config.ConfigPath)
			fmt.Fprintf(c.App.Writer, "Queue:  %s\n", identity.QueueDir)
			return nil
		},
	}
}

func agentStatusCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "status",
		Usage: "show local Agent queue and identity status",
		Flags: agentConfigFlags(),
		Action: func(c *urfavecli.Context) error {
			runtime := newAgentRuntime(c)
			status, err := runtime.Status(c.Context)
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
			fmt.Fprintln(writer, "CONFIG\tQUEUE\tINSTALLED\tPENDING\tSENT\tFAILED")
			fmt.Fprintf(writer, "%s\t%s\t%t\t%d\t%d\t%d\n", status.ConfigPath, status.QueueDir, status.Installed, status.Pending, status.Sent, status.Failed)
			return writer.Flush()
		},
	}
}

func agentEnqueueCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "enqueue",
		Usage: "enqueue local Agent evidence events",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "event",
				Usage: "enqueue one normalized event",
				Flags: append(agentConfigFlags(),
					&urfavecli.StringFlag{Name: "batch-id"},
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
					runtime := newAgentRuntime(c)
					batch, path, err := runtime.EnqueueEvent(c.Context, agent.EnqueueEventInput{
						BatchID:   c.String("batch-id"),
						EventTime: eventTime,
						Type:      c.String("type"),
						Target:    c.String("target"),
						Severity:  c.String("severity"),
						Message:   c.String("message"),
						Region:    c.String("region"),
						Labels:    parseLabels(c.StringSlice("label")),
						Payload:   parsePayload(c.StringSlice("payload")),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Queued batch %s with %d event(s)\n", batch.BatchID, len(batch.Events))
					fmt.Fprintf(c.App.Writer, "Path: %s\n", path)
					return nil
				},
			},
		},
	}
}

func agentSendCommand(name string, usage string) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  name,
		Usage: usage,
		Flags: append(agentConfigFlags(),
			&urfavecli.StringFlag{Name: "secret", Usage: "Hub ingest HMAC secret", EnvVars: []string{"AEGRAIL_HUB_INGEST_SECRET"}},
			&urfavecli.IntFlag{Name: "limit", Usage: "maximum pending batches to send"},
		),
		Action: func(c *urfavecli.Context) error {
			runtime := newAgentRuntime(c)
			result, err := runtime.SendQueued(c.Context, c.String("secret"), c.Int("limit"))
			if err != nil {
				return err
			}
			fmt.Fprintf(c.App.Writer, "Sent %d queued batch(es); %d failed; %d pending remain\n", result.Sent, result.Failed, result.PendingAfter)
			for _, item := range result.Errors {
				fmt.Fprintf(c.App.ErrWriter, "%s\n", item)
			}
			if result.Failed > 0 {
				return fmt.Errorf("failed to send %d queued batch(es)", result.Failed)
			}
			return nil
		},
	}
}

func agentStartCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "start",
		Usage: "watch local paths and enqueue evidence events",
		Flags: append(agentConfigFlags(),
			&urfavecli.StringSliceFlag{Name: "watch", Usage: "file or directory path to watch; can be repeated"},
			&urfavecli.StringFlag{Name: "root", Usage: "application root used by watch profiles"},
			&urfavecli.StringSliceFlag{Name: "profile", Usage: "watch profile: wordpress, prestashop"},
			&urfavecli.DurationFlag{Name: "interval", Usage: "watch polling interval", Value: 30 * time.Second},
			&urfavecli.BoolFlag{Name: "once", Usage: "run one scan and exit"},
			&urfavecli.StringFlag{Name: "secret", Usage: "Hub ingest HMAC secret; when omitted, events remain queued locally", EnvVars: []string{"AEGRAIL_HUB_INGEST_SECRET"}},
			&urfavecli.IntFlag{Name: "send-limit", Usage: "maximum pending batches to send after each scan"},
		),
		Action: func(c *urfavecli.Context) error {
			interval := c.Duration("interval")
			if interval <= 0 {
				return fmt.Errorf("interval must be positive")
			}
			options := agent.WatchOptions{
				Paths:    c.StringSlice("watch"),
				Root:     c.String("root"),
				Profiles: c.StringSlice("profile"),
			}
			paths, err := agent.ResolveWatchPaths(options)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				return fmt.Errorf("at least one watch path is required")
			}

			runtime := newAgentRuntime(c)
			ctx, stop := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			runOnce := func() error {
				result, err := runtime.ScanWatchedPaths(ctx, options)
				if err != nil {
					return err
				}

				if result.Baselined {
					fmt.Fprintf(c.App.Writer, "Watch baseline saved at %s (%d file(s))\n", result.StatePath, result.WatchedFiles)
				} else {
					fmt.Fprintf(c.App.Writer, "Watch scan queued %d event(s) from %d file(s)\n", result.Queued, result.WatchedFiles)
				}

				secret := c.String("secret")
				if secret == "" {
					if result.Queued > 0 {
						fmt.Fprintln(c.App.Writer, "Hub send skipped because no ingest secret was provided.")
					}
					return nil
				}

				send, err := runtime.SendQueued(ctx, secret, c.Int("send-limit"))
				if err != nil {
					if c.Bool("once") {
						return err
					}
					fmt.Fprintf(c.App.ErrWriter, "%s\n", err)
					return nil
				}
				fmt.Fprintf(c.App.Writer, "Sent %d queued batch(es); %d failed; %d pending remain\n", send.Sent, send.Failed, send.PendingAfter)
				for _, item := range send.Errors {
					fmt.Fprintf(c.App.ErrWriter, "%s\n", item)
				}
				if send.Failed > 0 {
					err := fmt.Errorf("failed to send %d queued batch(es)", send.Failed)
					if c.Bool("once") {
						return err
					}
					fmt.Fprintf(c.App.ErrWriter, "%s\n", err)
				}
				return nil
			}

			if c.Bool("once") {
				return runOnce()
			}

			for {
				if err := runOnce(); err != nil {
					fmt.Fprintf(c.App.ErrWriter, "%s\n", err)
				}

				timer := time.NewTimer(interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
			}
		},
	}
}

func newAgentRuntime(c *urfavecli.Context) *agent.Runtime {
	return agent.NewRuntime(agent.Config{
		ConfigPath: c.String("config"),
		QueueDir:   c.String("queue-dir"),
	})
}

func agentConfigFlags() []urfavecli.Flag {
	return []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "config", Usage: "Agent config path", Value: ".aegrail/agent.json"},
		&urfavecli.StringFlag{Name: "queue-dir", Usage: "Agent queue directory", Value: ".aegrail/queue"},
	}
}
