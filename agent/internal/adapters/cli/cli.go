package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/modules/catalog"
	urfavecli "github.com/urfave/cli/v2"
)

func New(meta domain.AppMeta) *urfavecli.App {
	return &urfavecli.App{
		Name:     meta.Binary,
		Usage:    "Aegrail Agent: scan a site instance and forward encrypted evidence to the Hub",
		Version:  meta.Version,
		Commands: agentCommandSet(meta),
	}
}

func NewAgent(meta domain.AppMeta) *urfavecli.App {
	return New(meta)
}

func agentCommandSet(meta domain.AppMeta) []*urfavecli.Command {
	return []*urfavecli.Command{
		versionCommand(meta),
		agentInstallCommand(),
		agentConfigCommand(),
		agentStatusCommand(),
		agentEnqueueCommand(),
		agentSendCommand("send", "send queued batches to the Hub"),
		agentStartCommand(),
		agentRunCommand(),
		moduleCommand(),
	}
}

func moduleCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "module",
		Usage: "inspect target modules",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "list",
				Usage: "list registered target modules",
				Action: func(c *urfavecli.Context) error {
					registry, err := catalog.DefaultRegistry()
					if err != nil {
						return err
					}

					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "ID\tNAME\tPRIORITY\tCAPABILITIES")
					for _, spec := range registry.All() {
						fmt.Fprintf(writer, "%s\t%s\t%d\t%d\n", spec.ID, spec.Name, spec.Priority, len(spec.Capabilities))
					}
					return writer.Flush()
				},
			},
		},
	}
}

func versionCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "version",
		Usage: "print build information",
		Action: func(c *urfavecli.Context) error {
			fmt.Fprintf(c.App.Writer, "%s %s\n", meta.Binary, meta.Version)
			fmt.Fprintf(c.App.Writer, "commit: %s\n", meta.Commit)
			fmt.Fprintf(c.App.Writer, "built:  %s\n", meta.BuildDate)
			return nil
		},
	}
}

func parseLabels(values []string) map[string]string {
	labels := make(map[string]string)
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		labels[key] = strings.TrimSpace(val)
	}
	return labels
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

func parseOptionalTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q must be RFC3339: %w", value, err)
	}
	return parsed.UTC(), nil
}
