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

func inventoryCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "inventory",
		Usage: "manage distributed monitoring inventory",
		Subcommands: []*urfavecli.Command{
			inventoryOrgCommand(meta),
			inventoryProjectCommand(meta),
			inventoryEnvironmentCommand(meta),
			inventoryAppCommand(meta),
			inventoryServiceCommand(meta),
			inventoryHostCommand(meta),
			inventoryAgentCommand(meta),
			inventoryDeployCommand(meta),
		},
	}
}

func inventoryOrgCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "org",
		Usage: "manage organizations",
		Subcommands: []*urfavecli.Command{
			{
				Name:      "add",
				Usage:     "create or update an organization",
				ArgsUsage: "[slug]",
				Flags: []urfavecli.Flag{
					&urfavecli.StringFlag{Name: "slug", Usage: "organization slug"},
					&urfavecli.StringFlag{Name: "name", Usage: "display name"},
				},
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveOrganization(c.Context, hubapp.SaveOrganizationInput{
						Slug: argOrFlag(c, "slug"),
						Name: c.String("name"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved organization %s (%s)\n", item.Slug, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list organizations",
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListOrganizations(c.Context)
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "SLUG\tNAME\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\n", item.Slug, item.Name, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryProjectCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "project",
		Usage: "manage projects",
		Subcommands: []*urfavecli.Command{
			{
				Name:      "add",
				Usage:     "create or update a project",
				ArgsUsage: "[slug]",
				Flags:     append(orgFlag(), &urfavecli.StringFlag{Name: "slug"}, &urfavecli.StringFlag{Name: "name"}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveProject(c.Context, hubapp.SaveProjectInput{
						OrganizationSlug: c.String("org"),
						Slug:             argOrFlag(c, "slug"),
						Name:             c.String("name"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved project %s (%s)\n", item.Slug, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list projects",
				Flags: orgFlag(),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListProjects(c.Context, c.String("org"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "SLUG\tNAME\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\n", item.Slug, item.Name, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryEnvironmentCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:    "environment",
		Aliases: []string{"env"},
		Usage:   "manage environments",
		Subcommands: []*urfavecli.Command{
			{
				Name:      "add",
				Usage:     "create or update an environment",
				ArgsUsage: "[slug]",
				Flags:     append(projectPathFlags(), &urfavecli.StringFlag{Name: "slug"}, &urfavecli.StringFlag{Name: "name"}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveEnvironment(c.Context, hubapp.SaveEnvironmentInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						Slug:             argOrFlag(c, "slug"),
						Name:             c.String("name"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved environment %s (%s)\n", item.Slug, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list environments",
				Flags: projectPathFlags(),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListEnvironments(c.Context, c.String("org"), c.String("project"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "SLUG\tNAME\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\n", item.Slug, item.Name, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryAppCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "app",
		Usage: "manage monitored apps",
		Subcommands: []*urfavecli.Command{
			{
				Name:      "add",
				Usage:     "create or update a monitored app",
				ArgsUsage: "[slug]",
				Flags:     append(environmentPathFlags(), &urfavecli.StringFlag{Name: "slug"}, &urfavecli.StringFlag{Name: "name"}, &urfavecli.StringFlag{Name: "kind"}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveMonitoredApp(c.Context, hubapp.SaveMonitoredAppInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						Slug:             argOrFlag(c, "slug"),
						Name:             c.String("name"),
						Kind:             c.String("kind"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved app %s (%s)\n", item.Slug, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list monitored apps",
				Flags: environmentPathFlags(),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListMonitoredApps(c.Context, c.String("org"), c.String("project"), c.String("env"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "SLUG\tNAME\tKIND\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", item.Slug, item.Name, item.Kind, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryServiceCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "service",
		Usage: "manage app services",
		Subcommands: []*urfavecli.Command{
			{
				Name:      "add",
				Usage:     "create or update a service",
				ArgsUsage: "[slug]",
				Flags:     append(appPathFlags(), &urfavecli.StringFlag{Name: "slug"}, &urfavecli.StringFlag{Name: "name"}, &urfavecli.StringFlag{Name: "role"}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveService(c.Context, hubapp.SaveServiceInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						Slug:             argOrFlag(c, "slug"),
						Name:             c.String("name"),
						Role:             c.String("role"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved service %s (%s)\n", item.Slug, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list services",
				Flags: appPathFlags(),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListServices(c.Context, c.String("org"), c.String("project"), c.String("env"), c.String("app"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "SLUG\tNAME\tROLE\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", item.Slug, item.Name, item.Role, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryHostCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "host",
		Usage: "manage hosts",
		Subcommands: []*urfavecli.Command{
			{
				Name:      "add",
				Usage:     "create or update a host",
				ArgsUsage: "[slug]",
				Flags:     append(environmentPathFlags(), &urfavecli.StringFlag{Name: "slug"}, &urfavecli.StringFlag{Name: "hostname"}, &urfavecli.StringFlag{Name: "region"}, &urfavecli.StringSliceFlag{Name: "label"}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveHost(c.Context, hubapp.SaveHostInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						Slug:             argOrFlag(c, "slug"),
						Hostname:         c.String("hostname"),
						Region:           c.String("region"),
						Labels:           parseLabels(c.StringSlice("label")),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved host %s (%s)\n", item.Slug, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list hosts",
				Flags: environmentPathFlags(),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListHosts(c.Context, c.String("org"), c.String("project"), c.String("env"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "SLUG\tHOSTNAME\tREGION\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", item.Slug, item.Hostname, item.Region, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryAgentCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "agent",
		Usage: "manage agent identities",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "register",
				Usage: "register or update an agent identity",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "host", Required: true},
					&urfavecli.StringFlag{Name: "agent-id", Required: true},
					&urfavecli.StringFlag{Name: "fingerprint", Required: true},
					&urfavecli.StringFlag{Name: "version"},
				),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveAgent(c.Context, hubapp.SaveAgentInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						HostSlug:         c.String("host"),
						AgentID:          c.String("agent-id"),
						Fingerprint:      c.String("fingerprint"),
						Version:          c.String("version"),
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved agent %s (%s)\n", item.AgentID, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list agents for a host",
				Flags: append(environmentPathFlags(), &urfavecli.StringFlag{Name: "host", Required: true}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListAgents(c.Context, c.String("org"), c.String("project"), c.String("env"), c.String("host"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "AGENT_ID\tVERSION\tFINGERPRINT\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", item.AgentID, item.Version, item.Fingerprint, item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func inventoryDeployCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "deploy",
		Usage: "manage deployment markers",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "add",
				Usage: "record a deployment marker",
				Flags: append(environmentPathFlags(),
					&urfavecli.StringFlag{Name: "app"},
					&urfavecli.StringFlag{Name: "version", Required: true},
					&urfavecli.StringFlag{Name: "commit"},
					&urfavecli.StringFlag{Name: "actor"},
					&urfavecli.StringFlag{Name: "started-at"},
					&urfavecli.StringFlag{Name: "finished-at"},
				),
				Action: func(c *urfavecli.Context) error {
					startedAt, err := parseOptionalTime(c.String("started-at"))
					if err != nil {
						return err
					}
					finishedAt, err := parseOptionalTimePtr(c.String("finished-at"))
					if err != nil {
						return err
					}
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					item, err := container.Hub.SaveDeploymentMarker(c.Context, hubapp.SaveDeploymentMarkerInput{
						OrganizationSlug: c.String("org"),
						ProjectSlug:      c.String("project"),
						EnvironmentSlug:  c.String("env"),
						AppSlug:          c.String("app"),
						Version:          c.String("version"),
						CommitSHA:        c.String("commit"),
						Actor:            c.String("actor"),
						StartedAt:        startedAt,
						FinishedAt:       finishedAt,
					})
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Saved deployment %s (%s)\n", item.Version, item.ID)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list deployment markers",
				Flags: append(environmentPathFlags(), &urfavecli.StringFlag{Name: "app"}),
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()
					items, err := container.Hub.ListDeploymentMarkers(c.Context, c.String("org"), c.String("project"), c.String("env"), c.String("app"))
					if err != nil {
						return err
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "VERSION\tCOMMIT\tACTOR\tSTARTED_AT\tID")
					for _, item := range items {
						fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", item.Version, item.CommitSHA, item.Actor, item.StartedAt.Format(time.RFC3339), item.ID)
					}
					return writer.Flush()
				},
			},
		},
	}
}

func orgFlag() []urfavecli.Flag {
	return []urfavecli.Flag{&urfavecli.StringFlag{Name: "org", Required: true}}
}

func projectPathFlags() []urfavecli.Flag {
	return []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "org", Required: true},
		&urfavecli.StringFlag{Name: "project", Required: true},
	}
}

func environmentPathFlags() []urfavecli.Flag {
	return []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "org", Required: true},
		&urfavecli.StringFlag{Name: "project", Required: true},
		&urfavecli.StringFlag{Name: "env", Required: true},
	}
}

func appPathFlags() []urfavecli.Flag {
	return []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "org", Required: true},
		&urfavecli.StringFlag{Name: "project", Required: true},
		&urfavecli.StringFlag{Name: "env", Required: true},
		&urfavecli.StringFlag{Name: "app", Required: true},
	}
}

func argOrFlag(c *urfavecli.Context, name string) string {
	value := c.String(name)
	if value == "" && c.NArg() > 0 {
		return c.Args().First()
	}
	return value
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

func parseOptionalTimePtr(value string) (*time.Time, error) {
	parsed, err := parseOptionalTime(value)
	if err != nil || parsed.IsZero() {
		return nil, err
	}
	return &parsed, nil
}
