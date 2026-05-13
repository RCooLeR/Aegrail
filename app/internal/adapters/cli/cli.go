package cli

import (
	"context"
	"fmt"
	nethttp "net/http"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	httpadapter "github.com/rcooler/aegrail/internal/adapters/http"
	"github.com/rcooler/aegrail/internal/bootstrap"
	"github.com/rcooler/aegrail/internal/domain"
	localapp "github.com/rcooler/aegrail/internal/local"
	"github.com/rcooler/aegrail/internal/modules/catalog"
	urfavecli "github.com/urfave/cli/v2"
)

func New(meta domain.AppMeta) *urfavecli.App {
	app := &urfavecli.App{
		Name:    meta.Binary,
		Usage:   "security audit and incident triage for small web applications",
		Version: meta.Version,
		Commands: []*urfavecli.Command{
			versionCommand(meta),
			initCommand(meta),
			dbCommand(meta),
			hubCommand(meta),
			agentCommand(meta),
			collectorCommand(meta),
			siteCommand(meta),
			inventoryCommand(meta),
			moduleCommand(),
			importCommand(meta),
			diffCommand(meta),
			scanCommand(meta),
			analyzeCommand(meta),
			reportCommand(meta),
			serveCommand(meta),
		},
	}
	return app
}

func hubCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "hub",
		Usage: "run central Aegrail Hub workflows",
		Subcommands: []*urfavecli.Command{
			hubServeCommand(meta),
			hubIngestCommand(meta),
			hubBaselineCommand(meta),
			hubCorrelationCommand(meta),
			hubFindingsCommand(meta),
			hubBrowserScriptsCommand(meta),
			hubRulesCommand(),
			inventoryCommand(meta),
		},
	}
}

func hubServeCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "serve",
		Usage: "start the central Hub HTTP API",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:    "addr",
				Usage:   "HTTP listen address",
				EnvVars: []string{"AEGRAIL_HTTP_ADDR"},
				Value:   "127.0.0.1:8787",
			},
			&urfavecli.StringFlag{
				Name:    "ingest-secret",
				Usage:   "shared HMAC secret for Hub ingest requests",
				EnvVars: []string{"AEGRAIL_HUB_INGEST_SECRET"},
			},
			&urfavecli.DurationFlag{
				Name:    "signature-skew",
				Usage:   "accepted timestamp skew for signed ingest requests",
				EnvVars: []string{"AEGRAIL_HUB_INGEST_SIGNATURE_SKEW"},
				Value:   5 * time.Minute,
			},
		},
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx, stop := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			addr := c.String("addr")
			server := &nethttp.Server{
				Addr: addr,
				Handler: httpadapter.NewHubRouter(meta, container.Hub, httpadapter.HubOptions{
					IngestSecret:        c.String("ingest-secret"),
					IngestSignatureSkew: c.Duration("signature-skew"),
				}),
				ReadHeaderTimeout: 5 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				container.Logger.Info().Str("addr", addr).Msg("starting aegrail hub api")
				errCh <- server.ListenAndServe()
			}()

			select {
			case err := <-errCh:
				if err == nethttp.ErrServerClosed {
					return nil
				}
				return err
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				container.Logger.Info().Msg("stopping aegrail hub api")
				return server.Shutdown(shutdownCtx)
			}
		},
	}
}

func agentCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "agent",
		Usage: "run per-server Aegrail Agent workflows",
		Subcommands: []*urfavecli.Command{
			agentInstallCommand(),
			agentConfigCommand(),
			agentStatusCommand(),
			agentEnqueueCommand(),
			agentSendCommand("send", "send queued batches to the Hub"),
			agentStartCommand(),
			agentRunCommand(),
		},
	}
}

func collectorCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "collector",
		Usage: "run app and database collector workflows",
		Subcommands: []*urfavecli.Command{
			collectorBrowserCommand(meta),
			{
				Name:  "db",
				Usage: "run database collector workflows",
				Subcommands: []*urfavecli.Command{
					placeholderCommand(meta, "start", "start a database collector"),
					placeholderCommand(meta, "status", "show database collector status"),
				},
			},
		},
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

func initCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "init",
		Usage: "create the local Aegrail workspace directories",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:    "data-dir",
				Usage:   "local runtime data directory",
				EnvVars: []string{"AEGRAIL_DATA_DIR"},
				Value:   "data",
			},
		},
		Action: func(c *urfavecli.Context) error {
			container, err := bootstrap.NewContainer(meta)
			if err != nil {
				return err
			}

			result, err := container.Local.InitProject(c.Context, localapp.InitProjectInput{
				DataDir: c.String("data-dir"),
			})
			if err != nil {
				return err
			}

			container.Logger.Info().
				Str("data_dir", result.DataDir).
				Int("dir_count", len(result.CreatedDirs)).
				Msg("initialized aegrail workspace")

			fmt.Fprintf(c.App.Writer, "Initialized Aegrail workspace at %s\n", result.DataDir)
			for _, dir := range result.CreatedDirs {
				fmt.Fprintf(c.App.Writer, "  %s\n", dir)
			}
			return nil
		},
	}
}

func siteCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "site",
		Usage: "manage monitored sites",
		Subcommands: []*urfavecli.Command{
			siteAddCommand(meta),
			siteListCommand(meta),
		},
	}
}

func dbCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "db",
		Usage: "manage the Aegrail database",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "migrate",
				Usage: "apply database migrations",
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					if err := container.Local.MigrateDatabase(c.Context); err != nil {
						return err
					}
					fmt.Fprintln(c.App.Writer, "Database migrations applied.")
					return nil
				},
			},
			{
				Name:  "status",
				Usage: "show database migration status",
				Action: func(c *urfavecli.Context) error {
					container, cleanup, err := newDatabaseContainer(c.Context, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					return container.Local.DatabaseStatus(c.Context)
				},
			},
		},
	}
}

func siteAddCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "add",
		Usage:     "register or update a monitored site",
		ArgsUsage: "[slug]",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:  "slug",
				Usage: "stable site slug",
			},
			&urfavecli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "display name",
			},
			&urfavecli.StringFlag{
				Name:  "url",
				Usage: "site base URL",
			},
		},
		Action: func(c *urfavecli.Context) error {
			slug := c.String("slug")
			if slug == "" && c.NArg() > 0 {
				slug = c.Args().First()
			}

			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			site, err := container.Local.CreateSite(c.Context, localapp.CreateSiteInput{
				Slug:    slug,
				Name:    c.String("name"),
				BaseURL: c.String("url"),
			})
			if err != nil {
				return err
			}

			fmt.Fprintf(c.App.Writer, "Saved site %s (%s)\n", site.Slug, site.ID)
			return nil
		},
	}
}

func siteListCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "list",
		Usage: "list monitored sites",
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			sites, err := container.Local.ListSites(c.Context)
			if err != nil {
				return err
			}
			if len(sites) == 0 {
				fmt.Fprintln(c.App.Writer, "No sites registered.")
				return nil
			}

			writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
			fmt.Fprintln(writer, "SLUG\tNAME\tURL\tID")
			for _, site := range sites {
				fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", site.Slug, site.Name, site.BaseURL, site.ID)
			}
			return writer.Flush()
		},
	}
}

func importCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "import",
		Usage: "import local evidence",
		Subcommands: []*urfavecli.Command{
			importLocalCommand(meta, "files", "files", "import local files as raw evidence"),
			importLocalCommand(meta, "logs", "logs", "import web or application logs as raw evidence"),
			placeholderCommand(meta, "prestashop-db", "import a PrestaShop database snapshot"),
		},
	}
}

func importLocalCommand(meta domain.AppMeta, name string, sourceType string, usage string) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  name,
		Usage: usage,
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:     "site",
				Usage:    "site slug",
				Required: true,
			},
			&urfavecli.StringFlag{
				Name:     "path",
				Usage:    "file or directory path to import",
				Required: true,
			},
			&urfavecli.StringFlag{
				Name:  "source-type",
				Usage: "override the stored evidence source type",
				Value: sourceType,
			},
		},
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			result, err := container.Local.ImportLocalEvidence(c.Context, localapp.ImportLocalEvidenceInput{
				SiteSlug:   c.String("site"),
				SourceType: c.String("source-type"),
				Path:       c.String("path"),
			})
			if err != nil {
				return err
			}

			action := "Imported"
			if result.Reused {
				action = "Reused"
			}
			fmt.Fprintf(
				c.App.Writer,
				"%s %d evidence object(s) for site %s as import %s\n",
				action,
				len(result.Refs),
				c.String("site"),
				result.Import.ID,
			)
			return nil
		},
	}
}

func analyzeCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "analyze",
		Usage: "run deterministic analysis and optional model-assisted workflows",
		Subcommands: []*urfavecli.Command{
			analyzeModelCommand(meta),
		},
	}
}

func diffCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "diff",
		Usage: "compare snapshots and baselines",
		Subcommands: []*urfavecli.Command{
			placeholderCommand(meta, "db", "compare database snapshots"),
		},
	}
}

func scanCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "scan",
		Usage: "scan local evidence",
		Subcommands: []*urfavecli.Command{
			placeholderCommand(meta, "files", "scan a file snapshot"),
		},
	}
}

func reportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "report",
		Usage: "generate reports from findings and timelines",
		Subcommands: []*urfavecli.Command{
			hubFindingsReportCommand(meta),
			evidenceBundleReportCommand(meta),
			timelineReportCommand(meta),
		},
	}
}

func serveCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "serve",
		Usage: "start the local HTTP API",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{
				Name:    "addr",
				Usage:   "HTTP listen address",
				EnvVars: []string{"AEGRAIL_HTTP_ADDR"},
				Value:   "127.0.0.1:8787",
			},
		},
		Action: func(c *urfavecli.Context) error {
			container, err := bootstrap.NewContainer(meta)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			addr := c.String("addr")
			server := &nethttp.Server{
				Addr:              addr,
				Handler:           httpadapter.NewRouter(meta),
				ReadHeaderTimeout: 5 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				container.Logger.Info().Str("addr", addr).Msg("starting aegrail http api")
				errCh <- server.ListenAndServe()
			}()

			select {
			case err := <-errCh:
				if err == nethttp.ErrServerClosed {
					return nil
				}
				return err
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				container.Logger.Info().Msg("stopping aegrail http api")
				return server.Shutdown(shutdownCtx)
			}
		},
	}
}

func placeholderCommand(meta domain.AppMeta, name string, usage string) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  name,
		Usage: usage,
		Action: func(c *urfavecli.Context) error {
			fmt.Fprintf(c.App.Writer, "%s %s is planned but not implemented yet.\n", meta.Binary, c.Command.FullName())
			return nil
		},
	}
}

func newDatabaseContainer(ctx context.Context, meta domain.AppMeta) (*bootstrap.Container, func(), error) {
	container, err := bootstrap.NewContainer(meta)
	if err != nil {
		return nil, nil, err
	}
	if err := container.ConnectDatabase(ctx); err != nil {
		container.Close()
		return nil, nil, err
	}
	return container, container.Close, nil
}
