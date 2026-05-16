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
	hubapp "github.com/rcooler/aegrail/internal/hub"
	"github.com/rcooler/aegrail/internal/modules/catalog"
	urfavecli "github.com/urfave/cli/v2"
)

// New returns the combined CLI app exposing both Hub and Agent commands.
// The split binaries use NewHub and NewAgent; this keeps existing local scripts
// working while the project moves to separate processes.
func New(meta domain.AppMeta) *urfavecli.App {
	return &urfavecli.App{
		Name:    meta.Binary,
		Usage:   "monitoring and incident triage for small web application estates",
		Version: meta.Version,
		Commands: []*urfavecli.Command{
			versionCommand(meta),
			dbCommand(meta),
			hubCommand(meta),
			inventoryCommand(meta),
			reportCommand(meta),
			agentCommand(meta),
			collectorCommand(meta),
			moduleCommand(),
			analyzeCommand(meta),
		},
	}
}

func NewHub(meta domain.AppMeta) *urfavecli.App {
	return &urfavecli.App{
		Name:     meta.Binary,
		Usage:    "Aegrail Hub: ingest, store, report, and triage agent evidence",
		Version:  meta.Version,
		Commands: hubCommandSet(meta),
	}
}

func NewAgent(meta domain.AppMeta) *urfavecli.App {
	return &urfavecli.App{
		Name:     meta.Binary,
		Usage:    "Aegrail Agent: scan a site instance and forward signed evidence to the Hub",
		Version:  meta.Version,
		Commands: agentCommandSet(meta),
	}
}

func hubCommandSet(meta domain.AppMeta) []*urfavecli.Command {
	return []*urfavecli.Command{
		versionCommand(meta),
		dbCommand(meta),
		hubCommand(meta),
		inventoryCommand(meta),
		reportCommand(meta),
		analyzeReportCommand(meta),
	}
}

func agentCommandSet(meta domain.AppMeta) []*urfavecli.Command {
	return []*urfavecli.Command{
		versionCommand(meta),
		agentCommand(meta),
		collectorCommand(meta),
		moduleCommand(),
		analyzeModelInspectCommand(meta),
	}
}

func analyzeCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "analyze",
		Usage: "inspect the model gateway and generate model-assisted reports",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "model",
				Usage: "inspect the model gateway and generate reports",
				Subcommands: []*urfavecli.Command{
					modelStatusCommand(meta),
					modelPromptCommand(meta),
					modelEmbedCommand(meta),
					modelReportCommand(meta),
				},
			},
		},
	}
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
			hubModelAnalysisCommand(meta),
			hubRulesCommand(),
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
			&urfavecli.StringFlag{
				Name:    "dashboard-dir",
				Usage:   "built dashboard directory to serve under /dashboard",
				EnvVars: []string{"AEGRAIL_DASHBOARD_DIR"},
			},
			&urfavecli.BoolFlag{
				Name:    "model-analysis-auto",
				Usage:   "automatically generate missing model analysis reports for open findings",
				EnvVars: []string{"AEGRAIL_MODEL_ANALYSIS_AUTO"},
				Value:   true,
			},
			&urfavecli.DurationFlag{
				Name:    "model-analysis-interval",
				Usage:   "how often the Hub scans open findings for missing model analysis",
				EnvVars: []string{"AEGRAIL_MODEL_ANALYSIS_INTERVAL"},
				Value:   time.Minute,
			},
			&urfavecli.IntFlag{
				Name:    "model-analysis-limit",
				Usage:   "maximum open findings checked per automatic model-analysis pass",
				EnvVars: []string{"AEGRAIL_MODEL_ANALYSIS_LIMIT"},
				Value:   5,
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
			if c.Bool("model-analysis-auto") {
				container.Hub.StartModelAnalysisWorker(ctx, hubapp.ModelAnalysisWorkerOptions{
					Interval: c.Duration("model-analysis-interval"),
					Limit:    c.Int("model-analysis-limit"),
				})
			}

			addr := c.String("addr")
			server := &nethttp.Server{
				Addr: addr,
				Handler: httpadapter.NewHubRouter(meta, container.Hub, httpadapter.HubOptions{
					IngestSecret:        c.String("ingest-secret"),
					IngestSignatureSkew: c.Duration("signature-skew"),
					DashboardDir:        c.String("dashboard-dir"),
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
		Usage: "run application collector workflows",
		Subcommands: []*urfavecli.Command{
			collectorBrowserCommand(meta),
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

					if err := container.MigrateDatabase(c.Context); err != nil {
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

					return container.DatabaseStatus(c.Context)
				},
			},
		},
	}
}

func analyzeReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "analyze",
		Usage: "generate model-assisted reports from persisted Hub findings",
		Subcommands: []*urfavecli.Command{
			analyzeModelReportSubcommand(meta),
		},
	}
}

func analyzeModelInspectCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "analyze",
		Usage: "inspect and smoke-test the configured model gateway",
		Subcommands: []*urfavecli.Command{
			analyzeModelInspectSubcommand(meta),
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
			modelAnalysisReportCommand(meta),
			timelineReportCommand(meta),
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
