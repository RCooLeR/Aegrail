package cli

import (
	"context"
	"fmt"
	nethttp "net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	httpadapter "github.com/rcooler/aegrail/hub/internal/adapters/http"
	"github.com/rcooler/aegrail/hub/internal/bootstrap"
	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/wire"
	urfavecli "github.com/urfave/cli/v2"
)

func New(meta domain.AppMeta) *urfavecli.App {
	return &urfavecli.App{
		Name:     meta.Binary,
		Usage:    "Aegrail Hub: ingest, store, report, and triage agent evidence",
		Version:  meta.Version,
		Commands: hubCommandSet(meta),
	}
}

func hubCommandSet(meta domain.AppMeta) []*urfavecli.Command {
	return []*urfavecli.Command{
		versionCommand(meta),
		dbCommand(meta),
		hubServeCommand(meta),
		hubIngestCommand(meta),
		hubBaselineCommand(meta),
		hubCorrelationCommand(meta),
		hubFindingsCommand(meta),
		hubBrowserScriptsCommand(meta),
		hubModelAnalysisCommand(meta),
		hubRulesCommand(),
		inventoryCommand(meta),
		wireCommand(),
		reportCommand(meta),
		analyzeReportCommand(meta),
	}
}

func wireCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "wire",
		Usage: "manage Agent-Hub encrypted wire protocol keys",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "keygen",
				Usage: "generate a Hub X25519 private/public key pair",
				Action: func(c *urfavecli.Context) error {
					privateKey, publicKey, err := wire.GenerateKeyPair()
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "AEGRAIL_HUB_WIRE_PRIVATE_KEY=%s\n", privateKey)
					fmt.Fprintf(c.App.Writer, "hub_public_key=%s\n", publicKey)
					return nil
				},
			},
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
				Name:    "wire-private-key",
				Usage:   "Hub X25519 private key for encrypted Agent wire envelopes",
				EnvVars: []string{"AEGRAIL_HUB_WIRE_PRIVATE_KEY"},
			},
			&urfavecli.DurationFlag{
				Name:    "wire-timestamp-skew",
				Usage:   "accepted timestamp skew for encrypted Agent wire envelopes",
				EnvVars: []string{"AEGRAIL_HUB_WIRE_TIMESTAMP_SKEW"},
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
			&urfavecli.IntFlag{
				Name:    "correlation-workers",
				Usage:   "number of Redis-backed ingest correlation workers; ignored when Redis is not configured",
				EnvVars: []string{"AEGRAIL_CORRELATION_WORKERS"},
				Value:   2,
			},
		},
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()
			wirePrivateKey := strings.TrimSpace(c.String("wire-private-key"))
			if wirePrivateKey != "" {
				container.Config.Hub.WirePrivateKey = wirePrivateKey
			}
			if err := container.Config.ValidateServe(); err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if c.Bool("model-analysis-auto") {
				container.Hub.StartModelAnalysisWorker(ctx, hubapp.ModelAnalysisWorkerOptions{
					Interval: c.Duration("model-analysis-interval"),
					Limit:    c.Int("model-analysis-limit"),
					OnError: func(err error) {
						container.Logger.Error().Err(err).Msg("model analysis worker failed")
					},
				})
			}
			if container.Hub.StartCorrelationWorker(ctx, hubapp.CorrelationWorkerOptions{
				Workers: c.Int("correlation-workers"),
				OnError: func(err error) {
					container.Logger.Error().Err(err).Msg("correlation worker failed")
				},
			}) {
				container.Logger.Info().Int("workers", c.Int("correlation-workers")).Msg("started redis correlation workers")
			}

			addr := c.String("addr")
			server := &nethttp.Server{
				Addr: addr,
				Handler: httpadapter.NewHubRouter(meta, container.Hub, httpadapter.HubOptions{
					WirePrivateKey:    container.Config.Hub.WirePrivateKey,
					WireTimestampSkew: c.Duration("wire-timestamp-skew"),
					DashboardDir:      c.String("dashboard-dir"),
					HealthCheck:       container.HealthCheck,
				}),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       60 * time.Second,
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
				shutdownErr := server.Shutdown(shutdownCtx)
				workersDone := make(chan struct{})
				go func() {
					container.Hub.WaitForWorkers()
					close(workersDone)
				}()
				select {
				case <-workersDone:
				case <-time.After(5 * time.Second):
					container.Logger.Warn().Msg("timed out waiting for background workers")
				}
				return shutdownErr
			}
		},
	}
}

func analyzeReportCommand(meta domain.AppMeta) *urfavecli.Command {
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

func reportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "report",
		Usage: "generate reports from findings and timelines",
		Subcommands: []*urfavecli.Command{
			hubFindingsReportCommand(meta),
			findingReviewReportCommand(meta),
			evidenceBundleReportCommand(meta),
			modelAnalysisReportCommand(meta),
			timelineReportCommand(meta),
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
