package cli

import (
	"context"
	"fmt"
	nethttp "net/http"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	httpadapter "github.com/rcooler/aegrail/hub/internal/adapters/http"
	"github.com/rcooler/aegrail/hub/internal/bootstrap"
	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/wire"
	urfavecli "github.com/urfave/cli/v3"
)

const (
	hubMaxHeaderValueCount = 256
	hubGracefulStopTimeout = 5 * time.Second
)

func New(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:                  meta.Binary,
		Usage:                 "Aegrail Hub: ingest, store, report, and triage agent evidence",
		Version:               meta.Version,
		EnableShellCompletion: true,
		Commands:              hubCommandSet(meta),
	}
}

func hubCommandSet(meta domain.AppMeta) []*urfavecli.Command {
	return []*urfavecli.Command{
		versionCommand(meta),
		dbCommand(meta),
		hubHealthcheckCommand(meta),
		hubServeCommand(meta),
		hubIngestCommand(meta),
		hubBaselineCommand(meta),
		hubCorrelationCommand(meta),
		hubFindingsCommand(meta),
		hubBrowserScriptsCommand(meta),
		hubModelAnalysisCommand(meta),
		hubRulesCommand(),
		hubUsersCommand(meta),
		notificationsCommand(),
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
		Commands: []*urfavecli.Command{
			{
				Name:  "keygen",
				Usage: "generate a Hub X25519 private/public key pair",
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					privateKey, publicKey, err := wire.GenerateKeyPair()
					if err != nil {
						return err
					}
					fmt.Fprintf(c.Root().Writer, "AEGRAIL_HUB_WIRE_PRIVATE_KEY=%s\n", privateKey)
					fmt.Fprintf(c.Root().Writer, "hub_public_key=%s\n", publicKey)
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
				Sources: urfavecli.EnvVars("AEGRAIL_HTTP_ADDR"),
				Value:   "127.0.0.1:8787",
			},
			&urfavecli.StringFlag{
				Name:    "wire-private-key",
				Usage:   "Hub X25519 private key for encrypted Agent wire envelopes",
				Sources: urfavecli.EnvVars("AEGRAIL_HUB_WIRE_PRIVATE_KEY"),
			},
			&urfavecli.DurationFlag{
				Name:    "wire-timestamp-skew",
				Usage:   "accepted timestamp skew for encrypted Agent wire envelopes",
				Sources: urfavecli.EnvVars("AEGRAIL_HUB_WIRE_TIMESTAMP_SKEW"),
				Value:   5 * time.Minute,
			},
			&urfavecli.StringFlag{
				Name:    "dashboard-dir",
				Usage:   "built dashboard directory to serve under /dashboard",
				Sources: urfavecli.EnvVars("AEGRAIL_DASHBOARD_DIR"),
			},
			&urfavecli.BoolFlag{
				Name:    "model-analysis-auto",
				Usage:   "automatically generate missing model analysis reports for open findings",
				Sources: urfavecli.EnvVars("AEGRAIL_MODEL_ANALYSIS_AUTO"),
				Value:   true,
			},
			&urfavecli.DurationFlag{
				Name:    "model-analysis-interval",
				Usage:   "how often the Hub scans open findings for missing model analysis",
				Sources: urfavecli.EnvVars("AEGRAIL_MODEL_ANALYSIS_INTERVAL"),
				Value:   time.Minute,
			},
			&urfavecli.IntFlag{
				Name:    "model-analysis-limit",
				Usage:   "maximum open findings checked per automatic model-analysis pass",
				Sources: urfavecli.EnvVars("AEGRAIL_MODEL_ANALYSIS_LIMIT"),
				Value:   5,
			},
			&urfavecli.IntFlag{
				Name:    "correlation-workers",
				Usage:   "number of Redis-backed ingest correlation workers; ignored when Redis is not configured",
				Sources: urfavecli.EnvVars("AEGRAIL_CORRELATION_WORKERS"),
				Value:   1,
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			container, err := bootstrap.NewContainer(meta)
			if err != nil {
				return err
			}
			defer container.Close()
			wirePrivateKey := strings.TrimSpace(c.String("wire-private-key"))
			if wirePrivateKey != "" {
				container.Config.Hub.WirePrivateKey = wirePrivateKey
			}
			if err := container.Config.ValidateServe(); err != nil {
				return err
			}
			if err := container.ConnectDatabase(ctx); err != nil {
				return err
			}
			if container.Config.Hub.MigrateOnStart {
				container.Logger.Info().Msg("AEGRAIL_MIGRATE_ON_START is enabled; applying database migrations before starting hub serve")
				if err := container.MigrateDatabase(ctx); err != nil {
					return err
				}
			}
			if !container.Config.Hub.AllowPendingMigrations {
				if err := container.EnsureDatabaseCurrent(ctx); err != nil {
					return err
				}
			} else {
				container.Logger.Warn().Msg("AEGRAIL_ALLOW_PENDING_MIGRATIONS is enabled; hub serve is skipping the migration currency check")
			}

			ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if container.Hub.StartTrafficBackfillWorker(ctx, hubapp.TrafficBackfillWorkerOptions{
				OnComplete: func(projected int) {
					if projected > 0 {
						container.Logger.Info().Int("projected", projected).Msg("completed recent access traffic backfill")
					}
				},
				OnError: func(err error) {
					container.Logger.Error().Err(err).Msg("recent access traffic backfill failed")
				},
			}) {
				container.Logger.Debug().Msg("started bounded recent access traffic backfill")
			}
			if container.Hub.StartNotificationOutboxWorker(ctx, hubapp.NotificationOutboxWorkerOptions{
				OnError: func(err error) {
					container.Logger.Error().Err(err).Msg("notification outbox worker failed")
				},
			}) {
				container.Logger.Info().Msg("started durable notification outbox worker")
			}
			if c.Bool("model-analysis-auto") {
				container.Hub.StartModelAnalysisWorker(ctx, hubapp.ModelAnalysisWorkerOptions{
					Interval: c.Duration("model-analysis-interval"),
					Limit:    c.Int("model-analysis-limit"),
					OnError: func(err error) {
						container.Logger.Error().Err(err).Msg("model analysis worker failed")
					},
				})
			}
			if container.Config.Hub.MaintenanceEvery > 0 {
				container.Hub.StartMaintenanceWorker(ctx, hubapp.MaintenanceWorkerOptions{
					Interval:                 container.Config.Hub.MaintenanceEvery,
					EventRetention:           container.Config.Hub.RetentionEvents,
					ResolvedFindingRetention: container.Config.Hub.RetentionResolvedFindings,
					ModelReportRetention:     container.Config.Hub.RetentionModelReports,
					AuthEventRetention:       container.Config.Hub.RetentionAuthEvents,
					BatchSize:                container.Config.Hub.RetentionBatchSize,
					OnRun: func(result domain.HubMaintenancePruneResult) {
						log := container.Logger.Info().
							Int("ingest_events_deleted", result.IngestEventsDeleted).
							Int("ingest_batches_deleted", result.IngestBatchesDeleted).
							Int("resolved_findings_deleted", result.ResolvedFindingsDeleted).
							Int("model_reports_deleted", result.ModelReportsDeleted).
							Int("auth_events_deleted", result.AuthEventsDeleted)
						if container.Config.Hub.DBSoftLimitBytes > 0 {
							status, err := container.Hub.GetHubSystemStatus(ctx)
							if err != nil {
								container.Logger.Warn().Err(err).Msg("could not read hub database size after maintenance")
							} else if status.DatabaseSizeBytes > container.Config.Hub.DBSoftLimitBytes {
								container.Logger.Warn().
									Int64("database_size_bytes", status.DatabaseSizeBytes).
									Int64("soft_limit_bytes", container.Config.Hub.DBSoftLimitBytes).
									Msg("hub database size is above configured soft limit")
							}
						}
						log.Msg("hub maintenance prune completed")
					},
					OnError: func(err error) {
						container.Logger.Error().Err(err).Msg("hub maintenance worker failed")
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
			var ingestDebugLog func(stage string, fields map[string]any)
			if container.Config.Hub.IngestDebug {
				container.Logger.Info().Msg("hub ingest debug logging enabled")
				ingestDebugLog = func(stage string, fields map[string]any) {
					event := container.Logger.Info().Str("stage", stage)
					for key, value := range fields {
						event = event.Interface(key, value)
					}
					event.Msg("hub ingest debug")
				}
			}

			addr := c.String("addr")
			handler := httpadapter.NewHubRouter(meta, container.Hub, httpadapter.HubOptions{
				WirePrivateKey:      container.Config.Hub.WirePrivateKey,
				WireTimestampSkew:   c.Duration("wire-timestamp-skew"),
				DashboardDir:        c.String("dashboard-dir"),
				DashboardCSRFSecret: container.Config.Hub.UserSecretKey,
				PushVAPIDPublicKey:  container.Config.Notifications.Push.VAPIDPublicKey,
				TrustedProxyCIDRs:   container.Config.Hub.TrustedProxyCIDRs,
				HealthCheck:         container.HealthCheck,
				IngestDebugLog:      ingestDebugLog,
			})
			server := newHubHTTPServer(addr, handler)

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
				shutdownCtx, cancel := newHubShutdownContext(ctx)
				defer cancel()
				container.Logger.Info().Msg("stopping aegrail hub api")
				shutdownErr := server.Shutdown(shutdownCtx)
				workerWaitCtx, cancelWorkerWait := newHubShutdownContext(ctx)
				defer cancelWorkerWait()
				workersDone := make(chan struct{})
				go func() {
					container.Hub.WaitForWorkers()
					close(workersDone)
				}()
				select {
				case <-workersDone:
				case <-workerWaitCtx.Done():
					container.Logger.Warn().Msg("timed out waiting for background workers")
				}
				return shutdownErr
			}
		},
	}
}

func newHubShutdownContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), hubGracefulStopTimeout)
}

func newHubHTTPServer(addr string, handler nethttp.Handler) *nethttp.Server {
	return &nethttp.Server{
		Addr:                addr,
		Handler:             handler,
		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        60 * time.Second,
		IdleTimeout:         60 * time.Second,
		MaxHeaderValueCount: hubMaxHeaderValueCount,
	}
}

func hubHealthcheckCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "healthcheck",
		Usage: "check Hub dependencies for container health probes",
		Flags: []urfavecli.Flag{
			&urfavecli.DurationFlag{
				Name:    "timeout",
				Usage:   "maximum healthcheck duration",
				Sources: urfavecli.EnvVars("AEGRAIL_HEALTHCHECK_TIMEOUT"),
				Value:   3 * time.Second,
			},
		},
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			ctx, cancel := context.WithTimeout(ctx, c.Duration("timeout"))
			defer cancel()

			container, err := bootstrap.NewContainer(meta)
			if err != nil {
				return err
			}
			defer container.Close()
			if err := container.Config.ValidateServe(); err != nil {
				return err
			}
			if err := container.ConnectDatabase(ctx); err != nil {
				return err
			}
			if !container.Config.Hub.AllowPendingMigrations {
				if err := container.EnsureDatabaseCurrent(ctx); err != nil {
					return err
				}
			}
			checks := container.HealthCheck(ctx)
			status, healthy := hubHealthStatus(checks)
			fmt.Fprintf(c.Root().Writer, "status: %s\n", status)
			names := make([]string, 0, len(checks))
			for name := range checks {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fmt.Fprintf(c.Root().Writer, "%s: %s\n", name, checks[name])
			}
			if !healthy {
				return urfavecli.Exit("hub healthcheck failed", 1)
			}
			return nil
		},
	}
}

func hubHealthStatus(checks map[string]string) (string, bool) {
	status := "ok"
	healthy := true
	for name, value := range checks {
		if value == "ok" || strings.HasPrefix(value, "ok: ") || value == "offline" {
			continue
		}
		if isOptionalCLIHealthCheck(name) {
			status = "degraded"
			continue
		}
		return "unhealthy", false
	}
	return status, healthy
}

func isOptionalCLIHealthCheck(name string) bool {
	return name == "ollama"
}

func analyzeReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "analyze",
		Usage: "inspect the model gateway and generate model-assisted reports",
		Commands: []*urfavecli.Command{
			{
				Name:  "model",
				Usage: "inspect the model gateway and generate reports",
				Commands: []*urfavecli.Command{
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
		Commands: []*urfavecli.Command{
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
		Action: func(ctx context.Context, c *urfavecli.Command) error {
			fmt.Fprintf(c.Root().Writer, "%s %s\n", meta.Binary, meta.Version)
			fmt.Fprintf(c.Root().Writer, "commit: %s\n", meta.Commit)
			fmt.Fprintf(c.Root().Writer, "built:  %s\n", meta.BuildDate)
			return nil
		},
	}
}

func dbCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "db",
		Usage: "manage the Aegrail database",
		Commands: []*urfavecli.Command{
			{
				Name:  "migrate",
				Usage: "apply database migrations",
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					container, cleanup, err := newDatabaseContainer(ctx, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					if err := container.MigrateDatabase(ctx); err != nil {
						return err
					}
					fmt.Fprintln(c.Root().Writer, "Database migrations applied.")
					return nil
				},
			},
			{
				Name:  "status",
				Usage: "show database migration status",
				Action: func(ctx context.Context, c *urfavecli.Command) error {
					container, cleanup, err := newDatabaseContainer(ctx, meta)
					if err != nil {
						return err
					}
					defer cleanup()

					return container.DatabaseStatus(ctx)
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
