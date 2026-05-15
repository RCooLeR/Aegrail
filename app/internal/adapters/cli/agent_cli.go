package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/agent"
	"github.com/rcooler/aegrail/internal/collector"
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
			runtime := newAgentStatusRuntime(c)
			status, err := runtime.Status(c.Context)
			if err != nil {
				return err
			}
			writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
			fmt.Fprintln(writer, "CONFIG\tQUEUE\tINSTALLED\tPENDING\tSENT\tFAILED\tDISCARDED")
			fmt.Fprintf(writer, "%s\t%s\t%t\t%d\t%d\t%d\t%d\n", status.ConfigPath, status.QueueDir, status.Installed, status.Pending, status.Sent, status.Failed, status.Discarded)
			return writer.Flush()
		},
	}
}

func agentConfigCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "config",
		Usage: "inspect Agent server configuration",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "validate",
				Usage: "validate a multi-site Agent config",
				Flags: []urfavecli.Flag{
					&urfavecli.StringFlag{Name: "config", Usage: "Agent server config path", Value: ".aegrail/agent.yaml"},
				},
				Action: func(c *urfavecli.Context) error {
					config, err := agent.LoadServerConfig(c.String("config"))
					if err != nil {
						return err
					}
					fmt.Fprintf(c.App.Writer, "Config valid: %d site(s), host %s, agent %s\n", len(config.Sites), config.Identity.Host, config.Identity.AgentID)
					return nil
				},
			},
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

func agentRunCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "run",
		Usage: "run an Agent from a multi-site server config",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "config", Usage: "Agent server config path", Value: ".aegrail/agent.yaml"},
			&urfavecli.BoolFlag{Name: "once", Usage: "run one scan and exit"},
			&urfavecli.BoolFlag{Name: "bootstrap", Usage: "capture current state as baseline; do not enqueue detection events"},
			&urfavecli.BoolFlag{Name: "discard-pending", Usage: "with --bootstrap, move existing pending queue batches to discarded after baseline"},
			&urfavecli.StringFlag{Name: "secret", Usage: "Hub ingest HMAC secret override", EnvVars: []string{"AEGRAIL_HUB_INGEST_SECRET"}},
			&urfavecli.IntFlag{Name: "send-limit", Usage: "maximum pending batches to send after each scan"},
			&urfavecli.DurationFlag{Name: "interval", Usage: "override configured polling interval"},
		},
		Action: func(c *urfavecli.Context) error {
			config, err := agent.LoadServerConfig(c.String("config"))
			if err != nil {
				return err
			}
			interval := c.Duration("interval")
			if interval <= 0 {
				interval, err = config.RuntimeInterval()
				if err != nil {
					return err
				}
			}
			sendLimit := c.Int("send-limit")
			if sendLimit == 0 {
				sendLimit = config.Hub.SendLimit
			}
			runtime := agent.NewRuntime(agent.Config{
				QueueDir: config.Runtime.QueueDir,
			})
			ctx, stop := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			runOnce := func(config agent.ServerConfig) error {
				secret := agent.ResolveServerConfigSecret(config, c.String("secret"))
				bootstrap := c.Bool("bootstrap")
				if c.Bool("discard-pending") && !bootstrap {
					return fmt.Errorf("--discard-pending can only be used with --bootstrap")
				}
				result, err := runtime.RunServerConfigOnce(ctx, config, "", sendLimit, bootstrap)
				if err != nil {
					return err
				}
				databaseResult, err := runConfiguredDatabaseCollectors(ctx, runtime, config, bootstrap)
				if err != nil {
					return err
				}
				result.Queued += databaseResult.Queued
				browserResult, err := runConfiguredBrowserCrawls(ctx, runtime, config, bootstrap)
				if err != nil {
					return err
				}
				result.Queued += browserResult.Queued
				var coverageResult agent.ServerConfigCoverageRunResult
				if !bootstrap {
					coverageResult, err = runtime.QueueServerConfigCoverage(ctx, config)
					if err != nil {
						return err
					}
				}
				result.Queued += coverageResult.Queued
				if bootstrap {
					status, err := runtime.Status(ctx)
					if err != nil {
						return err
					}
					result.Pending = status.Pending
					if c.Bool("discard-pending") {
						discard, err := runtime.DiscardPending(ctx, 0)
						if err != nil {
							return err
						}
						result.Pending = discard.PendingAfter
						fmt.Fprintf(c.App.Writer, "Discarded %d existing pending batch(es); pending %d\n", discard.Discarded, discard.PendingAfter)
						for _, item := range discard.Errors {
							fmt.Fprintf(c.App.ErrWriter, "%s\n", item)
						}
					}
				} else if secret != "" {
					send, err := runtime.SendQueued(ctx, secret, sendLimit)
					if err != nil {
						return err
					}
					result.Sent = send.Sent
					result.Failed = send.Failed
					result.Pending = send.PendingAfter
					for _, item := range send.Errors {
						fmt.Fprintf(c.App.ErrWriter, "%s\n", item)
					}
				} else {
					status, err := runtime.Status(ctx)
					if err != nil {
						return err
					}
					result.Pending = status.Pending
				}
				fmt.Fprintf(c.App.Writer, "Scanned %d site(s); queued %d event(s); sent %d; failed %d; pending %d\n", len(result.Sites), result.Queued, result.Sent, result.Failed, result.Pending)
				for _, site := range result.Sites {
					fmt.Fprintf(
						c.App.Writer,
						"  %s app=%s service=%s files=%d logs=%d queued=%d state=%s\n",
						site.Slug,
						site.App,
						site.Service,
						site.FilesWatched,
						site.LogsWatched,
						site.Queued,
						site.StateDir,
					)
				}
				if databaseResult.Databases > 0 || databaseResult.Queued > 0 {
					fmt.Fprintf(c.App.Writer, "Database collected %d database(s); queued %d event(s)\n", databaseResult.Databases, databaseResult.Queued)
					for _, site := range databaseResult.Sites {
						fmt.Fprintf(c.App.Writer, "  %s databases=%d baselines=%d changes=%d skipped=%d queued=%d warnings=%d\n", site.Slug, site.Databases, site.Baselines, site.Changes, site.Skipped, site.Queued, site.Warnings)
					}
				}
				if browserResult.Pages > 0 || browserResult.Queued > 0 {
					fmt.Fprintf(c.App.Writer, "Browser crawled %d page(s); queued %d event(s)\n", browserResult.Pages, browserResult.Queued)
					for _, site := range browserResult.Sites {
						fmt.Fprintf(c.App.Writer, "  %s browser_pages=%d queued=%d\n", site.Slug, site.Pages, site.Queued)
					}
				}
				if coverageResult.Sites > 0 {
					fmt.Fprintf(c.App.Writer, "Config coverage checked %d site(s); queued %d update(s)\n", coverageResult.Sites, coverageResult.Queued)
				}
				if bootstrap {
					fmt.Fprintln(c.App.Writer, "Bootstrap mode enabled: baselines captured, no events queued.")
				}
				return nil
			}

			if c.Bool("once") {
				return runOnce(config)
			}

			for {
				if err := runOnce(config); err != nil {
					fmt.Fprintf(c.App.ErrWriter, "%s\n", err)
				}
				timer := time.NewTimer(interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
					nextConfig, err := agent.LoadServerConfig(c.String("config"))
					if err != nil {
						fmt.Fprintf(c.App.ErrWriter, "%s\n", err)
						continue
					}
					config = nextConfig
					if nextInterval, err := config.RuntimeInterval(); err == nil && c.Duration("interval") <= 0 {
						interval = nextInterval
					}
				}
			}
		},
	}
}

type agentDatabaseRunResult struct {
	Sites     []agentDatabaseSiteRunResult
	Databases int
	Queued    int
}

type agentDatabaseSiteRunResult struct {
	Slug      string
	Databases int
	Baselines int
	Changes   int
	Skipped   int
	Queued    int
	Warnings  int
}

func runConfiguredDatabaseCollectors(ctx context.Context, runtime *agent.Runtime, config agent.ServerConfig, bootstrap bool) (agentDatabaseRunResult, error) {
	collectorRuntime := collector.NewRuntime(collector.Config{Name: "database"})
	piiKey := strings.TrimSpace(os.Getenv("AEGRAIL_PII_KEY"))
	summary := agentDatabaseRunResult{}
	for _, site := range config.Sites {
		if len(site.Databases) == 0 {
			continue
		}
		siteSummary := agentDatabaseSiteRunResult{Slug: site.Slug}
		for _, database := range site.Databases {
			profile := databaseProfileForSite(site, database)
			name := databaseEventName(database, profile)
			statePath := databaseStatePath(config, site, collector.DatabaseCollectResult{
				Name:    name,
				Engine:  databaseEngineForConfig(database),
				Profile: profile,
			})
			siteSummary.Databases++
			summary.Databases++
			if !bootstrap {
				schedule, err := parseOptionalDuration(database.Schedule)
				if err != nil {
					return agentDatabaseRunResult{}, fmt.Errorf("site %s database %s schedule: %w", site.Slug, name, err)
				}
				if schedule > 0 {
					skip, err := shouldSkipDatabaseCollection(schedule, statePath)
					if err != nil {
						if !errors.Is(err, os.ErrNotExist) {
							return agentDatabaseRunResult{}, fmt.Errorf("site %s database %s schedule check: %w", site.Slug, name, err)
						}
					} else if skip {
						siteSummary.Skipped++
						continue
					}
				}
			}
			timeout, err := parseOptionalDuration(database.Timeout)
			if err != nil {
				return agentDatabaseRunResult{}, fmt.Errorf("site %s database %s timeout: %w", site.Slug, database.Name, err)
			}
			dsn := strings.TrimSpace(os.Getenv(database.DSNEnv))
			var snapshot collector.DatabaseCollectResult
			if dsn == "" {
				now := time.Now().UTC()
				snapshot = collector.DatabaseCollectResult{
					StartedAt:  now,
					FinishedAt: now,
					Name:       name,
					Engine:     databaseEngineForConfig(database),
					Profile:    profile,
					Warnings:   []string{fmt.Sprintf("database DSN env %s is not set", database.DSNEnv)},
				}
			} else {
				snapshot, err = collectorRuntime.CollectDatabaseSnapshot(ctx, collector.DatabaseCollectInput{
					Name:        name,
					Engine:      database.Engine,
					DSN:         dsn,
					Profile:     profile,
					TablePrefix: database.TablePrefix,
					Timeout:     timeout,
					PIIKey:      piiKey,
				})
				if err != nil {
					now := time.Now().UTC()
					snapshot = collector.DatabaseCollectResult{
						StartedAt:  now,
						FinishedAt: now,
						Name:       name,
						Engine:     databaseEngineForConfig(database),
						Profile:    profile,
						Warnings:   []string{fmt.Sprintf("database collector failed: %v", err)},
					}
				}
			}
			labels := databaseBatchLabels(site, snapshot)
			diffResult, err := collector.UpdateDatabaseSnapshotState(databaseStatePath(config, site, snapshot), snapshot)
			if err != nil {
				snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("database snapshot state update failed: %v", err))
			}
			if diffResult.Baselined {
				siteSummary.Baselines++
			}
			siteSummary.Changes += len(diffResult.Changes) + len(diffResult.EntityChanges)
			siteSummary.Warnings += len(snapshot.Warnings)
			if bootstrap {
				continue
			}
			events := collector.BuildDatabaseSnapshotEvents(snapshot, labels)
			events = append(events, collector.BuildDatabaseSnapshotDiffEvents(snapshot, diffResult, labels)...)
			if len(events) == 0 {
				continue
			}
			inputEvents := make([]agent.EnqueueEventInput, 0, len(events))
			for _, event := range events {
				inputEvents = append(inputEvents, agent.EnqueueEventInput{
					EventTime: event.EventTime,
					Type:      event.Type,
					Target:    event.Target,
					Severity:  event.Severity,
					Message:   event.Message,
					Labels:    event.Labels,
					Payload:   event.Payload,
				})
			}
			if _, _, err := runtime.EnqueueEvents(ctx, agent.EnqueueEventsInput{
				BatchID: dbQueueBatchID(site, snapshot),
				App:     site.App,
				Service: "database",
				Source:  "agent.database",
				Region:  config.Identity.Region,
				Labels:  labels,
				Events:  inputEvents,
			}); err != nil {
				return agentDatabaseRunResult{}, fmt.Errorf("site %s database %s enqueue: %w", site.Slug, name, err)
			}
			siteSummary.Queued += len(events)
			summary.Queued += len(events)
		}
		if siteSummary.Databases > 0 || siteSummary.Queued > 0 {
			summary.Sites = append(summary.Sites, siteSummary)
		}
	}
	return summary, nil
}

func shouldSkipDatabaseCollection(schedule time.Duration, statePath string) (bool, error) {
	if schedule <= 0 {
		return false, nil
	}
	info, err := os.Stat(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return time.Since(info.ModTime()) < schedule, nil
}

type agentBrowserRunResult struct {
	Sites  []agentBrowserSiteRunResult
	Pages  int
	Queued int
}

type agentBrowserSiteRunResult struct {
	Slug    string
	Pages   int
	Queued  int
	Skipped bool
}

func runConfiguredBrowserCrawls(ctx context.Context, runtime *agent.Runtime, config agent.ServerConfig, bootstrap bool) (agentBrowserRunResult, error) {
	collectorRuntime := collector.NewRuntime(collector.Config{Name: "browser"})
	summary := agentBrowserRunResult{}
	for _, site := range config.Sites {
		crawl := site.BrowserCrawl
		if !crawl.Enabled || len(crawl.URLs) == 0 {
			continue
		}
		siteSummary := agentBrowserSiteRunResult{Slug: site.Slug}
		if !bootstrap {
			schedule, err := parseOptionalDuration(crawl.Schedule)
			if err != nil {
				return agentBrowserRunResult{}, fmt.Errorf("site %s browser schedule: %w", site.Slug, err)
			}
			if schedule > 0 {
				skip, err := shouldSkipDatabaseCollection(schedule, browserStatePath(config, site))
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						return agentBrowserRunResult{}, fmt.Errorf("site %s browser schedule check: %w", site.Slug, err)
					}
				} else if skip {
					siteSummary.Skipped = true
					summary.Sites = append(summary.Sites, siteSummary)
					continue
				}
			}
		}
		timeout, err := parseOptionalDuration(crawl.Timeout)
		if err != nil {
			return agentBrowserRunResult{}, fmt.Errorf("site %s browser timeout: %w", site.Slug, err)
		}
		crawlResult, err := collectorRuntime.CrawlBrowserPages(ctx, collector.BrowserCrawlInput{
			URLs:           crawl.URLs,
			MaxPages:       crawl.MaxPages,
			Timeout:        timeout,
			SameHostOnly:   true,
			Rendered:       crawl.Rendered,
			WaitTagManager: crawl.WaitTagManager,
		})
		if err != nil {
			return agentBrowserRunResult{}, fmt.Errorf("site %s browser crawl: %w", site.Slug, err)
		}
		labels := agent.SiteEventLabels(site)
		siteSummary.Pages = len(crawlResult.Pages)
		summary.Pages += len(crawlResult.Pages)
		if !bootstrap && crawl.Schedule != "" {
			if err := touchCollectionState(browserStatePath(config, site), crawlResult.FinishedAt); err != nil {
				return agentBrowserRunResult{}, fmt.Errorf("site %s browser schedule state: %w", site.Slug, err)
			}
		}
		if bootstrap {
			summary.Sites = append(summary.Sites, siteSummary)
			continue
		}
		events := collector.BuildBrowserCrawlEvents(crawlResult, labels)
		if len(events) == 0 {
			summary.Sites = append(summary.Sites, siteSummary)
			continue
		}
		inputEvents := make([]agent.EnqueueEventInput, 0, len(events))
		for _, event := range events {
			inputEvents = append(inputEvents, agent.EnqueueEventInput{
				EventTime: event.EventTime,
				Type:      event.Type,
				Target:    event.Target,
				Severity:  event.Severity,
				Message:   event.Message,
				Labels:    event.Labels,
				Payload:   event.Payload,
			})
		}
		if _, _, err := runtime.EnqueueEvents(ctx, agent.EnqueueEventsInput{
			BatchID: browserQueueBatchID(site, crawlResult),
			App:     site.App,
			Service: site.Service,
			Source:  "agent.browser",
			Region:  config.Identity.Region,
			Labels:  labels,
			Events:  inputEvents,
		}); err != nil {
			return agentBrowserRunResult{}, fmt.Errorf("site %s browser enqueue: %w", site.Slug, err)
		}
		siteSummary.Queued = len(events)
		summary.Queued += len(events)
		summary.Sites = append(summary.Sites, siteSummary)
	}
	return summary, nil
}

func touchCollectionState(path string, timestamp time.Time) error {
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content := []byte(timestamp.UTC().Format(time.RFC3339Nano) + "\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	return os.Chtimes(path, timestamp, timestamp)
}

func parseOptionalDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}

func browserQueueBatchID(site agent.ServerSiteConfig, result collector.BrowserCrawlResult) string {
	timestamp := result.FinishedAt
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	return "browser-" + cliSafeID(site.Slug) + "-" + timestamp.UTC().Format("20060102T150405.000000000Z")
}

func dbQueueBatchID(site agent.ServerSiteConfig, result collector.DatabaseCollectResult) string {
	timestamp := result.FinishedAt
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	return "db-" + cliSafeID(site.Slug) + "-" + cliSafeID(result.Name) + "-" + timestamp.UTC().Format("20060102T150405.000000000Z")
}

func databaseStatePath(config agent.ServerConfig, site agent.ServerSiteConfig, result collector.DatabaseCollectResult) string {
	return agent.SiteStatePath(config, site, "db-"+cliSafeID(result.Name)+".json")
}

func browserStatePath(config agent.ServerConfig, site agent.ServerSiteConfig) string {
	return agent.SiteStatePath(config, site, "browser-crawl.state")
}

func databaseBatchLabels(site agent.ServerSiteConfig, result collector.DatabaseCollectResult) map[string]string {
	labels := agent.SiteEventLabels(site)
	labels["collector"] = "database"
	if result.Name != "" {
		labels["db_name"] = result.Name
	}
	if result.Engine != "" {
		labels["db_engine"] = result.Engine
	}
	if result.Profile != "" {
		labels["db_profile"] = result.Profile
	}
	return labels
}

func databaseEventName(database agent.ServerDatabaseConfig, profile string) string {
	name := strings.TrimSpace(database.Name)
	if name != "" {
		return name
	}
	if profile != "" {
		return profile
	}
	return "database"
}

func databaseProfileForSite(site agent.ServerSiteConfig, database agent.ServerDatabaseConfig) string {
	if strings.TrimSpace(database.Profile) != "" {
		switch strings.ToLower(strings.TrimSpace(database.Profile)) {
		case "wp":
			return "wordpress"
		case "ps":
			return "prestashop"
		default:
			return strings.ToLower(strings.TrimSpace(database.Profile))
		}
	}
	switch site.Kind {
	case "prestashop":
		return "prestashop"
	case "wordpress", "wordpress-multisite":
		return "wordpress"
	default:
		return site.Kind
	}
}

func databaseEngineForConfig(database agent.ServerDatabaseConfig) string {
	engine := strings.ToLower(strings.TrimSpace(database.Engine))
	if engine == "" {
		return "mysql"
	}
	return engine
}

func cliSafeID(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('_')
	}
	if builder.Len() == 0 {
		return "site"
	}
	return builder.String()
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
			&urfavecli.StringSliceFlag{Name: "log", Usage: "log file or directory to tail; can be repeated"},
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
			logOptions := agent.LogWatchOptions{
				Paths: c.StringSlice("log"),
			}
			paths, err := agent.ResolveWatchPaths(options)
			if err != nil {
				return err
			}
			logPaths := agent.ResolveLogWatchPaths(logOptions)
			if len(paths) == 0 && len(logPaths) == 0 {
				return fmt.Errorf("at least one watch or log path is required")
			}

			runtime := newAgentRuntime(c)
			ctx, stop := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			runOnce := func() error {
				queued := 0
				if len(paths) > 0 {
					result, err := runtime.ScanWatchedPaths(ctx, options)
					if err != nil {
						return err
					}
					queued += result.Queued
					if result.Baselined {
						fmt.Fprintf(c.App.Writer, "Watch baseline saved at %s (%d file(s))\n", result.StatePath, result.WatchedFiles)
					} else {
						fmt.Fprintf(c.App.Writer, "Watch scan queued %d event(s) from %d file(s)\n", result.Queued, result.WatchedFiles)
					}
				}
				if len(logPaths) > 0 {
					result, err := runtime.ScanLogPaths(ctx, logOptions)
					if err != nil {
						return err
					}
					queued += result.Queued
					if result.Baselined {
						fmt.Fprintf(c.App.Writer, "Log baseline saved at %s (%d log file(s))\n", result.StatePath, result.WatchedLogs)
					} else {
						fmt.Fprintf(c.App.Writer, "Log scan queued %d event(s) from %d log file(s)\n", result.Queued, result.WatchedLogs)
					}
				}

				secret := c.String("secret")
				if secret == "" {
					if queued > 0 {
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

func newAgentStatusRuntime(c *urfavecli.Context) *agent.Runtime {
	if config, err := agent.LoadServerConfig(c.String("config")); err == nil {
		identity := config.AgentIdentity()
		return agent.NewRuntime(agent.Config{
			ConfigPath: c.String("config"),
			QueueDir:   identity.QueueDir,
			Identity:   &identity,
		})
	}
	return newAgentRuntime(c)
}

func agentConfigFlags() []urfavecli.Flag {
	return []urfavecli.Flag{
		&urfavecli.StringFlag{Name: "config", Usage: "Agent config path", Value: ".aegrail/agent.json"},
		&urfavecli.StringFlag{Name: "queue-dir", Usage: "Agent queue directory", Value: ".aegrail/queue"},
	}
}
