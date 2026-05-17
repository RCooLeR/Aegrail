package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/adapters/ollama"
	"github.com/rcooler/aegrail/hub/internal/adapters/postgres"
	redisadapter "github.com/rcooler/aegrail/hub/internal/adapters/redis"
	"github.com/rcooler/aegrail/hub/internal/adapters/webhook"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/ports"
	"github.com/rs/zerolog"
)

type Container struct {
	meta     domain.AppMeta
	db       *pgxpool.Pool
	redis    *redisadapter.Client
	migrator ports.DatabaseMigrator
	Config   Config
	Logger   zerolog.Logger
	Hub      *hub.Hub
	Model    ports.ModelGateway
}

func NewContainer(meta domain.AppMeta) (*Container, error) {
	cfg := LoadConfig()
	logger := NewLogger(cfg.Logging)
	modelGateway, err := ollama.NewGateway(ollama.Config{
		BaseURL:             cfg.Ollama.BaseURL,
		InvestigationModel:  cfg.Ollama.InvestigationModel,
		InvestigationModels: cfg.Ollama.InvestigationModels,
		EmbeddingModel:      cfg.Ollama.EmbeddingModel,
		Offline:             cfg.Ollama.Offline,
		Timeout:             cfg.Ollama.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return &Container{
		meta:   meta,
		Config: cfg,
		Logger: logger,
		Hub: hub.New(hub.Dependencies{
			Meta:  meta,
			Model: modelGateway,
		}),
		Model: modelGateway,
	}, nil
}

func (c *Container) ConnectDatabase(ctx context.Context) error {
	pool, err := postgres.OpenPool(ctx, c.Config.Database.URL)
	if err != nil {
		return err
	}

	c.db = pool
	if c.Config.Cache.RedisURL != "" {
		redisClient, err := redisadapter.NewClient(ctx, redisadapter.Config{
			URL:       c.Config.Cache.RedisURL,
			KeyPrefix: c.Config.Cache.KeyPrefix,
		})
		if err != nil {
			pool.Close()
			c.db = nil
			return err
		}
		c.redis = redisClient
	}
	notificationSink, err := webhook.NewNotificationSink(webhook.Config{
		URL:     c.Config.Notifications.WebhookURL,
		Secret:  c.Config.Notifications.WebhookSecret,
		Timeout: c.Config.Notifications.WebhookTimeout,
	})
	if err != nil {
		pool.Close()
		if c.redis != nil {
			_ = c.redis.Close()
			c.redis = nil
		}
		c.db = nil
		return err
	}
	c.migrator = postgres.NewMigrator(c.Config.Database.URL, c.Config.Paths.MigrationsDir)
	c.Hub = hub.New(hub.Dependencies{
		Meta:             c.meta,
		Inventory:        postgres.NewInventoryRepository(pool),
		Ingest:           postgres.NewIngestRepository(pool),
		Findings:         postgres.NewHubFindingRepository(pool),
		FileIgnoreRules:  postgres.NewHubFileIgnoreRuleRepository(pool),
		BrowserAllowlist: postgres.NewBrowserScriptAllowlistRepository(pool),
		ModelReports:     postgres.NewModelAnalysisReportRepository(pool),
		Model:            c.Model,
		Jobs:             c.redis,
		Locks:            c.redis,
		RateLimiter:      c.redis,
		Users:            postgres.NewHubUserRepository(pool),
		Notifications:    notificationSink,
		UserSecretKey:    c.Config.Hub.UserSecretKey,
		BackgroundError: func(err error) {
			c.Logger.Error().Err(err).Msg("hub background task failed")
		},
	})
	return nil
}

func (c *Container) HealthCheck(ctx context.Context) map[string]string {
	checks := map[string]string{}
	if c.db == nil {
		checks["database"] = "missing"
	} else if err := c.db.Ping(ctx); err != nil {
		checks["database"] = "error"
	} else {
		checks["database"] = "ok"
	}
	if c.Config.Cache.RedisURL != "" {
		if c.redis == nil {
			checks["redis"] = "missing"
		} else if err := c.redis.Ping(ctx); err != nil {
			checks["redis"] = "error"
		} else {
			checks["redis"] = "ok"
		}
	}
	if c.Model != nil {
		modelCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		health, err := c.Model.Health(modelCtx)
		switch {
		case err != nil:
			checks["ollama"] = "error"
		case health.Offline:
			checks["ollama"] = "offline"
		case !health.Available:
			checks["ollama"] = "unavailable"
		default:
			checks["ollama"] = fmt.Sprintf("ok: %s", health.InvestigationModel)
		}
	}
	return checks
}

func (c *Container) MigrateDatabase(ctx context.Context) error {
	if c.migrator == nil {
		return errMigratorNotConfigured
	}
	return c.migrator.Up(ctx)
}

func (c *Container) DatabaseStatus(ctx context.Context) error {
	if c.migrator == nil {
		return errMigratorNotConfigured
	}
	return c.migrator.Status(ctx)
}

func (c *Container) Close() {
	if c.db != nil {
		c.db.Close()
	}
	if c.redis != nil {
		_ = c.redis.Close()
	}
}
