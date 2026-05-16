package bootstrap

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/adapters/ollama"
	"github.com/rcooler/aegrail/internal/adapters/postgres"
	"github.com/rcooler/aegrail/internal/agent"
	"github.com/rcooler/aegrail/internal/collector"
	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/hub"
	"github.com/rcooler/aegrail/internal/ports"
	"github.com/rs/zerolog"
)

type Container struct {
	meta      domain.AppMeta
	db        *pgxpool.Pool
	migrator  ports.DatabaseMigrator
	Config    Config
	Logger    zerolog.Logger
	Hub       *hub.Hub
	Agent     *agent.Runtime
	Collector *collector.Runtime
	Model     ports.ModelGateway
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
		Agent:     agent.NewRuntime(agent.Config{QueueDir: ".aegrail/queue"}),
		Collector: collector.NewRuntime(collector.Config{Name: "default"}),
		Model:     modelGateway,
	}, nil
}

func (c *Container) ConnectDatabase(ctx context.Context) error {
	pool, err := postgres.OpenPool(ctx, c.Config.Database.URL)
	if err != nil {
		return err
	}

	c.db = pool
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
		Users:            postgres.NewHubUserRepository(pool),
		UserSecretKey:    c.Config.Hub.UserSecretKey,
	})
	return nil
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
}
