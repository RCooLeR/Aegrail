package bootstrap

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/adapters/filesystem"
	"github.com/rcooler/aegrail/internal/adapters/ollama"
	"github.com/rcooler/aegrail/internal/adapters/postgres"
	"github.com/rcooler/aegrail/internal/agent"
	"github.com/rcooler/aegrail/internal/collector"
	"github.com/rcooler/aegrail/internal/domain"
	"github.com/rcooler/aegrail/internal/hub"
	"github.com/rcooler/aegrail/internal/local"
	"github.com/rcooler/aegrail/internal/ports"
	"github.com/rs/zerolog"
)

type Container struct {
	meta      domain.AppMeta
	workspace ports.ProjectWorkspace
	db        *pgxpool.Pool
	Config    Config
	Logger    zerolog.Logger
	Local     *local.Application
	Hub       *hub.Hub
	Agent     *agent.Runtime
	Collector *collector.Runtime
	Model     ports.ModelGateway
}

func NewContainer(meta domain.AppMeta) (*Container, error) {
	cfg := LoadConfig()
	logger := NewLogger(cfg.Logging)
	workspace := filesystem.NewWorkspace()
	scanner := filesystem.NewEvidenceScanner()
	archive := filesystem.NewEvidenceArchive(cfg.Paths.DataDir)
	localApp := local.New(meta, local.Dependencies{
		Workspace: workspace,
		Scanner:   scanner,
		Archive:   archive,
	})
	modelGateway, err := ollama.NewGateway(ollama.Config{
		BaseURL:            cfg.Ollama.BaseURL,
		InvestigationModel: cfg.Ollama.InvestigationModel,
		EmbeddingModel:     cfg.Ollama.EmbeddingModel,
		Offline:            cfg.Ollama.Offline,
		Timeout:            cfg.Ollama.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return &Container{
		meta:      meta,
		workspace: workspace,
		Config:    cfg,
		Logger:    logger,
		Local:     localApp,
		Hub:       hub.New(hub.Dependencies{}),
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
	c.Local = local.New(c.meta, local.Dependencies{
		Workspace: c.workspace,
		Sites:     postgres.NewSiteRepository(pool),
		Migrator:  postgres.NewMigrator(c.Config.Database.URL, c.Config.Paths.MigrationsDir),
		Evidence:  postgres.NewEvidenceRepository(pool),
		Scanner:   filesystem.NewEvidenceScanner(),
		Archive:   filesystem.NewEvidenceArchive(c.Config.Paths.DataDir),
	})
	c.Hub = hub.New(hub.Dependencies{
		Inventory:        postgres.NewInventoryRepository(pool),
		Ingest:           postgres.NewIngestRepository(pool),
		Findings:         postgres.NewHubFindingRepository(pool),
		BrowserAllowlist: postgres.NewBrowserScriptAllowlistRepository(pool),
		ModelReports:     postgres.NewModelAnalysisReportRepository(pool),
		Users:            postgres.NewHubUserRepository(pool),
		UserSecretKey:    c.Config.Hub.UserSecretKey,
	})
	return nil
}

func (c *Container) Close() {
	if c.db != nil {
		c.db.Close()
	}
}
