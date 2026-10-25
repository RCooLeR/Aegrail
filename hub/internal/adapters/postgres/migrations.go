package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/pressly/goose/v3"
	gooselock "github.com/pressly/goose/v3/lock"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Migrator struct {
	databaseURL   string
	migrationsDir string
}

func NewMigrator(databaseURL string, migrationsDir string) *Migrator {
	return &Migrator{
		databaseURL:   databaseURL,
		migrationsDir: migrationsDir,
	}
}

func (m *Migrator) Up(ctx context.Context) error {
	db, err := m.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	locker, err := gooselock.NewPostgresTableLocker()
	if err != nil {
		return fmt.Errorf("configure database migration lock: %w", err)
	}
	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		os.DirFS(m.migrationsDir),
		goose.WithLocker(locker),
	)
	if err != nil {
		return fmt.Errorf("configure database migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}
	return nil
}

func (m *Migrator) Status(ctx context.Context) error {
	db, err := m.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	return goose.StatusContext(ctx, db, m.migrationsDir)
}

func (m *Migrator) EnsureCurrent(ctx context.Context) error {
	db, err := m.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return err
	}
	migrations, err := goose.CollectMigrations(m.migrationsDir, 0, goose.MaxVersion)
	if err != nil {
		return err
	}
	latest, err := migrations.Last()
	if err != nil {
		return err
	}
	switch {
	case current < latest.Version:
		return fmt.Errorf("database migrations are pending: database version %d, latest migration %d; run hub db migrate before starting hub serve", current, latest.Version)
	case current > latest.Version:
		return fmt.Errorf("database schema version %d is newer than this hub binary latest migration %d", current, latest.Version)
	default:
		return nil
	}
}

func (m *Migrator) open(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("pgx", m.databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
