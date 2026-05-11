package postgres

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"

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

	return goose.UpContext(ctx, db, m.migrationsDir)
}

func (m *Migrator) Status(ctx context.Context) error {
	db, err := m.open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	return goose.StatusContext(ctx, db, m.migrationsDir)
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
