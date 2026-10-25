package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func OpenPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := parsePoolConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func parsePoolConfig(databaseURL string) (*pgxpool.Config, error) {
	// pgxpool removes its pool_* settings from RuntimeParams while parsing. Parse
	// once with pgx as well so URL/DSN overrides remain distinguishable from
	// library defaults before applying Aegrail's production defaults.
	connectionConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	params := connectionConfig.RuntimeParams
	if params["application_name"] == "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = "aegrail-hub"
	}
	if _, configured := params["pool_max_conns"]; !configured {
		cfg.MaxConns = 20
	}
	if _, configured := params["pool_min_conns"]; !configured {
		cfg.MinConns = 0
	}
	if _, configured := params["pool_min_idle_conns"]; !configured {
		cfg.MinIdleConns = 1
	}
	if _, configured := params["pool_max_conn_lifetime"]; !configured {
		cfg.MaxConnLifetime = time.Hour
	}
	if _, configured := params["pool_max_conn_lifetime_jitter"]; !configured {
		cfg.MaxConnLifetimeJitter = 5 * time.Minute
	}
	if _, configured := params["pool_max_conn_idle_time"]; !configured {
		cfg.MaxConnIdleTime = 10 * time.Minute
	}
	if _, configured := params["pool_health_check_period"]; !configured {
		cfg.HealthCheckPeriod = time.Minute
	}
	cfg.PingTimeout = 5 * time.Second
	return cfg, nil
}
