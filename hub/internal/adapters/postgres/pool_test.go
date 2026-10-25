package postgres

import (
	"testing"
	"time"
)

func TestParsePoolConfigAppliesHubDefaults(t *testing.T) {
	cfg, err := parsePoolConfig("postgres://aegrail:password@localhost:5432/aegrail?sslmode=disable")
	if err != nil {
		t.Fatalf("parsePoolConfig returned error: %v", err)
	}

	if got := cfg.ConnConfig.RuntimeParams["application_name"]; got != "aegrail-hub" {
		t.Fatalf("application_name = %q, want aegrail-hub", got)
	}
	if cfg.MaxConns != 20 || cfg.MinConns != 0 || cfg.MinIdleConns != 1 {
		t.Fatalf("pool sizes = max %d, min %d, min idle %d; want 20, 0, 1", cfg.MaxConns, cfg.MinConns, cfg.MinIdleConns)
	}
	if cfg.MaxConnLifetime != time.Hour || cfg.MaxConnLifetimeJitter != 5*time.Minute {
		t.Fatalf("connection lifetime = %s + %s jitter, want 1h + 5m", cfg.MaxConnLifetime, cfg.MaxConnLifetimeJitter)
	}
	if cfg.MaxConnIdleTime != 10*time.Minute || cfg.HealthCheckPeriod != time.Minute || cfg.PingTimeout != 5*time.Second {
		t.Fatalf("pool health timings = idle %s, check %s, ping %s", cfg.MaxConnIdleTime, cfg.HealthCheckPeriod, cfg.PingTimeout)
	}
}

func TestParsePoolConfigPreservesDSNOverrides(t *testing.T) {
	cfg, err := parsePoolConfig("postgres://aegrail:password@localhost:5432/aegrail?" +
		"application_name=custom-worker&" +
		"pool_max_conns=7&" +
		"pool_min_conns=2&" +
		"pool_min_idle_conns=3&" +
		"pool_max_conn_lifetime=2h&" +
		"pool_max_conn_lifetime_jitter=17m&" +
		"pool_max_conn_idle_time=15m&" +
		"pool_health_check_period=30s")
	if err != nil {
		t.Fatalf("parsePoolConfig returned error: %v", err)
	}

	if got := cfg.ConnConfig.RuntimeParams["application_name"]; got != "custom-worker" {
		t.Fatalf("application_name = %q, want custom-worker", got)
	}
	if cfg.MaxConns != 7 || cfg.MinConns != 2 || cfg.MinIdleConns != 3 {
		t.Fatalf("pool sizes = max %d, min %d, min idle %d; want 7, 2, 3", cfg.MaxConns, cfg.MinConns, cfg.MinIdleConns)
	}
	if cfg.MaxConnLifetime != 2*time.Hour || cfg.MaxConnLifetimeJitter != 17*time.Minute {
		t.Fatalf("connection lifetime = %s + %s jitter, want 2h + 17m", cfg.MaxConnLifetime, cfg.MaxConnLifetimeJitter)
	}
	if cfg.MaxConnIdleTime != 15*time.Minute || cfg.HealthCheckPeriod != 30*time.Second {
		t.Fatalf("pool health timings = idle %s, check %s", cfg.MaxConnIdleTime, cfg.HealthCheckPeriod)
	}
}
