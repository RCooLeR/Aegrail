package bootstrap

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment   string
	Paths         PathsConfig
	Database      DatabaseConfig
	Cache         CacheConfig
	Notifications NotificationsConfig
	Ollama        OllamaConfig
	HTTP          HTTPConfig
	Hub           HubConfig
	Logging       LoggingConfig
}

type PathsConfig struct {
	DataDir       string
	MigrationsDir string
}

type DatabaseConfig struct {
	URL string
}

type CacheConfig struct {
	RedisURL  string
	KeyPrefix string
}

type NotificationsConfig struct {
	WebhookURL     string
	WebhookSecret  string
	WebhookTimeout time.Duration
}

type OllamaConfig struct {
	BaseURL             string
	InvestigationModel  string
	InvestigationModels []string
	EmbeddingModel      string
	Offline             bool
	Timeout             time.Duration
}

type HTTPConfig struct {
	Addr string
}

type HubConfig struct {
	WirePrivateKey     string
	WireTimestampSkew  time.Duration
	UserSecretKey      string
	TrustedProxyCIDRs  []*net.IPNet
	TrustedProxyErrors []string
	ModelAnalysisAuto  bool
	ModelAnalysisEvery time.Duration
	ModelAnalysisLimit int
	CorrelationWorkers int
}

type LoggingConfig struct {
	Level  string
	Format string
}

func LoadConfig() Config {
	trustedProxies := parseCIDRList(envString("AEGRAIL_TRUSTED_PROXY_CIDRS", ""))
	return Config{
		Environment: envString("AEGRAIL_ENV", "local"),
		Paths: PathsConfig{
			DataDir:       envString("AEGRAIL_DATA_DIR", "data"),
			MigrationsDir: envString("AEGRAIL_MIGRATIONS_DIR", "migrations"),
		},
		Database: DatabaseConfig{
			URL: envString("AEGRAIL_DATABASE_URL", ""),
		},
		Cache: CacheConfig{
			RedisURL:  envString("AEGRAIL_REDIS_URL", ""),
			KeyPrefix: envString("AEGRAIL_REDIS_KEY_PREFIX", "aegrail"),
		},
		Notifications: NotificationsConfig{
			WebhookURL:     envString("AEGRAIL_NOTIFICATION_WEBHOOK_URL", ""),
			WebhookSecret:  envString("AEGRAIL_NOTIFICATION_WEBHOOK_SECRET", ""),
			WebhookTimeout: envDuration("AEGRAIL_NOTIFICATION_WEBHOOK_TIMEOUT", 5*time.Second),
		},
		Ollama: OllamaConfig{
			BaseURL:             envString("AEGRAIL_OLLAMA_BASE_URL", "http://localhost:11434"),
			InvestigationModel:  envString("AEGRAIL_OLLAMA_INVESTIGATION_MODEL", ""),
			InvestigationModels: envStringList("AEGRAIL_OLLAMA_INVESTIGATION_MODELS", defaultInvestigationModels()),
			EmbeddingModel:      envString("AEGRAIL_OLLAMA_EMBEDDING_MODEL", "qwen3-embedding:0.6b"),
			Offline:             envBool("AEGRAIL_OLLAMA_OFFLINE", false),
			Timeout:             envDuration("AEGRAIL_OLLAMA_TIMEOUT", 5*time.Minute),
		},
		HTTP: HTTPConfig{
			Addr: envString("AEGRAIL_HTTP_ADDR", "127.0.0.1:8787"),
		},
		Hub: HubConfig{
			WirePrivateKey:     envString("AEGRAIL_HUB_WIRE_PRIVATE_KEY", ""),
			WireTimestampSkew:  envDuration("AEGRAIL_HUB_WIRE_TIMESTAMP_SKEW", 5*time.Minute),
			UserSecretKey:      envString("AEGRAIL_HUB_USER_SECRET", ""),
			TrustedProxyCIDRs:  trustedProxies.Networks,
			TrustedProxyErrors: trustedProxies.Errors,
			ModelAnalysisAuto:  envBool("AEGRAIL_MODEL_ANALYSIS_AUTO", true),
			ModelAnalysisEvery: envDuration("AEGRAIL_MODEL_ANALYSIS_INTERVAL", time.Minute),
			ModelAnalysisLimit: envInt("AEGRAIL_MODEL_ANALYSIS_LIMIT", 5),
			CorrelationWorkers: envInt("AEGRAIL_CORRELATION_WORKERS", 2),
		},
		Logging: LoggingConfig{
			Level:  envString("AEGRAIL_LOG_LEVEL", "info"),
			Format: envString("AEGRAIL_LOG_FORMAT", "console"),
		},
	}
}

func (c Config) ValidateServe() error {
	if strings.TrimSpace(c.Database.URL) == "" {
		return errors.New("AEGRAIL_DATABASE_URL is required")
	}
	if strings.TrimSpace(c.Hub.WirePrivateKey) == "" {
		return errors.New("AEGRAIL_HUB_WIRE_PRIVATE_KEY is required")
	}
	if strings.TrimSpace(c.Hub.UserSecretKey) == "" {
		return errors.New("AEGRAIL_HUB_USER_SECRET is required")
	}
	return nil
}

type parsedCIDRList struct {
	Networks []*net.IPNet
	Errors   []string
}

func parseCIDRList(value string) parsedCIDRList {
	var parsed parsedCIDRList
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			parsed.Errors = append(parsed.Errors, fmt.Sprintf("%s: %v", item, err))
			continue
		}
		parsed.Networks = append(parsed.Networks, network)
	}
	return parsed
}

func defaultInvestigationModels() []string {
	return []string{
		"qwen2.5-coder:14b",
		"mistral-small3.2:latest",
		"deepseek-coder-v2:16b",
		"qwen3:14b",
		"starcoder2:15b",
	}
}

func envString(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envStringList(key string, fallback []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		return fallback
	}
	return items
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
