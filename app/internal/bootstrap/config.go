package bootstrap

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment string
	Paths       PathsConfig
	Database    DatabaseConfig
	Ollama      OllamaConfig
	HTTP        HTTPConfig
	Hub         HubConfig
	Logging     LoggingConfig
}

type PathsConfig struct {
	DataDir       string
	MigrationsDir string
}

type DatabaseConfig struct {
	URL string
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
	IngestSecret        string
	IngestSignatureSkew time.Duration
	UserSecretKey       string
	ModelAnalysisAuto   bool
	ModelAnalysisEvery  time.Duration
	ModelAnalysisLimit  int
}

type LoggingConfig struct {
	Level  string
	Format string
}

func LoadConfig() Config {
	return Config{
		Environment: envString("AEGRAIL_ENV", "local"),
		Paths: PathsConfig{
			DataDir:       envString("AEGRAIL_DATA_DIR", "data"),
			MigrationsDir: envString("AEGRAIL_MIGRATIONS_DIR", "migrations"),
		},
		Database: DatabaseConfig{
			URL: envString("AEGRAIL_DATABASE_URL", "postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable"),
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
			IngestSecret:        envString("AEGRAIL_HUB_INGEST_SECRET", ""),
			IngestSignatureSkew: envDuration("AEGRAIL_HUB_INGEST_SIGNATURE_SKEW", 5*time.Minute),
			UserSecretKey:       envString("AEGRAIL_HUB_USER_SECRET", ""),
			ModelAnalysisAuto:   envBool("AEGRAIL_MODEL_ANALYSIS_AUTO", true),
			ModelAnalysisEvery:  envDuration("AEGRAIL_MODEL_ANALYSIS_INTERVAL", time.Minute),
			ModelAnalysisLimit:  envInt("AEGRAIL_MODEL_ANALYSIS_LIMIT", 5),
		},
		Logging: LoggingConfig{
			Level:  envString("AEGRAIL_LOG_LEVEL", "info"),
			Format: envString("AEGRAIL_LOG_FORMAT", "console"),
		},
	}
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
