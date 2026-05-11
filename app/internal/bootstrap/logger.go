package bootstrap

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

func NewLogger(cfg LoggingConfig) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	zerolog.TimeFieldFormat = time.RFC3339

	if cfg.Format == "json" {
		return zerolog.New(os.Stderr).With().Timestamp().Logger()
	}

	writer := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}
	return zerolog.New(writer).With().Timestamp().Logger()
}
