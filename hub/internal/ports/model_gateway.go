package ports

import (
	"context"
	"errors"
	"time"
)

var ErrModelGatewayOffline = errors.New("model gateway is offline by configuration")

type ModelGateway interface {
	Health(ctx context.Context) (ModelGatewayHealth, error)
	Generate(ctx context.Context, request ModelGenerateRequest) (ModelGenerateResponse, error)
	Embed(ctx context.Context, request ModelEmbedRequest) (ModelEmbedResponse, error)
}

type ModelGatewayHealth struct {
	Provider           string
	BaseURL            string
	Offline            bool
	Available          bool
	InvestigationModel string
	EmbeddingModel     string
	Models             []ModelInfo
}

type ModelInfo struct {
	Name       string
	ModifiedAt time.Time
	SizeBytes  int64
	Digest     string
}

type ModelGenerateRequest struct {
	Model   string
	System  string
	Prompt  string
	Options map[string]any
}

type ModelGenerateResponse struct {
	Model           string
	Text            string
	Done            bool
	TotalDuration   time.Duration
	PromptEvalCount int
	EvalCount       int
}

type ModelEmbedRequest struct {
	Model string
	Texts []string
}

type ModelEmbedResponse struct {
	Model      string
	Embeddings [][]float64
}
