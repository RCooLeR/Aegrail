package modeltest

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

type Gateway struct {
	HealthResult     ports.ModelGatewayHealth
	GenerateResponse ports.ModelGenerateResponse
	EmbedResponse    ports.ModelEmbedResponse
	GenerateRequests []ports.ModelGenerateRequest
	EmbedRequests    []ports.ModelEmbedRequest
}

func NewGateway() *Gateway {
	return &Gateway{
		HealthResult: ports.ModelGatewayHealth{
			Provider:           "fake",
			Available:          true,
			InvestigationModel: "fake-investigation",
			EmbeddingModel:     "fake-embedding",
			Models: []ports.ModelInfo{
				{Name: "fake-investigation", ModifiedAt: time.Unix(0, 0).UTC()},
				{Name: "fake-embedding", ModifiedAt: time.Unix(0, 0).UTC()},
			},
		},
		GenerateResponse: ports.ModelGenerateResponse{
			Model: "fake-investigation",
			Text:  "fake generated analysis",
			Done:  true,
		},
		EmbedResponse: ports.ModelEmbedResponse{
			Model:      "fake-embedding",
			Embeddings: [][]float64{{0.1, 0.2, 0.3}},
		},
	}
}

func (g *Gateway) Health(context.Context) (ports.ModelGatewayHealth, error) {
	return g.HealthResult, nil
}

func (g *Gateway) Generate(_ context.Context, request ports.ModelGenerateRequest) (ports.ModelGenerateResponse, error) {
	g.GenerateRequests = append(g.GenerateRequests, request)
	response := g.GenerateResponse
	if response.Model == "" {
		response.Model = request.Model
	}
	return response, nil
}

func (g *Gateway) Embed(_ context.Context, request ports.ModelEmbedRequest) (ports.ModelEmbedResponse, error) {
	g.EmbedRequests = append(g.EmbedRequests, request)
	response := g.EmbedResponse
	if response.Model == "" {
		response.Model = request.Model
	}
	return response, nil
}
