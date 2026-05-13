package modeltest

import (
	"context"
	"testing"

	"github.com/rcooler/aegrail/internal/ports"
)

func TestGatewayRecordsRequestsAndReturnsDeterministicResponses(t *testing.T) {
	gateway := NewGateway()
	generate, err := gateway.Generate(context.Background(), ports.ModelGenerateRequest{
		Model:  "fake-investigation",
		Prompt: "summarize",
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	embed, err := gateway.Embed(context.Background(), ports.ModelEmbedRequest{
		Model: "fake-embedding",
		Texts: []string{"evidence"},
	})
	if err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	if generate.Text == "" || len(embed.Embeddings) != 1 {
		t.Fatalf("responses = %#v / %#v, want deterministic fake data", generate, embed)
	}
	if len(gateway.GenerateRequests) != 1 || gateway.GenerateRequests[0].Prompt != "summarize" {
		t.Fatalf("generate requests = %#v, want recorded request", gateway.GenerateRequests)
	}
	if len(gateway.EmbedRequests) != 1 || gateway.EmbedRequests[0].Texts[0] != "evidence" {
		t.Fatalf("embed requests = %#v, want recorded request", gateway.EmbedRequests)
	}
}
