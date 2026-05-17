package ollama

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestGatewayHealthListsModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("path = %s, want /api/tags", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{
					"name":        "qwen3:30b",
					"modified_at": "2026-05-12T12:00:00Z",
					"size":        42,
					"digest":      "abc123",
				},
			},
		})
	}))
	defer server.Close()

	gateway := newTestGateway(t, server.URL)
	health, err := gateway.Health(context.Background())
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if !health.Available || health.Provider != "ollama" || health.Models[0].Name != "qwen3:30b" {
		t.Fatalf("health = %#v, want available ollama model", health)
	}
}

func TestGatewayHealthSelectsFirstInstalledPreferredModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("path = %s, want /api/tags", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "mistral-small3.2:latest"},
				{"name": "qwen3:8b"},
			},
		})
	}))
	defer server.Close()

	gateway, err := NewGateway(Config{
		BaseURL: server.URL,
		InvestigationModels: []string{
			"qwen2.5-coder:14b",
			"mistral-small3.2:latest",
			"qwen3:14b",
		},
		EmbeddingModel: "qwen3-embedding",
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("NewGateway returned error: %v", err)
	}
	health, err := gateway.Health(context.Background())
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if health.InvestigationModel != "mistral-small3.2:latest" {
		t.Fatalf("investigation model = %q, want first installed ranked model", health.InvestigationModel)
	}
}

func TestGatewayGenerateUsesConfiguredDefaultModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("path = %s, want /api/generate", r.URL.Path)
		}
		var request generateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		if request.Model != "qwen3:30b" || request.Prompt != "say ok" || request.Stream {
			t.Fatalf("request = %#v, want default model and non-streaming prompt", request)
		}
		_ = json.NewEncoder(w).Encode(generateResponse{
			Model:           request.Model,
			Response:        "ok",
			Done:            true,
			TotalDuration:   int64(25 * time.Millisecond),
			PromptEvalCount: 3,
			EvalCount:       1,
		})
	}))
	defer server.Close()

	gateway := newTestGateway(t, server.URL)
	response, err := gateway.Generate(context.Background(), ports.ModelGenerateRequest{Prompt: "say ok"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if response.Model != "qwen3:30b" || response.Text != "ok" || response.TotalDuration != 25*time.Millisecond {
		t.Fatalf("response = %#v, want normalized generate response", response)
	}
}

func TestGatewayGenerateFallsBackAcrossRankedInstalledModels(t *testing.T) {
	var generatedModels []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"name": "mistral-small3.2:latest"},
					{"name": "qwen3:14b"},
				},
			})
		case "/api/generate":
			var request generateRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("Decode returned error: %v", err)
			}
			generatedModels = append(generatedModels, request.Model)
			if request.Model == "mistral-small3.2:latest" {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "cuda fault"})
				return
			}
			_ = json.NewEncoder(w).Encode(generateResponse{
				Model:    request.Model,
				Response: "ok",
				Done:     true,
			})
		default:
			t.Fatalf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()

	gateway, err := NewGateway(Config{
		BaseURL: server.URL,
		InvestigationModels: []string{
			"qwen2.5-coder:14b",
			"mistral-small3.2:latest",
			"deepseek-coder-v2:16b",
			"qwen3:14b",
			"starcoder2:15b",
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewGateway returned error: %v", err)
	}
	response, err := gateway.Generate(context.Background(), ports.ModelGenerateRequest{Prompt: "say ok"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if response.Model != "qwen3:14b" || response.Text != "ok" {
		t.Fatalf("response = %#v, want qwen3 fallback response", response)
	}
	if got, want := strings.Join(generatedModels, ","), "mistral-small3.2:latest,qwen3:14b"; got != want {
		t.Fatalf("generated models = %s, want %s", got, want)
	}
}

func TestGatewayEmbedUsesConfiguredEmbeddingModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embed" {
			t.Fatalf("path = %s, want /api/embed", r.URL.Path)
		}
		var request embedRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		if request.Model != "qwen3-embedding" || len(request.Input) != 1 || request.Input[0] != "hello" {
			t.Fatalf("request = %#v, want embedding model and input", request)
		}
		_ = json.NewEncoder(w).Encode(embedResponse{
			Model:      request.Model,
			Embeddings: [][]float64{{0.1, 0.2, 0.3}},
		})
	}))
	defer server.Close()

	gateway := newTestGateway(t, server.URL)
	response, err := gateway.Embed(context.Background(), ports.ModelEmbedRequest{Texts: []string{"hello"}})
	if err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	if response.Model != "qwen3-embedding" || len(response.Embeddings) != 1 || len(response.Embeddings[0]) != 3 {
		t.Fatalf("response = %#v, want embedding vector", response)
	}
}

func TestGatewayOfflineHealthDoesNotCallNetwork(t *testing.T) {
	gateway, err := NewGateway(Config{
		BaseURL:            "http://127.0.0.1:1",
		InvestigationModel: "qwen3:30b",
		EmbeddingModel:     "qwen3-embedding",
		Offline:            true,
		Timeout:            time.Second,
	})
	if err != nil {
		t.Fatalf("NewGateway returned error: %v", err)
	}
	health, err := gateway.Health(context.Background())
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if !health.Offline || health.Available {
		t.Fatalf("health = %#v, want offline and unavailable", health)
	}
	_, err = gateway.Generate(context.Background(), ports.ModelGenerateRequest{Prompt: "test"})
	if err != ErrOffline {
		t.Fatalf("Generate error = %v, want ErrOffline", err)
	}
}

func newTestGateway(t *testing.T, baseURL string) *Gateway {
	t.Helper()
	gateway, err := NewGateway(Config{
		BaseURL:            baseURL,
		InvestigationModel: "qwen3:30b",
		EmbeddingModel:     "qwen3-embedding",
		Timeout:            time.Second,
	})
	if err != nil {
		t.Fatalf("NewGateway returned error: %v", err)
	}
	return gateway
}
