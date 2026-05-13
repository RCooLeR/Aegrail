package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyzeModelStatusListsConfiguredOllamaModels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("path = %s, want /api/tags", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{
					"name":        "qwen3:30b",
					"modified_at": "2026-05-12T12:00:00Z",
					"size":        123,
					"digest":      "abc123456789",
				},
			},
		})
	}))
	defer server.Close()
	setModelEnv(t, server.URL)

	stdout := runCLICapture(t, "aegrail", "analyze", "model", "status")
	if !strings.Contains(stdout, "Provider: ollama") ||
		!strings.Contains(stdout, "Available: true") ||
		!strings.Contains(stdout, "qwen3:30b") {
		t.Fatalf("stdout = %q, want configured ollama status", stdout)
	}
}

func TestAnalyzeModelPromptUsesGateway(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("path = %s, want /api/generate", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		if request["model"] != "investigation-test" || request["prompt"] != "say ok" {
			t.Fatalf("request = %#v, want configured model and prompt", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":    request["model"],
			"response": "ok",
			"done":     true,
		})
	}))
	defer server.Close()
	setModelEnv(t, server.URL)

	stdout := runCLICapture(t, "aegrail", "analyze", "model", "prompt", "--prompt", "say ok")
	if strings.TrimSpace(stdout) != "ok" {
		t.Fatalf("stdout = %q, want model response", stdout)
	}
}

func TestAnalyzeModelEmbedUsesGateway(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embed" {
			t.Fatalf("path = %s, want /api/embed", r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		if request["model"] != "embedding-test" {
			t.Fatalf("request = %#v, want configured embedding model", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":      request["model"],
			"embeddings": [][]float64{{0.1, 0.2}},
		})
	}))
	defer server.Close()
	setModelEnv(t, server.URL)

	stdout := runCLICapture(t, "aegrail", "analyze", "model", "embed", "--text", "hello")
	if !strings.Contains(stdout, "Model embedding-test produced 1 embedding vector(s), dimension 2.") {
		t.Fatalf("stdout = %q, want embedding summary", stdout)
	}
}

func setModelEnv(t *testing.T, baseURL string) {
	t.Helper()
	t.Setenv("AEGRAIL_OLLAMA_BASE_URL", baseURL)
	t.Setenv("AEGRAIL_OLLAMA_INVESTIGATION_MODEL", "investigation-test")
	t.Setenv("AEGRAIL_OLLAMA_EMBEDDING_MODEL", "embedding-test")
	t.Setenv("AEGRAIL_OLLAMA_OFFLINE", "false")
	t.Setenv("AEGRAIL_OLLAMA_TIMEOUT", "5s")
}
