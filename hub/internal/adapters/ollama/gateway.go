package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

var ErrOffline = ports.ErrModelGatewayOffline

type Config struct {
	BaseURL             string
	InvestigationModel  string
	InvestigationModels []string
	EmbeddingModel      string
	Offline             bool
	Timeout             time.Duration
	HTTPClient          *http.Client
}

type Gateway struct {
	baseURL             string
	investigationModel  string
	investigationModels []string
	embeddingModel      string
	offline             bool
	timeout             time.Duration
	client              *http.Client
}

func NewGateway(config Config) (*Gateway, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("ollama base URL %q is invalid: %w", baseURL, err)
	}
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Gateway{
		baseURL:             baseURL,
		investigationModel:  strings.TrimSpace(config.InvestigationModel),
		investigationModels: normalizeModelCandidates(config.InvestigationModel, config.InvestigationModels),
		embeddingModel:      strings.TrimSpace(config.EmbeddingModel),
		offline:             config.Offline,
		timeout:             timeout,
		client:              client,
	}, nil
}

func (g *Gateway) Health(ctx context.Context) (ports.ModelGatewayHealth, error) {
	health := ports.ModelGatewayHealth{
		Provider:           "ollama",
		BaseURL:            g.baseURL,
		Offline:            g.offline,
		Available:          false,
		InvestigationModel: g.investigationModel,
		EmbeddingModel:     g.embeddingModel,
	}
	if g.offline {
		health.InvestigationModel = firstNonEmpty(g.investigationModel, firstString(g.investigationModels))
		return health, nil
	}

	var response tagsResponse
	if err := g.doJSON(ctx, http.MethodGet, "/api/tags", nil, &response); err != nil {
		return health, err
	}
	for _, model := range response.Models {
		health.Models = append(health.Models, ports.ModelInfo{
			Name:       firstNonEmpty(model.Name, model.Model),
			ModifiedAt: model.ModifiedAt,
			SizeBytes:  model.Size,
			Digest:     model.Digest,
		})
	}
	health.InvestigationModel = g.selectInvestigationModel(health.Models)
	health.Available = true
	return health, nil
}

func (g *Gateway) Generate(ctx context.Context, request ports.ModelGenerateRequest) (ports.ModelGenerateResponse, error) {
	if g.offline {
		return ports.ModelGenerateResponse{}, ErrOffline
	}
	candidates, explicitModel, err := g.generateCandidates(ctx, request.Model)
	if err != nil {
		return ports.ModelGenerateResponse{}, err
	}
	if len(candidates) == 0 {
		return ports.ModelGenerateResponse{}, errors.New("investigation model is not configured")
	}
	if strings.TrimSpace(request.Prompt) == "" {
		return ports.ModelGenerateResponse{}, errors.New("prompt is required")
	}

	var attempts []string
	for _, model := range candidates {
		response, err := g.generateWithModel(ctx, model, request)
		if err != nil {
			if explicitModel {
				return ports.ModelGenerateResponse{}, err
			}
			attempts = append(attempts, fmt.Sprintf("%s: %v", model, err))
			continue
		}
		if strings.TrimSpace(response.Text) == "" {
			err := fmt.Errorf("ollama returned empty response from %s", model)
			if explicitModel {
				return ports.ModelGenerateResponse{}, err
			}
			attempts = append(attempts, err.Error())
			continue
		}
		return response, nil
	}

	return ports.ModelGenerateResponse{}, fmt.Errorf("all investigation models failed: %s", strings.Join(attempts, "; "))
}

func (g *Gateway) generateWithModel(ctx context.Context, model string, request ports.ModelGenerateRequest) (ports.ModelGenerateResponse, error) {
	var response generateResponse
	body := generateRequest{
		Model:   model,
		System:  request.System,
		Prompt:  request.Prompt,
		Stream:  false,
		Options: request.Options,
	}
	if err := g.doJSON(ctx, http.MethodPost, "/api/generate", body, &response); err != nil {
		return ports.ModelGenerateResponse{}, err
	}
	return ports.ModelGenerateResponse{
		Model:           firstNonEmpty(response.Model, model),
		Text:            response.Response,
		Done:            response.Done,
		TotalDuration:   time.Duration(response.TotalDuration),
		PromptEvalCount: response.PromptEvalCount,
		EvalCount:       response.EvalCount,
	}, nil
}

func (g *Gateway) generateCandidates(ctx context.Context, requestedModel string) ([]string, bool, error) {
	if model := strings.TrimSpace(requestedModel); model != "" {
		return []string{model}, true, nil
	}
	if strings.TrimSpace(g.investigationModel) != "" {
		return []string{g.investigationModel}, true, nil
	}

	health, err := g.Health(ctx)
	if err != nil {
		if len(g.investigationModels) == 0 {
			return nil, false, err
		}
		return append([]string(nil), g.investigationModels...), false, nil
	}
	if len(health.Models) == 0 {
		return append([]string(nil), g.investigationModels...), false, nil
	}

	installedNames := map[string]struct{}{}
	for _, model := range health.Models {
		name := strings.ToLower(strings.TrimSpace(model.Name))
		if name != "" {
			installedNames[name] = struct{}{}
		}
	}
	candidates := make([]string, 0, len(g.investigationModels))
	for _, candidate := range g.investigationModels {
		if _, ok := installedNames[strings.ToLower(candidate)]; ok {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return append([]string(nil), g.investigationModels...), false, nil
	}
	return candidates, false, nil
}

func (g *Gateway) selectInvestigationModel(installed []ports.ModelInfo) string {
	if strings.TrimSpace(g.investigationModel) != "" {
		return g.investigationModel
	}
	installedNames := map[string]struct{}{}
	for _, model := range installed {
		name := strings.ToLower(strings.TrimSpace(model.Name))
		if name != "" {
			installedNames[name] = struct{}{}
		}
	}
	for _, candidate := range g.investigationModels {
		if _, ok := installedNames[strings.ToLower(candidate)]; ok {
			return candidate
		}
	}
	return firstString(g.investigationModels)
}

func (g *Gateway) Embed(ctx context.Context, request ports.ModelEmbedRequest) (ports.ModelEmbedResponse, error) {
	if g.offline {
		return ports.ModelEmbedResponse{}, ErrOffline
	}
	model := strings.TrimSpace(request.Model)
	if model == "" {
		model = g.embeddingModel
	}
	if model == "" {
		return ports.ModelEmbedResponse{}, errors.New("embedding model is not configured")
	}
	texts := nonEmptyTexts(request.Texts)
	if len(texts) == 0 {
		return ports.ModelEmbedResponse{}, errors.New("at least one embedding input is required")
	}

	response, err := g.embed(ctx, model, texts)
	if err != nil && len(texts) == 1 && isHTTPStatus(err, http.StatusNotFound) {
		response, err = g.legacyEmbedding(ctx, model, texts[0])
	}
	if err != nil {
		return ports.ModelEmbedResponse{}, err
	}
	return response, nil
}

func (g *Gateway) embed(ctx context.Context, model string, texts []string) (ports.ModelEmbedResponse, error) {
	var response embedResponse
	if err := g.doJSON(ctx, http.MethodPost, "/api/embed", embedRequest{
		Model: model,
		Input: texts,
	}, &response); err != nil {
		return ports.ModelEmbedResponse{}, err
	}
	return ports.ModelEmbedResponse{
		Model:      firstNonEmpty(response.Model, model),
		Embeddings: response.Embeddings,
	}, nil
}

func (g *Gateway) legacyEmbedding(ctx context.Context, model string, text string) (ports.ModelEmbedResponse, error) {
	var response legacyEmbeddingResponse
	if err := g.doJSON(ctx, http.MethodPost, "/api/embeddings", legacyEmbeddingRequest{
		Model:  model,
		Prompt: text,
	}, &response); err != nil {
		return ports.ModelEmbedResponse{}, err
	}
	return ports.ModelEmbedResponse{
		Model:      model,
		Embeddings: [][]float64{response.Embedding},
	}, nil
}

func (g *Gateway) doJSON(ctx context.Context, method string, path string, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, g.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := g.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return httpStatusError{
			StatusCode: response.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(out)
}

type httpStatusError struct {
	StatusCode int
	Body       string
}

func (e httpStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("ollama returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("ollama returned HTTP %d: %s", e.StatusCode, e.Body)
}

func isHTTPStatus(err error, statusCode int) bool {
	var statusErr httpStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

type tagsResponse struct {
	Models []tagModel `json:"models"`
}

type tagModel struct {
	Name       string    `json:"name"`
	Model      string    `json:"model"`
	ModifiedAt time.Time `json:"modified_at"`
	Size       int64     `json:"size"`
	Digest     string    `json:"digest"`
}

type generateRequest struct {
	Model   string         `json:"model"`
	System  string         `json:"system,omitempty"`
	Prompt  string         `json:"prompt"`
	Stream  bool           `json:"stream"`
	Options map[string]any `json:"options,omitempty"`
}

type generateResponse struct {
	Model           string `json:"model"`
	Response        string `json:"response"`
	Done            bool   `json:"done"`
	TotalDuration   int64  `json:"total_duration"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
}

type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embedResponse struct {
	Model      string      `json:"model"`
	Embeddings [][]float64 `json:"embeddings"`
}

type legacyEmbeddingRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type legacyEmbeddingResponse struct {
	Embedding []float64 `json:"embedding"`
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func normalizeModelCandidates(primary string, candidates []string) []string {
	values := make([]string, 0, len(candidates)+1)
	seen := map[string]struct{}{}
	for _, value := range append([]string{primary}, candidates...) {
		model := strings.TrimSpace(value)
		if model == "" {
			continue
		}
		key := strings.ToLower(model)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, model)
	}
	return values
}

func nonEmptyTexts(values []string) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			items = append(items, text)
		}
	}
	return items
}
