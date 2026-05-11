package httpadapter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
)

const (
	headerSignature = "X-Aegrail-Signature"
	headerTimestamp = "X-Aegrail-Timestamp"
)

type HubOptions struct {
	IngestSecret        string
	IngestSignatureSkew time.Duration
	Now                 func() time.Time
}

func NewHubRouter(meta domain.AppMeta, hub *hubapp.Hub, options HubOptions) http.Handler {
	if options.IngestSignatureSkew <= 0 {
		options.IngestSignatureSkew = 5 * time.Minute
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	router := chi.NewRouter()
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"name":    meta.Name,
			"binary":  meta.Binary,
			"version": meta.Version,
			"mode":    "hub",
		})
	})
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": meta.Binary,
			"mode":    "hub",
		})
	})
	router.Post("/api/v1/ingest/events", ingestEventsHandler(hub, options))
	return router
}

type ingestEventsRequest struct {
	Organization string               `json:"org"`
	Project      string               `json:"project"`
	Environment  string               `json:"environment"`
	App          string               `json:"app"`
	Service      string               `json:"service"`
	Host         string               `json:"host"`
	AgentID      string               `json:"agent_id"`
	BatchID      string               `json:"batch_id"`
	Source       string               `json:"source"`
	Region       string               `json:"region"`
	Labels       map[string]string    `json:"labels"`
	Events       []ingestEventRequest `json:"events"`
}

type ingestEventRequest struct {
	Time     string            `json:"time"`
	Type     string            `json:"type"`
	Target   string            `json:"target"`
	Severity string            `json:"severity"`
	Message  string            `json:"message"`
	Region   string            `json:"region"`
	Labels   map[string]string `json:"labels"`
	Payload  map[string]any    `json:"payload"`
}

func ingestEventsHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "request body is too large or unreadable")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := verifyIngestSignature(r, body, options); err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		var request ingestEventsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		input, err := request.toInput(r.Header.Get(headerSignature))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		result, err := hub.IngestEvents(r.Context(), input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"batch_id":       result.Batch.ExternalID,
			"id":             result.Batch.ID,
			"events":         len(result.Events),
			"received_at":    result.Batch.ReceivedAt,
			"already_stored": result.Reused,
		})
	}
}

func (r ingestEventsRequest) toInput(signature string) (hubapp.IngestEventsInput, error) {
	events := make([]hubapp.IngestEventInput, 0, len(r.Events))
	for _, event := range r.Events {
		eventTime, err := parseEventTime(event.Time)
		if err != nil {
			return hubapp.IngestEventsInput{}, err
		}
		region := strings.TrimSpace(event.Region)
		if region == "" {
			region = r.Region
		}
		events = append(events, hubapp.IngestEventInput{
			EventTime: eventTime,
			Type:      event.Type,
			Target:    event.Target,
			Severity:  event.Severity,
			Message:   event.Message,
			Region:    region,
			Labels:    event.Labels,
			Payload:   event.Payload,
		})
	}
	return hubapp.IngestEventsInput{
		OrganizationSlug: r.Organization,
		ProjectSlug:      r.Project,
		EnvironmentSlug:  r.Environment,
		AppSlug:          r.App,
		ServiceSlug:      r.Service,
		HostSlug:         r.Host,
		AgentID:          r.AgentID,
		ExternalBatchID:  r.BatchID,
		Source:           r.Source,
		Signature:        signature,
		Region:           r.Region,
		Labels:           r.Labels,
		Events:           events,
	}, nil
}

func parseEventTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("event time %q must be RFC3339: %w", value, err)
	}
	return parsed.UTC(), nil
}

func verifyIngestSignature(r *http.Request, body []byte, options HubOptions) error {
	if strings.TrimSpace(options.IngestSecret) == "" {
		return errors.New("ingest signing secret is not configured")
	}
	timestamp := strings.TrimSpace(r.Header.Get(headerTimestamp))
	signature := strings.TrimSpace(r.Header.Get(headerSignature))
	if timestamp == "" || signature == "" {
		return errors.New("missing ingest signature headers")
	}
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return errors.New("invalid ingest timestamp")
	}
	now := options.Now().UTC()
	if parsed.Before(now.Add(-options.IngestSignatureSkew)) || parsed.After(now.Add(options.IngestSignatureSkew)) {
		return errors.New("ingest timestamp is outside the accepted window")
	}

	mac := hmac.New(sha256.New, []byte(options.IngestSecret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("\n"))
	mac.Write(body)
	expected := mac.Sum(nil)

	signature = strings.TrimPrefix(signature, "sha256=")
	actual, err := hex.DecodeString(signature)
	if err != nil {
		return errors.New("invalid ingest signature")
	}
	if !hmac.Equal(actual, expected) {
		return errors.New("invalid ingest signature")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
