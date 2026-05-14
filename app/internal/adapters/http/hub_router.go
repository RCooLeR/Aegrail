package httpadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
)

const (
	headerSignature      = "X-Aegrail-Signature"
	headerTimestamp      = "X-Aegrail-Timestamp"
	hubSessionCookieName = "aegrail_session"
)

type hubUserContextKey struct{}

type HubOptions struct {
	IngestSecret        string
	IngestSignatureSkew time.Duration
	DashboardDir        string
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
	router.Get("/api/v1/auth/me", getHubAuthMeHandler(hub, options))
	router.Post("/api/v1/auth/login", loginHubUserHandler(hub, options))
	router.Post("/api/v1/auth/logout", logoutHubUserHandler(hub, options))
	router.Get("/api/v1/rules", withHubAuth(hub, options, "viewer", listRulesHandler(hub)))
	router.Get("/api/v1/findings", withHubAuth(hub, options, "viewer", listFindingsHandler(hub)))
	router.Patch("/api/v1/findings/{id}/status", withHubAuth(hub, options, "operator", updateFindingStatusHandler(hub)))
	router.Post("/api/v1/findings/{id}/browser-script-allowlist", withHubAuth(hub, options, "operator", allowBrowserScriptFromFindingHandler(hub)))
	router.Get("/api/v1/reports/model-analysis", withHubAuth(hub, options, "viewer", listModelAnalysisReportsHandler(hub)))
	router.Get("/api/v1/reports/model-analysis/{id}", withHubAuth(hub, options, "viewer", getModelAnalysisReportHandler(hub)))
	router.Get("/api/v1/timeline", withHubAuth(hub, options, "viewer", listTimelineHandler(hub)))
	router.Get("/api/v1/coverage", withHubAuth(hub, options, "viewer", listCoverageHandler(hub)))
	router.Get("/api/v1/deployments", withHubAuth(hub, options, "viewer", listDeploymentsHandler(hub)))
	router.Get("/api/v1/browser/scripts", withHubAuth(hub, options, "viewer", listBrowserScriptsHandler(hub)))
	router.Get("/api/v1/browser/script-allowlist", withHubAuth(hub, options, "viewer", listBrowserScriptAllowlistHandler(hub)))
	router.Post("/api/v1/browser/script-allowlist", withHubAuth(hub, options, "operator", allowBrowserScriptHandler(hub)))
	router.Patch("/api/v1/browser/script-allowlist/{id}/status", withHubAuth(hub, options, "operator", updateBrowserScriptAllowlistStatusHandler(hub)))
	router.Get("/api/v1/access/users", withHubAuth(hub, options, "admin", listHubUsersHandler(hub)))
	router.Post("/api/v1/access/users", createHubUserHandler(hub, options))
	router.Patch("/api/v1/access/users/{id}", withHubAuth(hub, options, "admin", updateHubUserHandler(hub)))
	router.Post("/api/v1/access/users/{id}/totp", withHubAuth(hub, options, "admin", generateHubUserTOTPHandler(hub)))
	router.Get("/api/v1/inventory/scopes", withHubAuth(hub, options, "viewer", listInventoryScopesHandler(hub)))
	router.Get("/api/v1/inventory/apps", withHubAuth(hub, options, "viewer", listInventoryAppsHandler(hub)))
	router.Get("/api/v1/inventory/services", withHubAuth(hub, options, "viewer", listInventoryServicesHandler(hub)))
	router.Get("/api/v1/inventory/hosts", withHubAuth(hub, options, "viewer", listInventoryHostsHandler(hub)))
	router.Get("/api/v1/inventory/agents", withHubAuth(hub, options, "viewer", listInventoryAgentsHandler(hub)))
	router.Get("/api/v1/inventory/topology", withHubAuth(hub, options, "viewer", listInventoryTopologyHandler(hub)))
	mountDashboard(router, options.DashboardDir)
	return router
}

type hubFindingResponse struct {
	ID              string         `json:"id"`
	RuleID          string         `json:"rule_id"`
	RuleVersion     string         `json:"rule_version"`
	DedupeKey       string         `json:"dedupe_key"`
	Severity        string         `json:"severity"`
	Confidence      string         `json:"confidence"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	Description     string         `json:"description"`
	EventIDs        []string       `json:"event_ids"`
	FirstEventAt    time.Time      `json:"first_event_at"`
	LastEventAt     time.Time      `json:"last_event_at"`
	Status          string         `json:"status"`
	StatusReason    string         `json:"status_reason,omitempty"`
	StatusNote      string         `json:"status_note,omitempty"`
	StatusActor     string         `json:"status_actor,omitempty"`
	StatusUpdatedAt time.Time      `json:"status_updated_at"`
	Metadata        map[string]any `json:"metadata"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

type timelineEventResponse struct {
	ID              string            `json:"id"`
	BatchID         string            `json:"batch_id"`
	AppID           string            `json:"app_id,omitempty"`
	AppSlug         string            `json:"app,omitempty"`
	ServiceID       string            `json:"service_id,omitempty"`
	ServiceSlug     string            `json:"service,omitempty"`
	HostID          string            `json:"host_id"`
	HostSlug        string            `json:"host"`
	Hostname        string            `json:"hostname"`
	AgentID         string            `json:"agent_id"`
	AgentExternalID string            `json:"agent"`
	EventTime       time.Time         `json:"event_time"`
	ReceivedAt      time.Time         `json:"received_time"`
	EventType       string            `json:"type"`
	Target          string            `json:"target"`
	Severity        string            `json:"severity"`
	Message         string            `json:"message"`
	Region          string            `json:"region,omitempty"`
	Labels          map[string]string `json:"labels"`
	Payload         map[string]any    `json:"payload"`
	CreatedAt       time.Time         `json:"created_at"`
}

type configCoverageResponse struct {
	EventID         string            `json:"event_id"`
	AppID           string            `json:"app_id,omitempty"`
	AppSlug         string            `json:"app,omitempty"`
	HostID          string            `json:"host_id"`
	HostSlug        string            `json:"host"`
	Hostname        string            `json:"hostname"`
	AgentID         string            `json:"agent_id"`
	AgentExternalID string            `json:"agent"`
	ReportedAt      time.Time         `json:"reported_at"`
	ReceivedAt      time.Time         `json:"received_time"`
	SiteSlug        string            `json:"site"`
	SiteKind        string            `json:"site_kind"`
	CoverageLevel   string            `json:"coverage_level"`
	Labels          map[string]string `json:"labels"`
	Payload         map[string]any    `json:"payload"`
}

type organizationResponse struct {
	ID        string            `json:"id"`
	Slug      string            `json:"slug"`
	Name      string            `json:"name"`
	Projects  []projectResponse `json:"projects"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type projectResponse struct {
	ID             string                `json:"id"`
	OrganizationID string                `json:"organization_id"`
	Slug           string                `json:"slug"`
	Name           string                `json:"name"`
	Environments   []environmentResponse `json:"environments"`
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

type environmentResponse struct {
	ID        string                 `json:"id"`
	ProjectID string                 `json:"project_id"`
	Slug      string                 `json:"slug"`
	Name      string                 `json:"name"`
	Apps      []monitoredAppResponse `json:"apps"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type monitoredAppResponse struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type serviceResponse struct {
	ID        string    `json:"id"`
	AppID     string    `json:"app_id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type hostResponse struct {
	ID        string            `json:"id"`
	Slug      string            `json:"slug"`
	Hostname  string            `json:"hostname"`
	Region    string            `json:"region,omitempty"`
	Labels    map[string]string `json:"labels"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type agentResponse struct {
	ID          string     `json:"id"`
	HostID      string     `json:"host_id"`
	AgentID     string     `json:"agent_id"`
	Fingerprint string     `json:"fingerprint"`
	Version     string     `json:"version,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type deploymentResponse struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id,omitempty"`
	Version    string     `json:"version"`
	CommitSHA  string     `json:"commit_sha,omitempty"`
	Actor      string     `json:"actor,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type browserScriptObservationResponse struct {
	EventID         string            `json:"event_id"`
	AppID           string            `json:"app_id,omitempty"`
	AppSlug         string            `json:"app,omitempty"`
	HostID          string            `json:"host_id"`
	HostSlug        string            `json:"host"`
	Hostname        string            `json:"hostname"`
	AgentID         string            `json:"agent_id"`
	AgentExternalID string            `json:"agent"`
	EventTime       time.Time         `json:"event_time"`
	ReceivedAt      time.Time         `json:"received_time"`
	EventType       string            `json:"type"`
	Target          string            `json:"target"`
	Severity        string            `json:"severity"`
	PageURL         string            `json:"page_url,omitempty"`
	FinalURL        string            `json:"final_url,omitempty"`
	Mode            string            `json:"mode,omitempty"`
	SourceType      string            `json:"source_type,omitempty"`
	URL             string            `json:"url,omitempty"`
	URLRedacted     string            `json:"url_redacted,omitempty"`
	Domain          string            `json:"domain,omitempty"`
	Path            string            `json:"path,omitempty"`
	SHA256          string            `json:"sha256,omitempty"`
	InlineBytes     int               `json:"inline_bytes,omitempty"`
	TagManager      bool              `json:"tag_manager"`
	TagManagerIDs   []string          `json:"tag_manager_ids,omitempty"`
	Labels          map[string]string `json:"labels"`
	Payload         map[string]any    `json:"payload"`
}

type browserScriptAllowlistEntryResponse struct {
	ID         string    `json:"id"`
	AppID      string    `json:"app_id"`
	PageURL    string    `json:"page_url"`
	Kind       string    `json:"kind"`
	Value      string    `json:"value"`
	Reason     string    `json:"reason,omitempty"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type hubUserResponse struct {
	ID                string     `json:"id"`
	Email             string     `json:"email"`
	DisplayName       string     `json:"display_name"`
	AccessLevel       string     `json:"access_level"`
	Status            string     `json:"status"`
	TwoFactorRequired bool       `json:"two_factor_required"`
	TwoFactorEnabled  bool       `json:"two_factor_enabled"`
	TOTPEnrolledAt    *time.Time `json:"totp_enrolled_at,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type hubUserTOTPEnrollmentResponse struct {
	OTPAuthURL    string `json:"otpauth_url"`
	QRCodeDataURL string `json:"qr_code_data_url"`
	Secret        string `json:"secret"`
}

type hubAuthMeResponse struct {
	Authenticated     bool             `json:"authenticated"`
	AuthConfigured    bool             `json:"auth_configured"`
	RequiresBootstrap bool             `json:"requires_bootstrap"`
	User              *hubUserResponse `json:"user,omitempty"`
}

type modelAnalysisReportResponse struct {
	ID                             string         `json:"id"`
	AppID                          string         `json:"app_id,omitempty"`
	Schema                         string         `json:"schema"`
	Status                         string         `json:"status"`
	ModelProvider                  string         `json:"model_provider,omitempty"`
	ModelName                      string         `json:"model_name,omitempty"`
	PromptTemplateID               string         `json:"prompt_template_id"`
	PromptTemplateVersion          string         `json:"prompt_template_version"`
	PromptTemplateSHA256           string         `json:"prompt_template_sha256"`
	PromptSHA256                   string         `json:"prompt_sha256"`
	EvidenceBundleSchema           string         `json:"evidence_bundle_schema"`
	EvidenceBundleSHA256           string         `json:"evidence_bundle_sha256"`
	EvidenceBundleRedactionVersion string         `json:"evidence_bundle_redaction_version"`
	EvidenceBundleGeneratedAt      time.Time      `json:"evidence_bundle_generated_at"`
	SourceFindingIDs               []string       `json:"source_finding_ids"`
	Analysis                       string         `json:"analysis,omitempty"`
	Error                          string         `json:"error,omitempty"`
	TotalDurationMillis            int64          `json:"total_duration_millis,omitempty"`
	PromptEvalCount                int            `json:"prompt_eval_count,omitempty"`
	EvalCount                      int            `json:"eval_count,omitempty"`
	GeneratedAt                    time.Time      `json:"generated_at"`
	Metadata                       map[string]any `json:"metadata"`
	CreatedAt                      time.Time      `json:"created_at"`
}

type ruleDefinitionResponse struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	Platforms     []string `json:"platforms"`
	EvidenceTypes []string `json:"evidence_types"`
	ActionHints   []string `json:"action_hints"`
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

type updateFindingStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
	Actor  string `json:"actor"`
}

type allowBrowserScriptRequest struct {
	PageURL    string `json:"page_url"`
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

type allowBrowserScriptFromFindingRequest struct {
	PageURL    string `json:"page_url"`
	AppWide    bool   `json:"app_wide"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

type updateBrowserScriptAllowlistStatusRequest struct {
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

type createHubUserRequest struct {
	Email             string `json:"email"`
	DisplayName       string `json:"display_name"`
	AccessLevel       string `json:"access_level"`
	Password          string `json:"password"`
	Status            string `json:"status"`
	TwoFactorRequired bool   `json:"two_factor_required"`
}

type updateHubUserRequest struct {
	DisplayName       string `json:"display_name"`
	AccessLevel       string `json:"access_level"`
	Status            string `json:"status"`
	TwoFactorRequired bool   `json:"two_factor_required"`
}

type generateHubUserTOTPRequest struct {
	Issuer string `json:"issuer"`
}

type loginHubUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
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

func listRulesHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		category := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("category")))
		platform := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
		definitions := hub.ListRuleDefinitions()
		records := make([]ruleDefinitionResponse, 0, len(definitions))
		for _, definition := range definitions {
			if category != "" && string(definition.Category) != category {
				continue
			}
			if platform != "" && !containsString(definition.Platforms, platform) {
				continue
			}
			records = append(records, ruleDefinitionRecord(definition))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count": len(records),
			"rules": records,
		})
	}
}

func listFindingsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		limit, err := parseQueryLimit(r, 100)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		findings, err := hub.ListHubFindings(r.Context(), hubapp.ListHubFindingsInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			Limit:            limit,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]hubFindingResponse, 0, len(findings))
		for _, finding := range findings {
			records = append(records, hubFindingRecord(finding))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":    len(records),
			"findings": records,
		})
	}
}

func updateFindingStatusHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateFindingStatusRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		finding, err := hub.UpdateHubFindingStatus(r.Context(), hubapp.UpdateHubFindingStatusInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			FindingID:        chi.URLParam(r, "id"),
			Status:           request.Status,
			Reason:           request.Reason,
			Note:             request.Note,
			Actor:            request.Actor,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"finding": hubFindingRecord(finding),
		})
	}
}

func allowBrowserScriptFromFindingHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request allowBrowserScriptFromFindingRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		result, err := hub.AllowBrowserScriptFromFinding(r.Context(), hubapp.AllowBrowserScriptFromFindingInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			FindingID:        chi.URLParam(r, "id"),
			PageURL:          request.PageURL,
			AppWide:          request.AppWide,
			Reason:           request.Reason,
			ApprovedBy:       request.ApprovedBy,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"finding": hubFindingRecord(result.Finding),
			"entry":   browserScriptAllowlistEntryRecord(result.Entry),
		})
	}
}

func listModelAnalysisReportsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		limit, err := parseQueryLimit(r, 50)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		reports, err := hub.ListModelAnalysisReports(r.Context(), hubapp.ListModelAnalysisReportsInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			Limit:            limit,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]modelAnalysisReportResponse, 0, len(reports))
		for _, report := range reports {
			records = append(records, modelAnalysisReportRecord(report))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(records),
			"reports": records,
		})
	}
}

func getModelAnalysisReportHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		report, err := hub.GetModelAnalysisReport(r.Context(), hubapp.GetModelAnalysisReportInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			ReportID:         chi.URLParam(r, "id"),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"report": modelAnalysisReportRecord(report),
		})
	}
}

func listTimelineHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		limit, err := parseQueryLimit(r, 500)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		since, err := parseQueryTime(r.URL.Query().Get("since"), "since")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		events, err := hub.ListTimelineEvents(r.Context(), hubapp.ListTimelineEventsInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			Since:            since,
			Limit:            limit,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]timelineEventResponse, 0, len(events))
		for _, event := range events {
			records = append(records, timelineEventRecord(event))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":  len(records),
			"events": records,
		})
	}
}

func listCoverageHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		limit, err := parseQueryLimit(r, 5000)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		since, err := parseQueryTime(r.URL.Query().Get("since"), "since")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		coverage, err := hub.ListConfigCoverage(r.Context(), hubapp.ListConfigCoverageInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			Since:            since,
			Limit:            limit,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]configCoverageResponse, 0, len(coverage))
		for _, record := range coverage {
			records = append(records, configCoverageRecord(record))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":    len(records),
			"coverage": records,
		})
	}
}

func listDeploymentsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		deployments, err := hub.ListDeploymentMarkers(r.Context(), r.URL.Query().Get("org"), r.URL.Query().Get("project"), r.URL.Query().Get("environment"), r.URL.Query().Get("app"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]deploymentResponse, 0, len(deployments))
		for _, deployment := range deployments {
			records = append(records, deploymentRecord(deployment))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":       len(records),
			"deployments": records,
		})
	}
}

func listBrowserScriptsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		limit, err := parseQueryLimit(r, 1000)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		since, err := parseQueryTime(r.URL.Query().Get("since"), "since")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		observations, err := hub.ListBrowserScriptObservations(r.Context(), hubapp.ListBrowserScriptObservationsInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			PageURL:          r.URL.Query().Get("page"),
			Kind:             r.URL.Query().Get("kind"),
			Since:            since,
			Limit:            limit,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]browserScriptObservationResponse, 0, len(observations))
		for _, observation := range observations {
			records = append(records, browserScriptObservationRecord(observation))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(records),
			"scripts": records,
		})
	}
}

func listBrowserScriptAllowlistHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		entries, err := hub.ListBrowserScriptAllowlist(r.Context(), hubapp.ListBrowserScriptAllowlistInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			PageURL:          r.URL.Query().Get("page"),
			Kind:             r.URL.Query().Get("kind"),
			Status:           r.URL.Query().Get("status"),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]browserScriptAllowlistEntryResponse, 0, len(entries))
		for _, entry := range entries {
			records = append(records, browserScriptAllowlistEntryRecord(entry))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":     len(records),
			"allowlist": records,
		})
	}
}

func allowBrowserScriptHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request allowBrowserScriptRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		entry, err := hub.AllowBrowserScript(r.Context(), hubapp.AllowBrowserScriptInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			PageURL:          request.PageURL,
			Kind:             request.Kind,
			Value:            request.Value,
			Reason:           request.Reason,
			ApprovedBy:       request.ApprovedBy,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"entry": browserScriptAllowlistEntryRecord(entry),
		})
	}
}

func updateBrowserScriptAllowlistStatusHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateBrowserScriptAllowlistStatusRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		entry, err := hub.UpdateBrowserScriptAllowlistStatus(r.Context(), hubapp.UpdateBrowserScriptAllowlistStatusInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			EntryID:          chi.URLParam(r, "id"),
			Status:           request.Status,
			Reason:           request.Reason,
			ApprovedBy:       request.ApprovedBy,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"entry": browserScriptAllowlistEntryRecord(entry),
		})
	}
}

func getHubAuthMeHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		if !hub.HubUsersConfigured() {
			writeJSON(w, http.StatusOK, hubAuthMeResponse{
				Authenticated:  true,
				AuthConfigured: false,
			})
			return
		}
		count, err := hub.CountHubUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check hub users")
			return
		}
		if count == 0 {
			writeJSON(w, http.StatusOK, hubAuthMeResponse{
				Authenticated:     false,
				AuthConfigured:    true,
				RequiresBootstrap: true,
			})
			return
		}
		user, ok, err := authenticatedHubUser(r, hub, options)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not check session")
			return
		}
		if !ok {
			writeJSON(w, http.StatusOK, hubAuthMeResponse{
				Authenticated:  false,
				AuthConfigured: true,
			})
			return
		}
		record := hubUserRecord(user)
		writeJSON(w, http.StatusOK, hubAuthMeResponse{
			Authenticated:  true,
			AuthConfigured: true,
			User:           &record,
		})
	}
}

func loginHubUserHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request loginHubUserRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		now := options.Now().UTC()
		result, err := hub.LoginHubUser(r.Context(), hubapp.LoginHubUserInput{
			Email:    request.Email,
			Password: request.Password,
			TOTPCode: request.TOTPCode,
			Now:      now,
		})
		if errors.Is(err, hubapp.ErrHubMFARequired) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":        "mfa required",
				"mfa_required": true,
			})
			return
		}
		if errors.Is(err, hubapp.ErrHubInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		http.SetCookie(w, hubSessionCookie(result.Token, result.ExpiresAt, r))
		writeJSON(w, http.StatusOK, map[string]any{
			"user":       hubUserRecord(result.User),
			"expires_at": result.ExpiresAt,
		})
	}
}

func logoutHubUserHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		if cookie, err := r.Cookie(hubSessionCookieName); err == nil {
			if err := hub.LogoutHubUser(r.Context(), cookie.Value, options.Now().UTC()); err != nil {
				writeError(w, http.StatusInternalServerError, "could not revoke session")
				return
			}
		}
		http.SetCookie(w, clearHubSessionCookie(r))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func listHubUsersHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		users, err := hub.ListHubUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]hubUserResponse, 0, len(users))
		for _, user := range users {
			records = append(records, hubUserRecord(user))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count": len(records),
			"users": records,
		})
	}
}

func createHubUserHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		bootstrap := false
		if hub.HubUsersConfigured() {
			count, err := hub.CountHubUsers(r.Context())
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not check hub users")
				return
			}
			bootstrap = count == 0
			if !bootstrap {
				user, ok := requireHubUser(w, r, hub, options, "admin")
				if !ok {
					return
				}
				_ = user
			}
		}
		var request createHubUserRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if bootstrap {
			request.AccessLevel = "owner"
			request.Status = "active"
		}
		user, err := hub.CreateHubUser(r.Context(), hubapp.CreateHubUserInput{
			Email:             request.Email,
			DisplayName:       request.DisplayName,
			AccessLevel:       request.AccessLevel,
			Password:          request.Password,
			Status:            request.Status,
			TwoFactorRequired: request.TwoFactorRequired,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"user": hubUserRecord(user),
		})
	}
}

func updateHubUserHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateHubUserRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		user, err := hub.UpdateHubUser(r.Context(), hubapp.UpdateHubUserInput{
			UserID:            chi.URLParam(r, "id"),
			DisplayName:       request.DisplayName,
			AccessLevel:       request.AccessLevel,
			Status:            request.Status,
			TwoFactorRequired: request.TwoFactorRequired,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user": hubUserRecord(user),
		})
	}
}

func generateHubUserTOTPHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request generateHubUserTOTPRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
		}
		result, err := hub.GenerateHubUserTOTP(r.Context(), hubapp.GenerateHubUserTOTPInput{
			UserID: chi.URLParam(r, "id"),
			Issuer: request.Issuer,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"user": hubUserRecord(result.User),
			"enrollment": hubUserTOTPEnrollmentResponse{
				OTPAuthURL:    result.OTPAuthURL,
				QRCodeDataURL: result.QRCodeDataURL,
				Secret:        result.Secret,
			},
		})
	}
}

func listInventoryScopesHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		organizations, err := hub.ListOrganizations(r.Context())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		records := make([]organizationResponse, 0, len(organizations))
		projectCount := 0
		environmentCount := 0
		appCount := 0
		for _, organization := range organizations {
			orgRecord := organizationRecord(organization)
			projects, err := hub.ListProjects(r.Context(), organization.Slug)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			orgRecord.Projects = make([]projectResponse, 0, len(projects))
			projectCount += len(projects)
			for _, project := range projects {
				projectRecord := projectRecord(project)
				environments, err := hub.ListEnvironments(r.Context(), organization.Slug, project.Slug)
				if err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				projectRecord.Environments = make([]environmentResponse, 0, len(environments))
				environmentCount += len(environments)
				for _, environment := range environments {
					environmentRecord := environmentRecord(environment)
					apps, err := hub.ListMonitoredApps(r.Context(), organization.Slug, project.Slug, environment.Slug)
					if err != nil {
						writeError(w, http.StatusBadRequest, err.Error())
						return
					}
					environmentRecord.Apps = make([]monitoredAppResponse, 0, len(apps))
					appCount += len(apps)
					for _, app := range apps {
						environmentRecord.Apps = append(environmentRecord.Apps, monitoredAppRecord(app))
					}
					projectRecord.Environments = append(projectRecord.Environments, environmentRecord)
				}
				orgRecord.Projects = append(orgRecord.Projects, projectRecord)
			}
			records = append(records, orgRecord)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"count":         len(records),
			"projects":      projectCount,
			"environments":  environmentCount,
			"apps":          appCount,
			"organizations": records,
		})
	}
}

func listInventoryAppsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		apps, err := hub.ListMonitoredApps(r.Context(), r.URL.Query().Get("org"), r.URL.Query().Get("project"), r.URL.Query().Get("environment"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]monitoredAppResponse, 0, len(apps))
		for _, app := range apps {
			records = append(records, monitoredAppRecord(app))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count": len(records),
			"apps":  records,
		})
	}
}

func listInventoryServicesHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		services, err := hub.ListServices(r.Context(), r.URL.Query().Get("org"), r.URL.Query().Get("project"), r.URL.Query().Get("environment"), r.URL.Query().Get("app"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]serviceResponse, 0, len(services))
		for _, service := range services {
			records = append(records, serviceRecord(service))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":    len(records),
			"services": records,
		})
	}
}

func listInventoryHostsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		hosts, err := hub.ListHosts(r.Context(), r.URL.Query().Get("org"), r.URL.Query().Get("project"), r.URL.Query().Get("environment"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]hostResponse, 0, len(hosts))
		for _, host := range hosts {
			records = append(records, hostRecord(host))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count": len(records),
			"hosts": records,
		})
	}
}

func listInventoryAgentsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		agents, err := hub.ListAgents(r.Context(), r.URL.Query().Get("org"), r.URL.Query().Get("project"), r.URL.Query().Get("environment"), r.URL.Query().Get("host"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		records := make([]agentResponse, 0, len(agents))
		for _, agent := range agents {
			records = append(records, agentRecord(agent))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"count":  len(records),
			"agents": records,
		})
	}
}

func listInventoryTopologyHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		org := r.URL.Query().Get("org")
		project := r.URL.Query().Get("project")
		environment := r.URL.Query().Get("environment")

		apps, err := hub.ListMonitoredApps(r.Context(), org, project, environment)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		hosts, err := hub.ListHosts(r.Context(), org, project, environment)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		appRecords := make([]monitoredAppResponse, 0, len(apps))
		serviceRecords := []serviceResponse{}
		for _, app := range apps {
			appRecords = append(appRecords, monitoredAppRecord(app))
			services, err := hub.ListServices(r.Context(), org, project, environment, app.Slug)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			for _, service := range services {
				serviceRecords = append(serviceRecords, serviceRecord(service))
			}
		}

		hostRecords := make([]hostResponse, 0, len(hosts))
		agentRecords := []agentResponse{}
		for _, host := range hosts {
			hostRecords = append(hostRecords, hostRecord(host))
			agents, err := hub.ListAgents(r.Context(), org, project, environment, host.Slug)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			for _, agent := range agents {
				agentRecords = append(agentRecords, agentRecord(agent))
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"counts": map[string]int{
				"apps":     len(appRecords),
				"services": len(serviceRecords),
				"hosts":    len(hostRecords),
				"agents":   len(agentRecords),
			},
			"apps":     appRecords,
			"services": serviceRecords,
			"hosts":    hostRecords,
			"agents":   agentRecords,
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

func parseQueryTime(value string, name string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q must be RFC3339: %w", name, value, err)
	}
	return parsed.UTC(), nil
}

func parseQueryLimit(r *http.Request, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("limit %q must be an integer", raw)
	}
	if limit <= 0 {
		return fallback, nil
	}
	return limit, nil
}

func hubFindingRecord(finding domain.HubFinding) hubFindingResponse {
	return hubFindingResponse{
		ID:              string(finding.ID),
		RuleID:          finding.RuleID,
		RuleVersion:     finding.RuleVersion,
		DedupeKey:       finding.DedupeKey,
		Severity:        string(finding.Severity),
		Confidence:      string(finding.Confidence),
		Title:           finding.Title,
		Summary:         finding.Summary,
		Description:     finding.Description,
		EventIDs:        stringDomainIDs(finding.EventIDs),
		FirstEventAt:    finding.FirstEventAt,
		LastEventAt:     finding.LastEventAt,
		Status:          findingStatus(finding),
		StatusReason:    finding.StatusReason,
		StatusNote:      finding.StatusNote,
		StatusActor:     finding.StatusActor,
		StatusUpdatedAt: findingStatusUpdatedAt(finding),
		Metadata:        nonNilResponseMap(finding.Metadata),
		CreatedAt:       finding.CreatedAt,
		UpdatedAt:       finding.UpdatedAt,
	}
}

func findingStatus(finding domain.HubFinding) string {
	if strings.TrimSpace(finding.Status) == "" {
		return "open"
	}
	return finding.Status
}

func findingStatusUpdatedAt(finding domain.HubFinding) time.Time {
	if finding.StatusUpdatedAt.IsZero() {
		return finding.UpdatedAt
	}
	return finding.StatusUpdatedAt
}

func timelineEventRecord(event domain.TimelineEvent) timelineEventResponse {
	return timelineEventResponse{
		ID:              string(event.ID),
		BatchID:         string(event.BatchID),
		AppID:           string(event.AppID),
		AppSlug:         event.AppSlug,
		ServiceID:       string(event.ServiceID),
		ServiceSlug:     event.ServiceSlug,
		HostID:          string(event.HostID),
		HostSlug:        event.HostSlug,
		Hostname:        event.Hostname,
		AgentID:         string(event.AgentID),
		AgentExternalID: event.AgentExternalID,
		EventTime:       event.EventTime,
		ReceivedAt:      event.ReceivedAt,
		EventType:       event.EventType,
		Target:          event.Target,
		Severity:        string(event.Severity),
		Message:         event.Message,
		Region:          event.Region,
		Labels:          nonNilResponseStringMap(event.Labels),
		Payload:         nonNilResponseMap(event.Payload),
		CreatedAt:       event.CreatedAt,
	}
}

func configCoverageRecord(record hubapp.ConfigCoverageRecord) configCoverageResponse {
	return configCoverageResponse{
		EventID:         string(record.EventID),
		AppID:           string(record.AppID),
		AppSlug:         record.AppSlug,
		HostID:          string(record.HostID),
		HostSlug:        record.HostSlug,
		Hostname:        record.Hostname,
		AgentID:         string(record.AgentID),
		AgentExternalID: record.AgentExternalID,
		ReportedAt:      record.ReportedAt,
		ReceivedAt:      record.ReceivedAt,
		SiteSlug:        record.SiteSlug,
		SiteKind:        record.SiteKind,
		CoverageLevel:   record.CoverageLevel,
		Labels:          nonNilResponseStringMap(record.Labels),
		Payload:         nonNilResponseMap(record.Payload),
	}
}

func organizationRecord(organization domain.Organization) organizationResponse {
	return organizationResponse{
		ID:        string(organization.ID),
		Slug:      organization.Slug,
		Name:      organization.Name,
		CreatedAt: organization.CreatedAt,
		UpdatedAt: organization.UpdatedAt,
	}
}

func projectRecord(project domain.Project) projectResponse {
	return projectResponse{
		ID:             string(project.ID),
		OrganizationID: string(project.OrganizationID),
		Slug:           project.Slug,
		Name:           project.Name,
		CreatedAt:      project.CreatedAt,
		UpdatedAt:      project.UpdatedAt,
	}
}

func environmentRecord(environment domain.Environment) environmentResponse {
	return environmentResponse{
		ID:        string(environment.ID),
		ProjectID: string(environment.ProjectID),
		Slug:      environment.Slug,
		Name:      environment.Name,
		CreatedAt: environment.CreatedAt,
		UpdatedAt: environment.UpdatedAt,
	}
}

func monitoredAppRecord(app domain.MonitoredApp) monitoredAppResponse {
	return monitoredAppResponse{
		ID:        string(app.ID),
		Slug:      app.Slug,
		Name:      app.Name,
		Kind:      app.Kind,
		CreatedAt: app.CreatedAt,
		UpdatedAt: app.UpdatedAt,
	}
}

func serviceRecord(service domain.Service) serviceResponse {
	return serviceResponse{
		ID:        string(service.ID),
		AppID:     string(service.AppID),
		Slug:      service.Slug,
		Name:      service.Name,
		Role:      service.Role,
		CreatedAt: service.CreatedAt,
		UpdatedAt: service.UpdatedAt,
	}
}

func hostRecord(host domain.Host) hostResponse {
	return hostResponse{
		ID:        string(host.ID),
		Slug:      host.Slug,
		Hostname:  host.Hostname,
		Region:    host.Region,
		Labels:    nonNilResponseStringMap(host.Labels),
		CreatedAt: host.CreatedAt,
		UpdatedAt: host.UpdatedAt,
	}
}

func agentRecord(agent domain.Agent) agentResponse {
	return agentResponse{
		ID:          string(agent.ID),
		HostID:      string(agent.HostID),
		AgentID:     agent.AgentID,
		Fingerprint: agent.Fingerprint,
		Version:     agent.Version,
		LastSeenAt:  agent.LastSeenAt,
		CreatedAt:   agent.CreatedAt,
		UpdatedAt:   agent.UpdatedAt,
	}
}

func deploymentRecord(deployment domain.DeploymentMarker) deploymentResponse {
	return deploymentResponse{
		ID:         string(deployment.ID),
		AppID:      string(deployment.AppID),
		Version:    deployment.Version,
		CommitSHA:  deployment.CommitSHA,
		Actor:      deployment.Actor,
		StartedAt:  deployment.StartedAt,
		FinishedAt: deployment.FinishedAt,
		CreatedAt:  deployment.CreatedAt,
	}
}

func browserScriptObservationRecord(record hubapp.BrowserScriptObservationRecord) browserScriptObservationResponse {
	return browserScriptObservationResponse{
		EventID:         string(record.EventID),
		AppID:           string(record.AppID),
		AppSlug:         record.AppSlug,
		HostID:          string(record.HostID),
		HostSlug:        record.HostSlug,
		Hostname:        record.Hostname,
		AgentID:         string(record.AgentID),
		AgentExternalID: record.AgentExternalID,
		EventTime:       record.EventTime,
		ReceivedAt:      record.ReceivedAt,
		EventType:       record.EventType,
		Target:          record.Target,
		Severity:        string(record.Severity),
		PageURL:         record.PageURL,
		FinalURL:        record.FinalURL,
		Mode:            record.Mode,
		SourceType:      record.SourceType,
		URL:             record.URL,
		URLRedacted:     record.URLRedacted,
		Domain:          record.Domain,
		Path:            record.Path,
		SHA256:          record.SHA256,
		InlineBytes:     record.InlineBytes,
		TagManager:      record.TagManager,
		TagManagerIDs:   record.TagManagerIDs,
		Labels:          nonNilResponseStringMap(record.Labels),
		Payload:         nonNilResponseMap(record.Payload),
	}
}

func browserScriptAllowlistEntryRecord(entry domain.BrowserScriptAllowlistEntry) browserScriptAllowlistEntryResponse {
	return browserScriptAllowlistEntryResponse{
		ID:         string(entry.ID),
		AppID:      string(entry.AppID),
		PageURL:    entry.PageURL,
		Kind:       entry.Kind,
		Value:      entry.Value,
		Reason:     entry.Reason,
		ApprovedBy: entry.ApprovedBy,
		Status:     browserScriptAllowlistStatus(entry),
		CreatedAt:  entry.CreatedAt,
		UpdatedAt:  entry.UpdatedAt,
	}
}

func hubUserRecord(user domain.HubUser) hubUserResponse {
	return hubUserResponse{
		ID:                string(user.ID),
		Email:             user.Email,
		DisplayName:       user.DisplayName,
		AccessLevel:       user.AccessLevel,
		Status:            user.Status,
		TwoFactorRequired: user.TwoFactorRequired,
		TwoFactorEnabled:  user.TwoFactorEnabled,
		TOTPEnrolledAt:    user.TOTPEnrolledAt,
		LastLoginAt:       user.LastLoginAt,
		CreatedAt:         user.CreatedAt,
		UpdatedAt:         user.UpdatedAt,
	}
}

func modelAnalysisReportRecord(report domain.ModelAnalysisReport) modelAnalysisReportResponse {
	return modelAnalysisReportResponse{
		ID:                             string(report.ID),
		AppID:                          string(report.AppID),
		Schema:                         report.ReportSchema,
		Status:                         report.Status,
		ModelProvider:                  report.ModelProvider,
		ModelName:                      report.ModelName,
		PromptTemplateID:               report.PromptTemplateID,
		PromptTemplateVersion:          report.PromptTemplateVersion,
		PromptTemplateSHA256:           report.PromptTemplateSHA256,
		PromptSHA256:                   report.PromptSHA256,
		EvidenceBundleSchema:           report.EvidenceBundleSchema,
		EvidenceBundleSHA256:           report.EvidenceBundleSHA256,
		EvidenceBundleRedactionVersion: report.EvidenceBundleRedactionVersion,
		EvidenceBundleGeneratedAt:      report.EvidenceBundleGeneratedAt,
		SourceFindingIDs:               stringDomainIDs(report.SourceFindingIDs),
		Analysis:                       report.Analysis,
		Error:                          report.Error,
		TotalDurationMillis:            report.TotalDurationMillis,
		PromptEvalCount:                report.PromptEvalCount,
		EvalCount:                      report.EvalCount,
		GeneratedAt:                    report.GeneratedAt,
		Metadata:                       nonNilResponseMap(report.Metadata),
		CreatedAt:                      report.CreatedAt,
	}
}

func browserScriptAllowlistStatus(entry domain.BrowserScriptAllowlistEntry) string {
	if strings.TrimSpace(entry.Status) == "" {
		return "active"
	}
	return entry.Status
}

func ruleDefinitionRecord(definition hubapp.RuleDefinition) ruleDefinitionResponse {
	return ruleDefinitionResponse{
		ID:            definition.ID,
		Version:       definition.Version,
		Title:         definition.Title,
		Category:      string(definition.Category),
		Platforms:     append([]string(nil), definition.Platforms...),
		EvidenceTypes: append([]string(nil), definition.EvidenceTypes...),
		ActionHints:   ruleActionHintStrings(definition.ActionHints),
	}
}

func ruleActionHintStrings(actions []hubapp.RuleActionHint) []string {
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return values
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func stringDomainIDs(ids []domain.ID) []string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, string(id))
	}
	return values
}

func nonNilResponseMap(values map[string]any) map[string]any {
	if values == nil {
		return map[string]any{}
	}
	return values
}

func nonNilResponseStringMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}

func withHubAuth(hub *hubapp.Hub, options HubOptions, minimumAccess string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := requireHubUser(w, r, hub, options, minimumAccess)
		if !ok {
			return
		}
		ctx := context.WithValue(r.Context(), hubUserContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func requireHubUser(w http.ResponseWriter, r *http.Request, hub *hubapp.Hub, options HubOptions, minimumAccess string) (domain.HubUser, bool) {
	if hub == nil {
		writeError(w, http.StatusServiceUnavailable, "hub is not configured")
		return domain.HubUser{}, false
	}
	if !hub.HubUsersConfigured() {
		return domain.HubUser{AccessLevel: "owner", Status: "active"}, true
	}
	count, err := hub.CountHubUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check hub users")
		return domain.HubUser{}, false
	}
	if count == 0 {
		writeError(w, http.StatusUnauthorized, hubapp.ErrHubAuthBootstrapNeeded.Error())
		return domain.HubUser{}, false
	}
	user, ok, err := authenticatedHubUser(r, hub, options)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check session")
		return domain.HubUser{}, false
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, hubapp.ErrHubAuthRequired.Error())
		return domain.HubUser{}, false
	}
	if !hubapp.HubUserHasAccess(user, minimumAccess) {
		writeError(w, http.StatusForbidden, hubapp.ErrHubAuthForbidden.Error())
		return domain.HubUser{}, false
	}
	return user, true
}

func authenticatedHubUser(r *http.Request, hub *hubapp.Hub, options HubOptions) (domain.HubUser, bool, error) {
	cookie, err := r.Cookie(hubSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return domain.HubUser{}, false, nil
	}
	return hub.HubUserForSession(r.Context(), cookie.Value, options.Now().UTC())
}

func hubSessionCookie(token string, expiresAt time.Time, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     hubSessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
	}
}

func clearHubSessionCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     hubSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecureRequest(r),
	}
}

func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
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
