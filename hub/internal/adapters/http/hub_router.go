package httpadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/reports"
	"github.com/rcooler/aegrail/hub/internal/wire"
)

const (
	dashboardProtocol    = "aegrail.dashboard.v1"
	headerDashboardProto = "X-Aegrail-Dashboard-Protocol"
	headerDashboardCSRF  = "X-Aegrail-CSRF"
	hubSessionCookieName = "aegrail_session"
	maxHTTPQueryLimit    = 5000
)

type hubUserContextKey struct{}

var (
	hubBootstrapUserMu sync.Mutex
	hubAuthLimiter     = newHubAuthRateLimiter(10, time.Minute)
)

type HubOptions struct {
	WirePrivateKey    string
	WireTimestampSkew time.Duration
	DashboardDir      string
	Now               func() time.Time
	HealthCheck       func(context.Context) map[string]string
}

func NewHubRouter(meta domain.AppMeta, hub *hubapp.Hub, options HubOptions) http.Handler {
	if options.WireTimestampSkew <= 0 {
		options.WireTimestampSkew = 5 * time.Minute
	}
	if options.Now == nil {
		options.Now = time.Now
	}

	router := chi.NewRouter()
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(options.DashboardDir) != "" {
			http.Redirect(w, r, "/dashboard/", http.StatusFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"name":    meta.Name,
			"binary":  meta.Binary,
			"version": meta.Version,
			"mode":    "hub",
		})
	})
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]string{}
		statusCode := http.StatusOK
		status := "ok"
		if options.HealthCheck != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			checks = options.HealthCheck(ctx)
			for _, value := range checks {
				if value != "ok" && !strings.HasPrefix(value, "ok: ") && value != "offline" {
					status = "unhealthy"
					statusCode = http.StatusServiceUnavailable
					break
				}
			}
		}
		writeJSON(w, statusCode, map[string]any{
			"service": meta.Binary,
			"mode":    "hub",
			"health":  checks,
			"status":  status,
		})
	})
	router.Post("/api/v1/ingest/events", ingestEventsHandler(hub, options))
	router.Get("/api/v1/auth/me", getHubAuthMeHandler(hub, options))
	router.Post("/api/v1/auth/login", loginHubUserHandler(hub, options))
	router.Post("/api/v1/auth/logout", logoutHubUserHandler(hub, options))
	router.Post("/api/v1/auth/totp/start", startCurrentHubUserTOTPHandler(hub, options))
	router.Post("/api/v1/auth/totp/verify", verifyCurrentHubUserTOTPHandler(hub, options))
	router.Get("/api/v1/rules", withHubAuth(hub, options, "viewer", listRulesHandler(hub)))
	router.Get("/api/v1/findings", withHubAuth(hub, options, "viewer", listFindingsHandler(hub)))
	router.Post("/api/v1/findings/baseline", withHubAuth(hub, options, "operator", acceptFindingsBaselineHandler(hub)))
	router.Get("/api/v1/findings/{id}", withHubAuth(hub, options, "viewer", getFindingHandler(hub)))
	router.Patch("/api/v1/findings/{id}/status", withHubAuth(hub, options, "operator", updateFindingStatusHandler(hub)))
	router.Post("/api/v1/findings/{id}/file-ignore", withHubAuth(hub, options, "operator", ignoreFilePathFromFindingHandler(hub)))
	router.Post("/api/v1/findings/{id}/browser-script-allowlist", withHubAuth(hub, options, "operator", allowBrowserScriptFromFindingHandler(hub)))
	router.Post("/api/v1/findings/{id}/model-analysis", withHubAuth(hub, options, "operator", generateModelAnalysisFromFindingHandler(hub)))
	router.Get("/api/v1/findings/{id}/model-analysis", withHubAuth(hub, options, "viewer", listModelAnalysisReportsForFindingHandler(hub)))
	router.Get("/api/v1/model-analysis", withHubAuth(hub, options, "viewer", listModelAnalysisReportsHandler(hub)))
	router.Get("/api/v1/reports/finding-review", withHubAuth(hub, options, "viewer", findingReviewReportHandler(meta, hub)))
	router.Get("/api/v1/reports/model-analysis", withHubAuth(hub, options, "viewer", listModelAnalysisReportsHandler(hub)))
	router.Get("/api/v1/reports/model-analysis/{id}", withHubAuth(hub, options, "viewer", getModelAnalysisReportHandler(hub)))
	router.Get("/api/v1/timeline", withHubAuth(hub, options, "viewer", listTimelineHandler(hub)))
	router.Get("/api/v1/coverage", withHubAuth(hub, options, "viewer", listCoverageHandler(hub)))
	router.Get("/api/v1/deployments", withHubAuth(hub, options, "viewer", listDeploymentsHandler(hub)))
	router.Post("/api/v1/deployments", withHubAuth(hub, options, "operator", createDeploymentHandler(hub)))
	router.Get("/api/v1/browser/scripts", withHubAuth(hub, options, "viewer", listBrowserScriptsHandler(hub)))
	router.Get("/api/v1/browser/script-allowlist", withHubAuth(hub, options, "viewer", listBrowserScriptAllowlistHandler(hub)))
	router.Post("/api/v1/browser/script-allowlist", withHubAuth(hub, options, "operator", allowBrowserScriptHandler(hub)))
	router.Patch("/api/v1/browser/script-allowlist/{id}/status", withHubAuth(hub, options, "operator", updateBrowserScriptAllowlistStatusHandler(hub)))
	router.Get("/api/v1/access/users", withHubAuth(hub, options, "admin", listHubUsersHandler(hub)))
	router.Post("/api/v1/access/users", createHubUserHandler(hub, options))
	router.Patch("/api/v1/access/users/{id}", withHubAuth(hub, options, "admin", updateHubUserHandler(hub)))
	router.Post("/api/v1/access/users/{id}/totp/start", withHubAuth(hub, options, "admin", startHubUserTOTPHandler(hub)))
	router.Post("/api/v1/access/users/{id}/totp/verify", withHubAuth(hub, options, "admin", verifyHubUserTOTPHandler(hub, options)))
	router.Delete("/api/v1/access/users/{id}/totp", withHubAuth(hub, options, "admin", disableHubUserTOTPHandler(hub)))
	router.Get("/api/v1/inventory/scopes", withHubAuth(hub, options, "viewer", listInventoryScopesHandler(hub)))
	router.Get("/api/v1/inventory/apps", withHubAuth(hub, options, "viewer", listInventoryAppsHandler(hub)))
	router.Get("/api/v1/inventory/services", withHubAuth(hub, options, "viewer", listInventoryServicesHandler(hub)))
	router.Get("/api/v1/inventory/hosts", withHubAuth(hub, options, "viewer", listInventoryHostsHandler(hub)))
	router.Get("/api/v1/inventory/agents", withHubAuth(hub, options, "viewer", listInventoryAgentsHandler(hub)))
	router.Get("/api/v1/inventory/topology", withHubAuth(hub, options, "viewer", listInventoryTopologyHandler(hub)))
	router.Post("/api/v1/inventory/companies", withHubAuth(hub, options, "admin", createInventoryCompanyHandler(hub)))
	router.Patch("/api/v1/inventory/companies/{id}", withHubAuth(hub, options, "admin", updateInventoryCompanyHandler(hub)))
	router.Post("/api/v1/inventory/sites", withHubAuth(hub, options, "admin", createInventorySiteHandler(hub)))
	router.Patch("/api/v1/inventory/projects/{id}", withHubAuth(hub, options, "admin", updateInventoryProjectHandler(hub)))
	router.Patch("/api/v1/inventory/environments/{id}", withHubAuth(hub, options, "admin", updateInventoryEnvironmentHandler(hub)))
	router.Patch("/api/v1/inventory/apps/{id}", withHubAuth(hub, options, "admin", updateInventoryAppHandler(hub)))
	router.Patch("/api/v1/inventory/services/{id}", withHubAuth(hub, options, "admin", updateInventoryServiceHandler(hub)))
	router.Post("/api/v1/inventory/nodes", withHubAuth(hub, options, "admin", createInventoryNodeHandler(hub, options)))
	router.Patch("/api/v1/inventory/hosts/{id}", withHubAuth(hub, options, "admin", updateInventoryHostHandler(hub)))
	router.Patch("/api/v1/inventory/agents/{id}", withHubAuth(hub, options, "admin", updateInventoryAgentHandler(hub)))
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
	OperatorAction  map[string]any `json:"operator_action,omitempty"`
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
	Hosts     []hostResponse         `json:"hosts"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type monitoredAppResponse struct {
	ID        string            `json:"id"`
	Slug      string            `json:"slug"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Services  []serviceResponse `json:"services"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
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
	Agents    []agentResponse   `json:"agents"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type agentResponse struct {
	ID            string     `json:"id"`
	HostID        string     `json:"host_id"`
	AgentID       string     `json:"agent_id"`
	Fingerprint   string     `json:"fingerprint"`
	Version       string     `json:"version,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	WireProtocol  string     `json:"wire_protocol,omitempty"`
	NodePublicKey string     `json:"node_public_key,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
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
	ID                   string     `json:"id"`
	Email                string     `json:"email"`
	DisplayName          string     `json:"display_name"`
	AccessLevel          string     `json:"access_level"`
	Status               string     `json:"status"`
	TwoFactorRequired    bool       `json:"two_factor_required"`
	TwoFactorEnabled     bool       `json:"two_factor_enabled"`
	TwoFactorPending     bool       `json:"two_factor_pending"`
	TOTPEnrolledAt       *time.Time `json:"totp_enrolled_at,omitempty"`
	PendingTOTPStartedAt *time.Time `json:"pending_totp_started_at,omitempty"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
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
	Protocol          string           `json:"protocol"`
	CSRFToken         string           `json:"csrf_token,omitempty"`
	DashboardReady    bool             `json:"dashboard_ready"`
	TOTPSetupRequired bool             `json:"totp_setup_required"`
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

type acceptFindingsBaselineRequest struct {
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

type ignoreFilePathFromFindingRequest struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Actor  string `json:"actor"`
}

type generateModelAnalysisRequest struct {
	Model                string `json:"model"`
	MaxEvents            int    `json:"max_events"`
	MaxMetadataDepth     int    `json:"max_metadata_depth"`
	MaxStringLength      int    `json:"max_string_length"`
	MaxCollectionEntries int    `json:"max_collection_entries"`
}

type fileIgnoreRuleResponse struct {
	ID              string    `json:"id"`
	MatchKind       string    `json:"match_kind"`
	MatchValue      string    `json:"match_value"`
	NormalizedValue string    `json:"normalized_value"`
	Reason          string    `json:"reason"`
	CreatedBy       string    `json:"created_by"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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

type verifyHubUserTOTPRequest struct {
	Code string `json:"code"`
}

type createDeploymentMarkerRequest struct {
	Version    string     `json:"version"`
	CommitSHA  string     `json:"commit_sha"`
	Actor      string     `json:"actor"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type createInventoryCompanyRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type updateInventoryCompanyRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type createInventorySiteRequest struct {
	OrganizationSlug string `json:"org"`
	ProjectSlug      string `json:"project"`
	ProjectName      string `json:"project_name"`
	EnvironmentSlug  string `json:"environment"`
	EnvironmentName  string `json:"environment_name"`
	AppSlug          string `json:"app"`
	AppName          string `json:"app_name"`
	Kind             string `json:"kind"`
	ServiceSlug      string `json:"service"`
	ServiceName      string `json:"service_name"`
	ServiceRole      string `json:"service_role"`
}

type updateInventoryProjectRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type updateInventoryEnvironmentRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type updateInventoryAppRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type updateInventoryServiceRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type createInventoryNodeRequest struct {
	OrganizationSlug string            `json:"org"`
	ProjectSlug      string            `json:"project"`
	EnvironmentSlug  string            `json:"environment"`
	AppSlug          string            `json:"app"`
	ServiceSlug      string            `json:"service"`
	HostSlug         string            `json:"host"`
	Hostname         string            `json:"hostname"`
	Region           string            `json:"region"`
	Labels           map[string]string `json:"labels"`
	AgentID          string            `json:"agent_id"`
	Version          string            `json:"version"`
	QueueDir         string            `json:"queue_dir"`
	StateDir         string            `json:"state_dir"`
	Interval         string            `json:"interval"`
}

type updateInventoryHostRequest struct {
	Slug     string            `json:"slug"`
	Hostname string            `json:"hostname"`
	Region   string            `json:"region"`
	Labels   map[string]string `json:"labels"`
}

type updateInventoryAgentRequest struct {
	AgentID string `json:"agent_id"`
	Version string `json:"version"`
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
		body, signature, err := decodeIngestBody(r, body, hub, options)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		var request ingestEventsRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := verifyWireEnvelopeMatchesBatch(signature, request.AgentID); err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		input, err := request.toInput(signature)
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

func getFindingHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		finding, err := hub.GetHubFinding(r.Context(), hubapp.GetHubFindingInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			FindingID:        chi.URLParam(r, "id"),
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

func listModelAnalysisReportsForFindingHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		finding, err := hub.GetHubFinding(r.Context(), hubapp.GetHubFindingInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			FindingID:        chi.URLParam(r, "id"),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		limit, err := parseQueryLimit(r, 50)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		reports, err := hub.ListModelAnalysisReportsForFinding(r.Context(), hubapp.ListModelAnalysisReportsForFindingInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			FindingID:        chi.URLParam(r, "id"),
			Limit:            limit,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		reportRecords := make([]modelAnalysisReportResponse, 0, len(reports))
		for _, report := range reports {
			reportRecords = append(reportRecords, modelAnalysisReportRecord(report))
		}
		sort.Slice(reportRecords, func(left int, right int) bool {
			return reportRecords[left].GeneratedAt.After(reportRecords[right].GeneratedAt)
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"finding": hubFindingRecord(finding),
			"count":   len(reportRecords),
			"reports": reportRecords,
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

func acceptFindingsBaselineHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request acceptFindingsBaselineRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		result, err := hub.AcceptHubFindingsBaseline(r.Context(), hubapp.AcceptHubFindingsBaselineInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			Reason:           request.Reason,
			Note:             request.Note,
			Actor:            request.Actor,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"updated": result.Updated,
			"status":  result.Status,
			"reason":  result.Reason,
			"note":    result.Note,
			"actor":   result.Actor,
		})
	}
}

func ignoreFilePathFromFindingHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request ignoreFilePathFromFindingRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		result, err := hub.IgnoreFilePathFromFinding(r.Context(), hubapp.IgnoreFilePathFromFindingInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			FindingID:        chi.URLParam(r, "id"),
			Path:             request.Path,
			Reason:           request.Reason,
			Actor:            request.Actor,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"finding":                hubFindingRecord(result.Finding),
			"ignore_rule":            fileIgnoreRuleRecord(result.Rule),
			"agent_exclude_hint":     result.AgentExcludeHint,
			"normalized_pattern":     result.NormalizedPattern,
			"requires_agent_restart": false,
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

func findingReviewReportHandler(meta domain.AppMeta, hub *hubapp.Hub) http.HandlerFunc {
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
		modelReports, err := hub.ListModelAnalysisReports(r.Context(), hubapp.ListModelAnalysisReportsInput{
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
		report := reports.BuildFindingReviewReport(meta, reports.HubFindingsScope{
			Organization: r.URL.Query().Get("org"),
			Project:      r.URL.Query().Get("project"),
			Environment:  r.URL.Query().Get("environment"),
			App:          r.URL.Query().Get("app"),
		}, findings, modelReports, time.Now().UTC())
		writeJSON(w, http.StatusOK, map[string]any{
			"report": report,
		})
	}
}

func generateModelAnalysisFromFindingHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request generateModelAnalysisRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		report, err := hub.GenerateModelAnalysisReport(r.Context(), hubapp.GenerateModelAnalysisReportInput{
			OrganizationSlug:     r.URL.Query().Get("org"),
			ProjectSlug:          r.URL.Query().Get("project"),
			EnvironmentSlug:      r.URL.Query().Get("environment"),
			AppSlug:              r.URL.Query().Get("app"),
			FindingID:            chi.URLParam(r, "id"),
			Model:                request.Model,
			MaxEventsPerFinding:  request.MaxEvents,
			MaxMetadataDepth:     request.MaxMetadataDepth,
			MaxStringLength:      request.MaxStringLength,
			MaxCollectionEntries: request.MaxCollectionEntries,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"report": modelAnalysisReportRecord(report),
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

func createDeploymentHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request createDeploymentMarkerRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		startedAt := time.Time{}
		if request.StartedAt != nil {
			startedAt = request.StartedAt.UTC()
		}
		var finishedAt *time.Time
		if request.FinishedAt != nil {
			finished := request.FinishedAt.UTC()
			finishedAt = &finished
		}
		deployment, err := hub.SaveDeploymentMarker(r.Context(), hubapp.SaveDeploymentMarkerInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			Version:          request.Version,
			CommitSHA:        request.CommitSHA,
			Actor:            request.Actor,
			StartedAt:        startedAt,
			FinishedAt:       finishedAt,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"deployment": deploymentRecord(deployment),
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
				Protocol:       dashboardProtocol,
				DashboardReady: true,
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
				Protocol:          dashboardProtocol,
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
				Protocol:       dashboardProtocol,
			})
			return
		}
		record := hubUserRecord(user)
		sessionToken := hubSessionToken(r)
		writeJSON(w, http.StatusOK, hubAuthMeResponse{
			Authenticated:     true,
			AuthConfigured:    true,
			Protocol:          dashboardProtocol,
			CSRFToken:         dashboardCSRFToken(sessionToken),
			DashboardReady:    hubUserDashboardReady(user),
			TOTPSetupRequired: !hubUserDashboardReady(user),
			User:              &record,
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
		if !allowHubAuthAttempt(r, options, "login:"+strings.ToLower(strings.TrimSpace(request.Email))) {
			writeError(w, http.StatusTooManyRequests, "too many authentication attempts")
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
			"protocol":            dashboardProtocol,
			"csrf_token":          dashboardCSRFToken(result.Token),
			"dashboard_ready":     hubUserDashboardReady(result.User),
			"totp_setup_required": !hubUserDashboardReady(result.User),
			"user":                hubUserRecord(result.User),
			"expires_at":          result.ExpiresAt,
		})
	}
}

func logoutHubUserHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		if err := verifyDashboardCSRF(r); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
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

func startCurrentHubUserTOTPHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := requireHubSession(w, r, hub, options)
		if !ok {
			return
		}
		if err := verifyDashboardCSRF(r); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		var request generateHubUserTOTPRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
				writeError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
		}
		result, err := hub.StartHubUserTOTP(r.Context(), hubapp.StartHubUserTOTPInput{
			UserID: string(user.ID),
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

func verifyCurrentHubUserTOTPHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := requireHubSession(w, r, hub, options)
		if !ok {
			return
		}
		if err := verifyDashboardCSRF(r); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		var request verifyHubUserTOTPRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if !allowHubAuthAttempt(r, options, "totp-current:"+string(user.ID)) {
			writeError(w, http.StatusTooManyRequests, "too many authentication attempts")
			return
		}
		result, err := hub.VerifyHubUserTOTP(r.Context(), hubapp.VerifyHubUserTOTPInput{
			UserID: string(user.ID),
			Code:   request.Code,
		})
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, hubapp.ErrHubTOTPInvalidCode) || errors.Is(err, hubapp.ErrHubTOTPNoPending) {
				status = http.StatusUnauthorized
			}
			writeError(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user": hubUserRecord(result.User),
		})
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
		bootstrapLockHeld := false
		if hub.HubUsersConfigured() {
			hubBootstrapUserMu.Lock()
			count, err := hub.CountHubUsers(r.Context())
			if err != nil {
				hubBootstrapUserMu.Unlock()
				writeError(w, http.StatusInternalServerError, "could not check hub users")
				return
			}
			bootstrap = count == 0
			bootstrapLockHeld = bootstrap
			if !bootstrap {
				hubBootstrapUserMu.Unlock()
				user, ok := requireHubUser(w, r, hub, options, "admin")
				if !ok {
					return
				}
				_ = user
			}
		}
		if bootstrapLockHeld {
			defer hubBootstrapUserMu.Unlock()
		}
		var request createHubUserRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if bootstrap {
			request.AccessLevel = "owner"
			request.Status = "active"
			request.TwoFactorRequired = true
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

func startHubUserTOTPHandler(hub *hubapp.Hub) http.HandlerFunc {
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
		result, err := hub.StartHubUserTOTP(r.Context(), hubapp.StartHubUserTOTPInput{
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

func verifyHubUserTOTPHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request verifyHubUserTOTPRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if !allowHubAuthAttempt(r, options, "totp-admin:"+chi.URLParam(r, "id")) {
			writeError(w, http.StatusTooManyRequests, "too many authentication attempts")
			return
		}
		result, err := hub.VerifyHubUserTOTP(r.Context(), hubapp.VerifyHubUserTOTPInput{
			UserID: chi.URLParam(r, "id"),
			Code:   request.Code,
		})
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, hubapp.ErrHubTOTPInvalidCode) || errors.Is(err, hubapp.ErrHubTOTPNoPending) {
				status = http.StatusUnauthorized
			}
			writeError(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user": hubUserRecord(result.User),
		})
	}
}

func disableHubUserTOTPHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		result, err := hub.DisableHubUserTOTP(r.Context(), hubapp.DisableHubUserTOTPInput{
			UserID: chi.URLParam(r, "id"),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user": hubUserRecord(result.User),
		})
	}
}

func createInventoryCompanyHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request createInventoryCompanyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		organization, err := hub.SaveOrganization(r.Context(), hubapp.SaveOrganizationInput{
			Slug: request.Slug,
			Name: request.Name,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"organization": organizationRecord(organization)})
	}
}

func updateInventoryCompanyHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryCompanyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		organization, err := hub.UpdateOrganization(r.Context(), hubapp.UpdateOrganizationInput{
			ID:   chi.URLParam(r, "id"),
			Slug: request.Slug,
			Name: request.Name,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"organization": organizationRecord(organization)})
	}
}

func createInventorySiteHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request createInventorySiteRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		envSlug := defaultString(request.EnvironmentSlug, "production")
		appSlug := defaultString(request.AppSlug, "main-web")
		serviceSlug := defaultString(request.ServiceSlug, "frontend")
		project, err := hub.SaveProject(r.Context(), hubapp.SaveProjectInput{
			OrganizationSlug: request.OrganizationSlug,
			Slug:             request.ProjectSlug,
			Name:             request.ProjectName,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		environment, err := hub.SaveEnvironment(r.Context(), hubapp.SaveEnvironmentInput{
			OrganizationSlug: request.OrganizationSlug,
			ProjectSlug:      project.Slug,
			Slug:             envSlug,
			Name:             defaultString(request.EnvironmentName, envSlug),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		app, err := hub.SaveMonitoredApp(r.Context(), hubapp.SaveMonitoredAppInput{
			OrganizationSlug: request.OrganizationSlug,
			ProjectSlug:      project.Slug,
			EnvironmentSlug:  environment.Slug,
			Slug:             appSlug,
			Name:             defaultString(request.AppName, appSlug),
			Kind:             request.Kind,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		service, err := hub.SaveService(r.Context(), hubapp.SaveServiceInput{
			OrganizationSlug: request.OrganizationSlug,
			ProjectSlug:      project.Slug,
			EnvironmentSlug:  environment.Slug,
			AppSlug:          app.Slug,
			Slug:             serviceSlug,
			Name:             defaultString(request.ServiceName, serviceSlug),
			Role:             defaultString(request.ServiceRole, "web"),
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"project":     projectRecord(project),
			"environment": environmentRecord(environment),
			"app":         monitoredAppRecord(app),
			"service":     serviceRecord(service),
		})
	}
}

func updateInventoryProjectHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryProjectRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		project, err := hub.UpdateProject(r.Context(), hubapp.UpdateProjectInput{
			ID:   chi.URLParam(r, "id"),
			Slug: request.Slug,
			Name: request.Name,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"project": projectRecord(project)})
	}
}

func updateInventoryEnvironmentHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryEnvironmentRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		environment, err := hub.UpdateEnvironment(r.Context(), hubapp.UpdateEnvironmentInput{
			ID:   chi.URLParam(r, "id"),
			Slug: request.Slug,
			Name: request.Name,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"environment": environmentRecord(environment)})
	}
}

func updateInventoryAppHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryAppRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		app, err := hub.UpdateMonitoredApp(r.Context(), hubapp.UpdateMonitoredAppInput{
			ID:   chi.URLParam(r, "id"),
			Slug: request.Slug,
			Name: request.Name,
			Kind: request.Kind,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"app": monitoredAppRecord(app)})
	}
}

func updateInventoryServiceHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryServiceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		service, err := hub.UpdateService(r.Context(), hubapp.UpdateServiceInput{
			ID:   chi.URLParam(r, "id"),
			Slug: request.Slug,
			Name: request.Name,
			Role: request.Role,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"service": serviceRecord(service)})
	}
}

func createInventoryNodeHandler(hub *hubapp.Hub, options HubOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		if strings.TrimSpace(options.WirePrivateKey) == "" {
			writeError(w, http.StatusServiceUnavailable, "Hub wire private key is not configured")
			return
		}
		if !isSecureRequest(r) && !isLoopbackRequest(r) {
			writeError(w, http.StatusBadRequest, "node secrets can only be created over HTTPS or loopback")
			return
		}
		hubPublicKey, err := wire.PublicKeyFromPrivate(options.WirePrivateKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Hub wire private key is invalid")
			return
		}
		var request createInventoryNodeRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		host, err := hub.SaveHost(r.Context(), hubapp.SaveHostInput{
			OrganizationSlug: request.OrganizationSlug,
			ProjectSlug:      request.ProjectSlug,
			EnvironmentSlug:  defaultString(request.EnvironmentSlug, "production"),
			Slug:             request.HostSlug,
			Hostname:         request.Hostname,
			Region:           request.Region,
			Labels:           request.Labels,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		nodeSecret, nodePublicKey, err := wire.GenerateKeyPair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not generate node key")
			return
		}
		agentID := strings.TrimSpace(request.AgentID)
		if agentID == "" {
			agentID = "node-" + host.Slug + "-" + randomToken(4)
		}
		agent, err := hub.SaveAgent(r.Context(), hubapp.SaveAgentInput{
			OrganizationSlug: request.OrganizationSlug,
			ProjectSlug:      request.ProjectSlug,
			EnvironmentSlug:  defaultString(request.EnvironmentSlug, "production"),
			HostSlug:         host.Slug,
			AgentID:          agentID,
			Version:          request.Version,
			WireProtocol:     wire.EnvelopeSchema,
			NodePublicKey:    nodePublicKey,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		sample := buildAgentSampleConfig(r, request, host, agent, hubPublicKey, nodeSecret)
		writeJSON(w, http.StatusCreated, map[string]any{
			"host":           hostRecord(host),
			"agent":          agentRecord(agent),
			"node_id":        agent.AgentID,
			"node_secret":    nodeSecret,
			"hub_public_key": hubPublicKey,
			"sample_config":  sample,
		})
	}
}

func updateInventoryHostHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryHostRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		host, err := hub.UpdateHost(r.Context(), hubapp.UpdateHostInput{
			ID:       chi.URLParam(r, "id"),
			Slug:     request.Slug,
			Hostname: request.Hostname,
			Region:   request.Region,
			Labels:   request.Labels,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"host": hostRecord(host)})
	}
}

func updateInventoryAgentHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateInventoryAgentRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		agent, err := hub.UpdateAgent(r.Context(), hubapp.UpdateAgentInput{
			ID:      chi.URLParam(r, "id"),
			AgentID: request.AgentID,
			Version: request.Version,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"agent": agentRecord(agent)})
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
						appRecord := monitoredAppRecord(app)
						services, err := hub.ListServices(r.Context(), organization.Slug, project.Slug, environment.Slug, app.Slug)
						if err != nil {
							writeError(w, http.StatusBadRequest, err.Error())
							return
						}
						appRecord.Services = make([]serviceResponse, 0, len(services))
						for _, service := range services {
							appRecord.Services = append(appRecord.Services, serviceRecord(service))
						}
						environmentRecord.Apps = append(environmentRecord.Apps, appRecord)
					}
					hosts, err := hub.ListHosts(r.Context(), organization.Slug, project.Slug, environment.Slug)
					if err != nil {
						writeError(w, http.StatusBadRequest, err.Error())
						return
					}
					environmentRecord.Hosts = make([]hostResponse, 0, len(hosts))
					for _, host := range hosts {
						hostResponse := hostRecord(host)
						agents, err := hub.ListAgents(r.Context(), organization.Slug, project.Slug, environment.Slug, host.Slug)
						if err != nil {
							writeError(w, http.StatusBadRequest, err.Error())
							return
						}
						hostResponse.Agents = make([]agentResponse, 0, len(agents))
						for _, agent := range agents {
							hostResponse.Agents = append(hostResponse.Agents, agentRecord(agent))
						}
						environmentRecord.Hosts = append(environmentRecord.Hosts, hostResponse)
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
	if limit > maxHTTPQueryLimit {
		return maxHTTPQueryLimit, nil
	}
	return limit, nil
}

type hubAuthRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string][]time.Time
}

func newHubAuthRateLimiter(limit int, window time.Duration) *hubAuthRateLimiter {
	return &hubAuthRateLimiter{
		limit:    limit,
		window:   window,
		attempts: map[string][]time.Time{},
	}
}

func allowHubAuthAttempt(r *http.Request, options HubOptions, routeKey string) bool {
	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}
	ip := requestRemoteIP(r)
	remote := "unknown"
	if ip != nil {
		remote = ip.String()
	}
	return hubAuthLimiter.allow(remote+"|"+routeKey, now)
}

func (l *hubAuthRateLimiter) allow(key string, now time.Time) bool {
	if l == nil {
		return true
	}
	if l.limit <= 0 {
		l.limit = 10
	}
	if l.window <= 0 {
		l.window = time.Minute
	}
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	items := l.attempts[key]
	kept := items[:0]
	for _, at := range items {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= l.limit {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)
	return true
}

func hubFindingRecord(finding domain.HubFinding) hubFindingResponse {
	metadata := nonNilResponseMap(finding.Metadata)
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
		OperatorAction:  responseOperatorAction(metadata),
		EventIDs:        stringDomainIDs(finding.EventIDs),
		FirstEventAt:    finding.FirstEventAt,
		LastEventAt:     finding.LastEventAt,
		Status:          findingStatus(finding),
		StatusReason:    finding.StatusReason,
		StatusNote:      finding.StatusNote,
		StatusActor:     finding.StatusActor,
		StatusUpdatedAt: findingStatusUpdatedAt(finding),
		Metadata:        metadata,
		CreatedAt:       finding.CreatedAt,
		UpdatedAt:       finding.UpdatedAt,
	}
}

func responseOperatorAction(metadata map[string]any) map[string]any {
	action, ok := metadata["operator_action"].(map[string]any)
	if !ok {
		return nil
	}
	return action
}

func fileIgnoreRuleRecord(rule domain.HubFileIgnoreRule) fileIgnoreRuleResponse {
	return fileIgnoreRuleResponse{
		ID:              string(rule.ID),
		MatchKind:       rule.MatchKind,
		MatchValue:      rule.MatchValue,
		NormalizedValue: rule.NormalizedValue,
		Reason:          rule.Reason,
		CreatedBy:       rule.CreatedBy,
		Status:          rule.Status,
		CreatedAt:       rule.CreatedAt,
		UpdatedAt:       rule.UpdatedAt,
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
		ID:            string(agent.ID),
		HostID:        string(agent.HostID),
		AgentID:       agent.AgentID,
		Fingerprint:   agent.Fingerprint,
		Version:       agent.Version,
		LastSeenAt:    agent.LastSeenAt,
		WireProtocol:  agent.WireProtocol,
		NodePublicKey: agent.NodePublicKey,
		CreatedAt:     agent.CreatedAt,
		UpdatedAt:     agent.UpdatedAt,
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
		ID:                   string(user.ID),
		Email:                user.Email,
		DisplayName:          user.DisplayName,
		AccessLevel:          user.AccessLevel,
		Status:               user.Status,
		TwoFactorRequired:    user.TwoFactorRequired,
		TwoFactorEnabled:     user.TwoFactorEnabled,
		TwoFactorPending:     strings.TrimSpace(user.PendingTOTPSecretCiphertext) != "",
		TOTPEnrolledAt:       user.TOTPEnrolledAt,
		PendingTOTPStartedAt: user.PendingTOTPStartedAt,
		LastLoginAt:          user.LastLoginAt,
		CreatedAt:            user.CreatedAt,
		UpdatedAt:            user.UpdatedAt,
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
	if !hubUserDashboardReady(user) {
		writeError(w, http.StatusForbidden, "2FA enrollment required")
		return domain.HubUser{}, false
	}
	if err := verifyDashboardCSRF(r); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return domain.HubUser{}, false
	}
	if !hubapp.HubUserHasAccess(user, minimumAccess) {
		writeError(w, http.StatusForbidden, hubapp.ErrHubAuthForbidden.Error())
		return domain.HubUser{}, false
	}
	return user, true
}

func requireHubSession(w http.ResponseWriter, r *http.Request, hub *hubapp.Hub, options HubOptions) (domain.HubUser, bool) {
	if hub == nil {
		writeError(w, http.StatusServiceUnavailable, "hub is not configured")
		return domain.HubUser{}, false
	}
	if !hub.HubUsersConfigured() {
		writeError(w, http.StatusUnauthorized, hubapp.ErrHubAuthRequired.Error())
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
	return user, true
}

func authenticatedHubUser(r *http.Request, hub *hubapp.Hub, options HubOptions) (domain.HubUser, bool, error) {
	cookie, err := r.Cookie(hubSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return domain.HubUser{}, false, nil
	}
	return hub.HubUserForSession(r.Context(), cookie.Value, options.Now().UTC())
}

func hubUserDashboardReady(user domain.HubUser) bool {
	if !user.TwoFactorRequired {
		return true
	}
	return user.TwoFactorEnabled && strings.TrimSpace(user.TOTPSecretCiphertext) != ""
}

func hubSessionToken(r *http.Request) string {
	cookie, err := r.Cookie(hubSessionCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func dashboardCSRFToken(sessionToken string) string {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte(dashboardProtocol))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyDashboardCSRF(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	if strings.TrimSpace(r.Header.Get(headerDashboardProto)) != dashboardProtocol {
		return errors.New("dashboard protocol header is required")
	}
	sessionToken := hubSessionToken(r)
	if sessionToken == "" {
		return hubapp.ErrHubAuthRequired
	}
	expected := dashboardCSRFToken(sessionToken)
	actual := strings.TrimSpace(r.Header.Get(headerDashboardCSRF))
	if expected == "" || actual == "" {
		return errors.New("dashboard CSRF token is required")
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return errors.New("dashboard CSRF token is invalid")
	}
	actualBytes, err := hex.DecodeString(actual)
	if err != nil {
		return errors.New("dashboard CSRF token is invalid")
	}
	if !hmac.Equal(actualBytes, expectedBytes) {
		return errors.New("dashboard CSRF token is invalid")
	}
	return nil
}

func hubSessionCookie(token string, expiresAt time.Time, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     hubSessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
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
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
	}
}

func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || (trustedForwardedHeaders(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

func decodeIngestBody(r *http.Request, body []byte, hub *hubapp.Hub, options HubOptions) ([]byte, string, error) {
	var envelope wire.Envelope
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Schema != wire.EnvelopeSchema {
		return nil, "", errors.New("encrypted wire envelope is required")
	}
	if strings.TrimSpace(options.WirePrivateKey) == "" {
		return nil, "", errors.New("Hub wire private key is not configured")
	}
	agent, ok, err := hub.FindAgentByAgentID(r.Context(), envelope.NodeID)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return nil, "", fmt.Errorf("node %q is not registered", envelope.NodeID)
	}
	if strings.TrimSpace(agent.NodePublicKey) == "" {
		return nil, "", fmt.Errorf("node %q does not have a wire public key", envelope.NodeID)
	}
	plaintext, err := wire.Decrypt(envelope, agent.NodePublicKey, options.WirePrivateKey, options.Now(), options.WireTimestampSkew)
	if err != nil {
		return nil, "", err
	}
	return plaintext, wireEnvelopeSignature(envelope), nil
}

func wireEnvelopeSignature(envelope wire.Envelope) string {
	sum := sha256.Sum256([]byte(envelope.NodeID + "\n" + envelope.Timestamp + "\n" + envelope.Nonce + "\n" + envelope.Ciphertext))
	return "wire:v1:" + envelope.NodeID + ":" + hex.EncodeToString(sum[:])
}

func verifyWireEnvelopeMatchesBatch(signature string, agentID string) error {
	if !strings.HasPrefix(signature, "wire:v1:") {
		return nil
	}
	parts := strings.SplitN(signature, ":", 4)
	if len(parts) != 4 {
		return errors.New("invalid wire signature metadata")
	}
	if strings.TrimSpace(agentID) != parts[2] {
		return errors.New("wire node id does not match decrypted batch agent id")
	}
	return nil
}

func buildAgentSampleConfig(r *http.Request, request createInventoryNodeRequest, host domain.Host, agent domain.Agent, hubPublicKey string, nodeSecret string) string {
	environment := defaultString(request.EnvironmentSlug, "production")
	app := defaultString(request.AppSlug, "main-web")
	service := defaultString(request.ServiceSlug, "frontend")
	queueDir := defaultString(request.QueueDir, "/var/lib/aegrail/queue")
	stateDir := defaultString(request.StateDir, "/var/lib/aegrail/state")
	interval := defaultString(request.Interval, "30s")
	return fmt.Sprintf(`schema: aegrail.agent.server_config.v1

hub:
  url: %q
  protocol: aegrail-wire-v1
  hub_public_key: %q
  node_secret: %q
  send_limit: 100

identity:
  org: %q
  project: %q
  environment: %q
  host: %q
  agent_id: %q
  region: %q

runtime:
  queue_dir: %q
  state_dir: %q
  interval: %q
  sent_retention: "0s"
  timezone: UTC

sites:
  - slug: %q
    name: %q
    kind: wordpress
    app: %q
    service: %q
    root: /var/www/example
    files:
      enabled: true
    coverage:
      enabled: true
`,
		requestBaseURL(r),
		hubPublicKey,
		nodeSecret,
		request.OrganizationSlug,
		request.ProjectSlug,
		environment,
		host.Slug,
		agent.AgentID,
		host.Region,
		queueDir,
		stateDir,
		interval,
		request.ProjectSlug,
		defaultString(request.ProjectSlug, "Example Site"),
		app,
		service,
	)
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if trustedForwardedHeaders(r) {
		if forwardedScheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwardedScheme != "" {
			scheme = forwardedScheme
		}
		if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	return strings.TrimRight(scheme+"://"+host, "/")
}

func trustedForwardedHeaders(r *http.Request) bool {
	ip := requestRemoteIP(r)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func isLoopbackRequest(r *http.Request) bool {
	ip := requestRemoteIP(r)
	if ip == nil {
		host := strings.TrimSpace(r.Host)
		if hostName, _, err := net.SplitHostPort(host); err == nil {
			host = hostName
		}
		return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
	}
	return ip.IsLoopback()
}

func requestRemoteIP(r *http.Request) net.IP {
	remote := strings.TrimSpace(r.RemoteAddr)
	if remote == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	return net.ParseIP(strings.Trim(remote, "[]"))
}

func defaultString(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func randomToken(bytesLen int) string {
	raw := make([]byte, bytesLen)
	if _, err := rand.Read(raw); err != nil {
		return time.Now().UTC().Format("150405")
	}
	return hex.EncodeToString(raw)
}

func writeError(w http.ResponseWriter, status int, message string) {
	if status == http.StatusInternalServerError {
		message = "internal server error"
	}
	writeJSON(w, status, map[string]string{"error": message})
}
