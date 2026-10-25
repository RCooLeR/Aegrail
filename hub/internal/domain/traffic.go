package domain

import "time"

type TrafficScope struct {
	OrganizationID ID
	ProjectID      ID
	EnvironmentID  ID
	AppID          ID
}

type TrafficFilter struct {
	Scope TrafficScope
	Since time.Time
	Until time.Time
	Limit int
}

type TrafficOverview struct {
	Since         time.Time `json:"since"`
	Until         time.Time `json:"until"`
	TotalRequests int64     `json:"total_requests"`
	UniqueIPs     int64     `json:"unique_ips"`
	TotalBytes    int64     `json:"total_bytes"`
	ErrorRequests int64     `json:"error_requests"`
	// BotRequests counts crawler/RAG traffic. Monitors and client tools are
	// included in the automation listing but deliberately excluded here.
	BotRequests    int64                     `json:"bot_requests"`
	StatusCodes    []TrafficStatusCount      `json:"status_codes"`
	TopIPs         []TrafficIPSummary        `json:"top_ips"`
	TopPaths       []TrafficPathSummary      `json:"top_paths"`
	TopUserAgents  []TrafficUserAgentSummary `json:"top_user_agents"`
	Timeline       []TrafficTimelineBucket   `json:"timeline"`
	TimelineBucket string                    `json:"timeline_bucket"`
}

type TrafficStatusCount struct {
	StatusCode int   `json:"status_code"`
	Requests   int64 `json:"requests"`
}

type TrafficIPSummary struct {
	IP                 string    `json:"ip"`
	Requests           int64     `json:"requests"`
	ErrorRequests      int64     `json:"error_requests"`
	TotalBytes         int64     `json:"total_bytes"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	ManualPolicy       string    `json:"manual_policy"`
	Trusted            bool      `json:"trusted"`
	Blocked            bool      `json:"blocked"`
	RecognizedProvider string    `json:"recognized_provider,omitempty"`
	ProviderVerified   bool      `json:"provider_verified"`
}

type TrafficPathSummary struct {
	Path          string    `json:"path"`
	Requests      int64     `json:"requests"`
	ErrorRequests int64     `json:"error_requests"`
	TotalBytes    int64     `json:"total_bytes"`
	LastSeen      time.Time `json:"last_seen"`
}

type TrafficUserAgentSummary struct {
	Hash             string    `json:"hash"`
	UserAgent        string    `json:"user_agent"`
	Family           string    `json:"family"`
	BrowserFamily    string    `json:"browser_family,omitempty"`
	BrowserVersion   string    `json:"browser_version,omitempty"`
	OSFamily         string    `json:"os_family,omitempty"`
	OSVersion        string    `json:"os_version,omitempty"`
	DeviceFamily     string    `json:"device_family,omitempty"`
	ActorType        string    `json:"actor_type"`
	KnownActor       string    `json:"known_actor,omitempty"`
	IsBot            bool      `json:"is_bot"`
	IsTool           bool      `json:"is_tool"`
	RiskScore        int       `json:"risk_score"`
	Requests         int64     `json:"requests"`
	VerifiedRequests int64     `json:"verified_requests"`
	UniqueIPs        int64     `json:"unique_ips"`
	ErrorRequests    int64     `json:"error_requests"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// TrafficBotsPage keeps list pagination separate from aggregate counts. The
// totals describe every classified automation client in the requested scope
// and time window, while Bots contains at most the requested limit.
type TrafficBotsPage struct {
	TotalClients          int64                     `json:"total_clients"`
	TotalRequests         int64                     `json:"total_requests"`
	TotalVerifiedRequests int64                     `json:"total_verified_requests"`
	TotalErrorRequests    int64                     `json:"total_error_requests"`
	Bots                  []TrafficUserAgentSummary `json:"bots"`
}

type TrafficTimelineBucket struct {
	Start         time.Time `json:"start"`
	Requests      int64     `json:"requests"`
	ErrorRequests int64     `json:"error_requests"`
	// BotRequests uses the same crawler/RAG-only definition as the overview.
	BotRequests int64 `json:"bot_requests"`
	TotalBytes  int64 `json:"total_bytes"`
}

type TrafficRequestSample struct {
	EventID         ID        `json:"event_id"`
	EventTime       time.Time `json:"event_time"`
	IP              string    `json:"ip,omitempty"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	StatusCode      int       `json:"status_code,omitempty"`
	ResponseBytes   int64     `json:"response_bytes,omitempty"`
	UserAgentHash   string    `json:"user_agent_hash,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	UserAgentFamily string    `json:"user_agent_family,omitempty"`
}

type TrafficIPDetail struct {
	IP             string                    `json:"ip"`
	Since          time.Time                 `json:"since"`
	Until          time.Time                 `json:"until"`
	Requests       int64                     `json:"requests"`
	ErrorRequests  int64                     `json:"error_requests"`
	TotalBytes     int64                     `json:"total_bytes"`
	FirstSeen      time.Time                 `json:"first_seen"`
	LastSeen       time.Time                 `json:"last_seen"`
	StatusCodes    []TrafficStatusCount      `json:"status_codes"`
	TopPaths       []TrafficPathSummary      `json:"top_paths"`
	UserAgents     []TrafficUserAgentSummary `json:"user_agents"`
	RecentRequests []TrafficRequestSample    `json:"recent_requests"`
	Intel          TrafficIPIntel            `json:"intel"`
	Policy         TrafficIPPolicy           `json:"policy"`
	Trusted        bool                      `json:"trusted"`
	Blocked        bool                      `json:"blocked"`
}

type TrafficUserAgentDetail struct {
	TrafficUserAgentSummary
	Since          time.Time              `json:"since"`
	Until          time.Time              `json:"until"`
	StatusCodes    []TrafficStatusCount   `json:"status_codes"`
	TopIPs         []TrafficIPSummary     `json:"top_ips"`
	TopPaths       []TrafficPathSummary   `json:"top_paths"`
	RecentRequests []TrafficRequestSample `json:"recent_requests"`
}

type TrafficIPIntel struct {
	IP                 string    `json:"ip"`
	NetworkClass       string    `json:"network_class"`
	ReverseDNS         []string  `json:"reverse_dns"`
	DNSVerified        bool      `json:"dns_verified"`
	ProviderFamily     string    `json:"provider_family,omitempty"`
	RecognizedProvider string    `json:"recognized_provider,omitempty"`
	ProviderActorType  string    `json:"provider_actor_type,omitempty"`
	ProviderVerified   bool      `json:"provider_verified"`
	LookupStatus       string    `json:"lookup_status"`
	LastLookupAt       time.Time `json:"last_lookup_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	LastError          string    `json:"last_error,omitempty"`
}

type TrafficIPPolicy struct {
	IP        string     `json:"ip"`
	Policy    string     `json:"policy"`
	Reason    string     `json:"reason,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}
