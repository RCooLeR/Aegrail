package domain

import "time"

type Organization struct {
	ID        ID
	Slug      string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Project struct {
	ID             ID
	OrganizationID ID
	Slug           string
	Name           string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Environment struct {
	ID        ID
	ProjectID ID
	Slug      string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type MonitoredApp struct {
	ID            ID
	EnvironmentID ID
	Slug          string
	Name          string
	Kind          string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Service struct {
	ID        ID
	AppID     ID
	Slug      string
	Name      string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Host struct {
	ID            ID
	EnvironmentID ID
	Slug          string
	Hostname      string
	Region        string
	Labels        map[string]string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Agent struct {
	ID          ID
	HostID      ID
	AgentID     string
	Fingerprint string
	Version     string
	LastSeenAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type DistributedEventContext struct {
	OrganizationID ID
	ProjectID      ID
	EnvironmentID  ID
	AppID          ID
	ServiceID      ID
	HostID         ID
	AgentID        ID
	Region         string
	Labels         map[string]string
	EventTime      time.Time
	ReceivedTime   time.Time
}

type DeploymentMarker struct {
	ID            ID
	EnvironmentID ID
	AppID         ID
	Version       string
	CommitSHA     string
	Actor         string
	StartedAt     time.Time
	FinishedAt    *time.Time
	CreatedAt     time.Time
}

type HubFinding struct {
	ID              ID
	OrganizationID  ID
	ProjectID       ID
	EnvironmentID   ID
	AppID           ID
	RuleID          string
	RuleVersion     string
	DedupeKey       string
	Severity        Severity
	Confidence      Confidence
	Title           string
	Summary         string
	Description     string
	EventIDs        []ID
	FirstEventAt    time.Time
	LastEventAt     time.Time
	Status          string
	StatusReason    string
	StatusNote      string
	StatusActor     string
	StatusUpdatedAt time.Time
	Metadata        map[string]any
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type HubFindingStatusUpdate struct {
	Status string
	Reason string
	Note   string
	Actor  string
}

type ModelAnalysisReport struct {
	ID                             ID
	OrganizationID                 ID
	ProjectID                      ID
	EnvironmentID                  ID
	AppID                          ID
	ReportSchema                   string
	Status                         string
	ModelProvider                  string
	ModelName                      string
	PromptTemplateID               string
	PromptTemplateVersion          string
	PromptTemplateSHA256           string
	PromptSHA256                   string
	EvidenceBundleSchema           string
	EvidenceBundleSHA256           string
	EvidenceBundleRedactionVersion string
	EvidenceBundleGeneratedAt      time.Time
	SourceFindingIDs               []ID
	Analysis                       string
	Error                          string
	TotalDurationMillis            int64
	PromptEvalCount                int
	EvalCount                      int
	GeneratedAt                    time.Time
	Metadata                       map[string]any
	CreatedAt                      time.Time
}

type BrowserScriptAllowlistEntry struct {
	ID             ID
	OrganizationID ID
	ProjectID      ID
	EnvironmentID  ID
	AppID          ID
	PageURL        string
	Kind           string
	Value          string
	Reason         string
	ApprovedBy     string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type BrowserScriptAllowlistStatusUpdate struct {
	Status     string
	Reason     string
	ApprovedBy string
}
