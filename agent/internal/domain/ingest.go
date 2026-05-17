package domain

import "time"

type IngestBatch struct {
	ID             ID
	ExternalID     string
	OrganizationID ID
	ProjectID      ID
	EnvironmentID  ID
	AppID          ID
	ServiceID      ID
	HostID         ID
	AgentID        ID
	Source         string
	BodySHA256     string
	Signature      string
	Status         string
	EventCount     int
	ReceivedAt     time.Time
	Metadata       map[string]any
	CreatedAt      time.Time
}

type IngestEvent struct {
	ID             ID
	BatchID        ID
	OrganizationID ID
	ProjectID      ID
	EnvironmentID  ID
	AppID          ID
	ServiceID      ID
	HostID         ID
	AgentID        ID
	EventTime      time.Time
	ReceivedAt     time.Time
	EventType      string
	Target         string
	Severity       Severity
	Message        string
	Region         string
	Labels         map[string]string
	Payload        map[string]any
	CreatedAt      time.Time
}

type FileStateObservation struct {
	EventID         ID
	EnvironmentID   ID
	AppID           ID
	HostID          ID
	AgentID         ID
	HostSlug        string
	Hostname        string
	AgentExternalID string
	EventTime       time.Time
	EventType       string
	Target          string
	Severity        Severity
	RelativePath    string
	Path            string
	SHA256          string
	PreviousSHA256  string
	SizeBytes       int64
	HashSkipped     bool
	Deleted         bool
}

type TimelineEvent struct {
	ID              ID
	BatchID         ID
	OrganizationID  ID
	ProjectID       ID
	EnvironmentID   ID
	AppID           ID
	AppSlug         string
	ServiceID       ID
	ServiceSlug     string
	HostID          ID
	HostSlug        string
	Hostname        string
	AgentID         ID
	AgentExternalID string
	EventTime       time.Time
	ReceivedAt      time.Time
	EventType       string
	Target          string
	Severity        Severity
	Message         string
	Region          string
	Labels          map[string]string
	Payload         map[string]any
	CreatedAt       time.Time
}
