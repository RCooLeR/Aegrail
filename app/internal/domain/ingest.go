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
