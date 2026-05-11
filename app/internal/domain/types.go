package domain

import "time"

type ID string

type AppMeta struct {
	Name      string
	Binary    string
	Version   string
	Commit    string
	BuildDate string
}

type Site struct {
	ID        ID
	Slug      string
	Name      string
	BaseURL   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type EvidenceImportStatus string

const (
	EvidenceImportPending    EvidenceImportStatus = "pending"
	EvidenceImportProcessing EvidenceImportStatus = "processing"
	EvidenceImportCompleted  EvidenceImportStatus = "completed"
	EvidenceImportFailed     EvidenceImportStatus = "failed"
)

type EvidenceImport struct {
	ID                ID
	SiteID            ID
	SourceType        string
	SourceURI         string
	SourceFingerprint string
	Status            EvidenceImportStatus
	StartedAt         time.Time
	FinishedAt        *time.Time
	ToolName          string
	ToolVersion       string
	ObjectCount       int
}

type EvidenceRef struct {
	ID           ID
	ImportID     ID
	URI          string
	OriginalURI  string
	RelativePath string
	SHA256       string
	ContentType  string
	SizeBytes    int64
	CreatedAt    time.Time
}

type EvidenceFile struct {
	SourcePath   string
	RelativePath string
	SHA256       string
	ContentType  string
	SizeBytes    int64
}

type EvidenceManifest struct {
	SourceURI         string
	SourceFingerprint string
	Files             []EvidenceFile
}

type Event struct {
	ID                 ID
	SiteID             ID
	ImportID           ID
	OccurredAt         time.Time
	SourceType         string
	SourceRef          string
	ActorType          string
	ActorID            string
	ActorEmailRedacted string
	IP                 string
	Method             string
	Path               string
	QueryRedacted      string
	Controller         string
	Action             string
	StatusCode         int
	Bytes              int64
	UserAgent          string
	ObjectType         string
	ObjectID           string
	EventName          string
	RiskTags           []string
	RawRef             string
	Metadata           map[string]any
	CreatedAt          time.Time
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type Finding struct {
	ID                   ID
	SiteID               ID
	RuleID               string
	RuleVersion          string
	Severity             Severity
	Confidence           Confidence
	Title                string
	Description          string
	EvidenceRefs         []ID
	RecommendedNextCheck string
	CreatedAt            time.Time
}
