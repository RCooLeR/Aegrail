package reports

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type TimelineCSVScope struct {
	Organization string
	Project      string
	Environment  string
	App          string
}

type TimelineCSVReport struct {
	GeneratedAt time.Time
	Tool        ToolInfo
	Scope       TimelineCSVScope
	EventCount  int
	Events      []TimelineCSVRecord
}

type TimelineCSVRecord struct {
	ID          string
	BatchID     string
	App         string
	Service     string
	Host        string
	Hostname    string
	Agent       string
	EventTime   time.Time
	ReceivedAt  time.Time
	Type        string
	Target      string
	Severity    string
	Message     string
	Region      string
	LabelsJSON  string
	PayloadJSON string
}

func BuildTimelineCSVReport(meta domain.AppMeta, scope TimelineCSVScope, events []domain.TimelineEvent, generatedAt time.Time) TimelineCSVReport {
	items := slices.Clone(events)
	slices.SortFunc(items, func(a domain.TimelineEvent, b domain.TimelineEvent) int {
		if !a.EventTime.Equal(b.EventTime) {
			if a.EventTime.Before(b.EventTime) {
				return -1
			}
			return 1
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			if a.CreatedAt.Before(b.CreatedAt) {
				return -1
			}
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})

	records := make([]TimelineCSVRecord, 0, len(items))
	for _, event := range items {
		records = append(records, timelineCSVRecord(event))
	}
	return TimelineCSVReport{
		GeneratedAt: generatedAt.UTC(),
		Tool: ToolInfo{
			Name:      meta.Name,
			Binary:    meta.Binary,
			Version:   meta.Version,
			Commit:    meta.Commit,
			BuildDate: meta.BuildDate,
		},
		Scope:      scope,
		EventCount: len(records),
		Events:     records,
	}
}

func WriteTimelineCSV(w io.Writer, report TimelineCSVReport) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{
		"event_time",
		"received_time",
		"organization",
		"project",
		"environment",
		"app",
		"service",
		"host",
		"hostname",
		"agent",
		"severity",
		"type",
		"target",
		"message",
		"region",
		"event_id",
		"batch_id",
		"labels",
		"payload",
		"report_generated_at",
	}); err != nil {
		return err
	}
	for _, event := range report.Events {
		if err := writer.Write([]string{
			csvTime(event.EventTime),
			csvTime(event.ReceivedAt),
			report.Scope.Organization,
			report.Scope.Project,
			report.Scope.Environment,
			event.App,
			event.Service,
			event.Host,
			event.Hostname,
			event.Agent,
			event.Severity,
			event.Type,
			event.Target,
			event.Message,
			event.Region,
			event.ID,
			event.BatchID,
			event.LabelsJSON,
			event.PayloadJSON,
			csvTime(report.GeneratedAt),
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func timelineCSVRecord(event domain.TimelineEvent) TimelineCSVRecord {
	return TimelineCSVRecord{
		ID:          string(event.ID),
		BatchID:     string(event.BatchID),
		App:         event.AppSlug,
		Service:     event.ServiceSlug,
		Host:        event.HostSlug,
		Hostname:    event.Hostname,
		Agent:       event.AgentExternalID,
		EventTime:   event.EventTime.UTC(),
		ReceivedAt:  event.ReceivedAt.UTC(),
		Type:        event.EventType,
		Target:      event.Target,
		Severity:    string(event.Severity),
		Message:     event.Message,
		Region:      event.Region,
		LabelsJSON:  csvJSON(event.Labels),
		PayloadJSON: csvJSON(event.Payload),
	}
}

func csvJSON(value any) string {
	if value == nil {
		return "{}"
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	if string(bytes) == "null" {
		return "{}"
	}
	return string(bytes)
}

func csvTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
