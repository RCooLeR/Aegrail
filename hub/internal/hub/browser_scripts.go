package hub

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type ListBrowserScriptObservationsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	PageURL          string
	Kind             string
	Since            time.Time
	Limit            int
}

type BrowserScriptObservationRecord struct {
	EventID         domain.ID
	AppID           domain.ID
	AppSlug         string
	HostID          domain.ID
	HostSlug        string
	Hostname        string
	AgentID         domain.ID
	AgentExternalID string
	EventTime       time.Time
	ReceivedAt      time.Time
	EventType       string
	Target          string
	Severity        domain.Severity
	PageURL         string
	FinalURL        string
	Mode            string
	SourceType      string
	URL             string
	URLRedacted     string
	Domain          string
	Path            string
	SHA256          string
	InlineBytes     int
	InlinePreview   string
	InlineTruncated bool
	TagManager      bool
	TagManagerIDs   []string
	Labels          map[string]string
	Payload         map[string]any
}

func (h *Hub) ListBrowserScriptObservations(ctx context.Context, input ListBrowserScriptObservationsInput) ([]BrowserScriptObservationRecord, error) {
	if h.ingest == nil {
		return nil, errors.New("ingest repository is not configured")
	}
	timelineLimit := input.Limit
	if timelineLimit <= 0 || timelineLimit < 10000 {
		timelineLimit = 10000
	}
	events, err := h.listTimelineEventsByTypes(ctx, ListTimelineEventsInput{
		OrganizationSlug: input.OrganizationSlug,
		ProjectSlug:      input.ProjectSlug,
		EnvironmentSlug:  input.EnvironmentSlug,
		AppSlug:          input.AppSlug,
		Since:            input.Since,
	}, []string{"browser.script.observed", "browser.tag_manager.detected"}, timelineLimit)
	if err != nil {
		return nil, err
	}

	pageFilter := normalizeBrowserPageURL(input.PageURL)
	kindFilter := strings.ToLower(strings.TrimSpace(input.Kind))
	records := make([]BrowserScriptObservationRecord, 0, len(events))
	for _, event := range events {
		if !isBrowserScriptObservation(event) {
			continue
		}
		record := browserScriptObservationRecord(event)
		if pageFilter != "" && normalizeBrowserPageURL(record.PageURL) != pageFilter && normalizeBrowserPageURL(record.FinalURL) != pageFilter {
			continue
		}
		if kindFilter != "" && strings.ToLower(record.SourceType) != kindFilter && strings.ToLower(record.EventType) != kindFilter {
			continue
		}
		records = append(records, record)
	}
	slices.SortFunc(records, func(a BrowserScriptObservationRecord, b BrowserScriptObservationRecord) int {
		if a.EventTime.Equal(b.EventTime) {
			return strings.Compare(string(a.EventID), string(b.EventID))
		}
		if a.EventTime.After(b.EventTime) {
			return -1
		}
		return 1
	})
	if input.Limit > 0 && len(records) > input.Limit {
		records = records[:input.Limit]
	}
	return records, nil
}

func browserScriptObservationRecord(event domain.TimelineEvent) BrowserScriptObservationRecord {
	payload := cloneAnyMap(event.Payload)
	return BrowserScriptObservationRecord{
		EventID:         event.ID,
		AppID:           event.AppID,
		AppSlug:         event.AppSlug,
		HostID:          event.HostID,
		HostSlug:        event.HostSlug,
		Hostname:        event.Hostname,
		AgentID:         event.AgentID,
		AgentExternalID: event.AgentExternalID,
		EventTime:       event.EventTime,
		ReceivedAt:      event.ReceivedAt,
		EventType:       event.EventType,
		Target:          event.Target,
		Severity:        event.Severity,
		PageURL:         payloadStringAny(payload, "page_url", ""),
		FinalURL:        payloadStringAny(payload, "final_url", ""),
		Mode:            payloadStringAny(payload, "mode", ""),
		SourceType:      payloadStringAny(payload, "source_type", ""),
		URL:             payloadStringAny(payload, "url", ""),
		URLRedacted:     payloadStringAny(payload, "url_redacted", ""),
		Domain:          payloadStringAny(payload, "domain", ""),
		Path:            payloadStringAny(payload, "path", ""),
		SHA256:          payloadStringAny(payload, "sha256", ""),
		InlineBytes:     payloadInt(payload, "inline_bytes"),
		InlinePreview:   payloadStringAny(payload, "inline_preview", ""),
		InlineTruncated: payloadBool(payload, "inline_preview_truncated"),
		TagManager:      payloadBool(payload, "tag_manager"),
		TagManagerIDs:   payloadStringSlice(payload, "tag_manager_ids"),
		Labels:          cloneStringMap(event.Labels),
		Payload:         payload,
	}
}
