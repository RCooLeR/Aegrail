package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type IngestEventsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	ServiceSlug      string
	HostSlug         string
	AgentID          string
	ExternalBatchID  string
	Source           string
	Signature        string
	Region           string
	Labels           map[string]string
	Events           []IngestEventInput
}

type IngestEventInput struct {
	EventTime time.Time
	Type      string
	Target    string
	Severity  string
	Message   string
	Region    string
	Labels    map[string]string
	Payload   map[string]any
}

type IngestEventsResult struct {
	Batch  domain.IngestBatch
	Events []domain.IngestEvent
	Reused bool
}

const (
	autoCorrelationLookback = 30 * time.Minute
	autoCorrelationWindow   = 30 * time.Minute
	autoCorrelationLimit    = 5000
)

func (h *Hub) IngestEvents(ctx context.Context, input IngestEventsInput) (IngestEventsResult, error) {
	if h.ingest == nil {
		return IngestEventsResult{}, errors.New("ingest repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return IngestEventsResult{}, err
	}

	externalID := strings.TrimSpace(input.ExternalBatchID)
	if externalID == "" {
		return IngestEventsResult{}, errors.New("external batch id is required")
	}
	if len(input.Events) == 0 {
		return IngestEventsResult{}, errors.New("at least one event is required")
	}

	org, err := h.resolveOrganization(ctx, input.OrganizationSlug)
	if err != nil {
		return IngestEventsResult{}, err
	}
	project, err := h.resolveProjectPath(ctx, input.OrganizationSlug, input.ProjectSlug)
	if err != nil {
		return IngestEventsResult{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return IngestEventsResult{}, err
	}
	host, err := h.resolveHostPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.HostSlug)
	if err != nil {
		return IngestEventsResult{}, err
	}
	agent, err := h.resolveAgent(ctx, host.ID, input.AgentID)
	if err != nil {
		return IngestEventsResult{}, err
	}

	var appID domain.ID
	appSlug := strings.TrimSpace(input.AppSlug)
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return IngestEventsResult{}, err
		}
		appID = app.ID
		appSlug = app.Slug
	}

	var serviceID domain.ID
	if strings.TrimSpace(input.ServiceSlug) != "" {
		service, err := h.resolveServicePath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug, input.ServiceSlug)
		if err != nil {
			return IngestEventsResult{}, err
		}
		serviceID = service.ID
	}

	receivedAt := time.Now().UTC()
	batchLabels := cloneStringMap(input.Labels)
	events := make([]domain.IngestEvent, 0, len(input.Events))
	for _, eventInput := range input.Events {
		event, err := h.buildIngestEvent(eventInput, batchLabels, receivedAt)
		if err != nil {
			return IngestEventsResult{}, err
		}
		event.OrganizationID = org.ID
		event.ProjectID = project.ID
		event.EnvironmentID = environment.ID
		event.AppID = appID
		event.ServiceID = serviceID
		event.HostID = host.ID
		event.AgentID = agent.ID
		events = append(events, event)
	}

	bodyHash, err := hashEvents(events)
	if err != nil {
		return IngestEventsResult{}, err
	}
	batch := domain.IngestBatch{
		ExternalID:     externalID,
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  environment.ID,
		AppID:          appID,
		ServiceID:      serviceID,
		HostID:         host.ID,
		AgentID:        agent.ID,
		Source:         strings.TrimSpace(input.Source),
		BodySHA256:     bodyHash,
		Signature:      strings.TrimSpace(input.Signature),
		Status:         "accepted",
		EventCount:     len(events),
		ReceivedAt:     receivedAt,
		Metadata: map[string]any{
			"labels": batchLabels,
		},
	}

	savedBatch, savedEvents, created, err := h.ingest.SaveIngestBatch(ctx, batch, events)
	if err != nil {
		return IngestEventsResult{}, err
	}
	if created {
		if !h.enqueueAutoCorrelation(ctx, org.Slug, project.Slug, environment.Slug, appSlug, savedEvents) {
			h.autoCorrelateIngestEvents(ctx, org.Slug, project.Slug, environment.Slug, appSlug, savedEvents)
		}
	}
	return IngestEventsResult{
		Batch:  savedBatch,
		Events: savedEvents,
		Reused: !created,
	}, nil
}

func (h *Hub) enqueueAutoCorrelation(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string, events []domain.IngestEvent) bool {
	if h.jobs == nil || h.findings == nil || len(events) == 0 || !shouldAutoCorrelateIngestEvents(events) {
		return false
	}
	since := earliestIngestEventTime(events)
	if since.IsZero() {
		since = time.Now().UTC()
	}
	payload, err := json.Marshal(ingestCorrelationJob{
		Schema:           ingestCorrelationJobSchema,
		OrganizationSlug: organizationSlug,
		ProjectSlug:      projectSlug,
		EnvironmentSlug:  environmentSlug,
		AppSlug:          appSlug,
		Since:            since.Add(-autoCorrelationLookback).UTC(),
		Window:           autoCorrelationWindow,
		Limit:            autoCorrelationLimit,
		QueuedAt:         time.Now().UTC(),
	})
	if err != nil {
		return false
	}
	return h.jobs.Enqueue(ctx, ingestCorrelationQueueName, payload) == nil
}

func (h *Hub) autoCorrelateIngestEvents(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string, events []domain.IngestEvent) {
	if h.findings == nil || len(events) == 0 || !shouldAutoCorrelateIngestEvents(events) {
		return
	}
	since := earliestIngestEventTime(events)
	if since.IsZero() {
		since = time.Now().UTC()
	}
	if _, err := h.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: organizationSlug,
		ProjectSlug:      projectSlug,
		EnvironmentSlug:  environmentSlug,
		AppSlug:          appSlug,
		Since:            since.Add(-autoCorrelationLookback),
		Window:           autoCorrelationWindow,
		Limit:            autoCorrelationLimit,
		SaveFindings:     true,
	}); err != nil && h.backgroundError != nil {
		h.backgroundError(err)
	}
}

func shouldAutoCorrelateIngestEvents(events []domain.IngestEvent) bool {
	for _, event := range events {
		eventType := strings.ToLower(strings.TrimSpace(event.EventType))
		if strings.HasPrefix(eventType, "db.") ||
			isFileMutationEventType(eventType) ||
			eventType == "log.access" ||
			eventType == "log.php_error" {
			return true
		}
	}
	return false
}

func isFileMutationEventType(eventType string) bool {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "file.created", "file.modified", "file.deleted":
		return true
	default:
		return false
	}
}

func earliestIngestEventTime(events []domain.IngestEvent) time.Time {
	var earliest time.Time
	for _, event := range events {
		if event.EventTime.IsZero() {
			continue
		}
		if earliest.IsZero() || event.EventTime.Before(earliest) {
			earliest = event.EventTime
		}
	}
	return earliest
}

func (h *Hub) ListIngestBatches(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, limit int) ([]domain.IngestBatch, error) {
	if h.ingest == nil {
		return nil, errors.New("ingest repository is not configured")
	}
	environment, err := h.resolveEnvironmentPath(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return nil, err
	}
	return h.ingest.ListIngestBatches(ctx, environment.ID, limit)
}

func (h *Hub) buildIngestEvent(input IngestEventInput, batchLabels map[string]string, receivedAt time.Time) (domain.IngestEvent, error) {
	eventType := strings.TrimSpace(input.Type)
	if eventType == "" {
		return domain.IngestEvent{}, errors.New("event type is required")
	}
	severity, err := normalizeSeverity(input.Severity)
	if err != nil {
		return domain.IngestEvent{}, err
	}
	eventTime := input.EventTime
	if eventTime.IsZero() {
		eventTime = receivedAt
	}
	labels := cloneStringMap(batchLabels)
	for key, value := range input.Labels {
		key = strings.TrimSpace(key)
		if key != "" {
			labels[key] = strings.TrimSpace(value)
		}
	}
	payload := input.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	region := strings.TrimSpace(input.Region)
	return domain.IngestEvent{
		EventTime:  eventTime.UTC(),
		ReceivedAt: receivedAt,
		EventType:  eventType,
		Target:     strings.TrimSpace(input.Target),
		Severity:   severity,
		Message:    strings.TrimSpace(input.Message),
		Region:     region,
		Labels:     labels,
		Payload:    payload,
	}, nil
}

func (h *Hub) resolveServicePath(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string, serviceSlug string) (domain.Service, error) {
	app, err := h.resolveAppPath(ctx, organizationSlug, projectSlug, environmentSlug, appSlug)
	if err != nil {
		return domain.Service{}, err
	}
	slug, err := domain.NormalizeSlug("service", serviceSlug)
	if err != nil {
		return domain.Service{}, err
	}
	service, ok, err := h.inventory.FindServiceBySlug(ctx, app.ID, slug)
	if err != nil {
		return domain.Service{}, err
	}
	if !ok {
		return domain.Service{}, fmt.Errorf("service %q does not exist in app %q", slug, app.Slug)
	}
	return service, nil
}

func (h *Hub) resolveAgent(ctx context.Context, hostID domain.ID, agentID string) (domain.Agent, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return domain.Agent{}, errors.New("agent id is required")
	}
	agent, ok, err := h.inventory.FindAgentByAgentID(ctx, agentID)
	if err != nil {
		return domain.Agent{}, err
	}
	if !ok {
		return domain.Agent{}, fmt.Errorf("agent %q does not exist", agentID)
	}
	if agent.HostID != hostID {
		return domain.Agent{}, fmt.Errorf("agent %q is not registered to the selected host", agentID)
	}
	return agent, nil
}

func normalizeSeverity(value string) (domain.Severity, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return domain.SeverityInfo, nil
	}
	severity := domain.Severity(value)
	switch severity {
	case domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical:
		return severity, nil
	default:
		return "", fmt.Errorf("severity %q is not supported", value)
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			clone[key] = strings.TrimSpace(value)
		}
	}
	return clone
}

func hashEvents(events []domain.IngestEvent) (string, error) {
	bytes, err := json.Marshal(events)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
