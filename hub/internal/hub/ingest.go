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
	"github.com/rcooler/aegrail/hub/internal/ports"
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
	autoCorrelationLookback           = 30 * time.Minute
	autoCorrelationWindow             = 30 * time.Minute
	autoCorrelationLimit              = 5000
	autoCorrelationEnqueueMinInterval = 30 * time.Second
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

	scope, err := h.resolveIngestScope(ctx, input)
	if err != nil {
		return IngestEventsResult{}, err
	}

	receivedAt := time.Now().UTC()
	batchLabels := cloneStringMap(input.Labels)
	events := make([]domain.IngestEvent, 0, len(input.Events))
	for _, eventInput := range input.Events {
		event, err := h.buildIngestEvent(eventInput, batchLabels, receivedAt)
		if err != nil {
			return IngestEventsResult{}, err
		}
		event.OrganizationID = scope.Organization.ID
		event.ProjectID = scope.Project.ID
		event.EnvironmentID = scope.Environment.ID
		event.AppID = scope.App.ID
		event.ServiceID = scope.Service.ID
		event.HostID = scope.Host.ID
		event.AgentID = scope.Agent.ID
		events = append(events, event)
	}

	bodyHash, err := hashEvents(events)
	if err != nil {
		return IngestEventsResult{}, err
	}
	batch := domain.IngestBatch{
		ExternalID:     externalID,
		OrganizationID: scope.Organization.ID,
		ProjectID:      scope.Project.ID,
		EnvironmentID:  scope.Environment.ID,
		AppID:          scope.App.ID,
		ServiceID:      scope.Service.ID,
		HostID:         scope.Host.ID,
		AgentID:        scope.Agent.ID,
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
		if h.jobs != nil && h.findings != nil && shouldAutoCorrelateIngestEvents(savedEvents) {
			h.enqueueAutoCorrelation(ctx, scope.Organization.Slug, scope.Project.Slug, scope.Environment.Slug, scope.App.Slug, savedEvents)
		} else {
			h.autoCorrelateIngestEvents(ctx, scope.Organization.Slug, scope.Project.Slug, scope.Environment.Slug, scope.App.Slug, savedEvents)
		}
	}
	return IngestEventsResult{
		Batch:  savedBatch,
		Events: savedEvents,
		Reused: !created,
	}, nil
}

func (h *Hub) resolveIngestScope(ctx context.Context, input IngestEventsInput) (ports.InventoryIngestScopePath, error) {
	orgSlug := strings.TrimSpace(input.OrganizationSlug)
	projectSlug := strings.TrimSpace(input.ProjectSlug)
	environmentSlug := strings.TrimSpace(input.EnvironmentSlug)
	hostSlug := strings.TrimSpace(input.HostSlug)
	agentID := strings.TrimSpace(input.AgentID)
	appSlug := strings.TrimSpace(input.AppSlug)
	serviceSlug := strings.TrimSpace(input.ServiceSlug)

	if scopeRepository, ok := h.inventory.(ports.InventoryIngestScopeRepository); ok {
		scope, found, err := scopeRepository.GetInventoryIngestScope(ctx, orgSlug, projectSlug, environmentSlug, hostSlug, agentID, appSlug, serviceSlug)
		if err != nil {
			return ports.InventoryIngestScopePath{}, err
		}
		if found {
			return scope, nil
		}
	}

	org, err := h.resolveOrganization(ctx, orgSlug)
	if err != nil {
		return ports.InventoryIngestScopePath{}, err
	}
	project, err := h.resolveProjectPath(ctx, orgSlug, projectSlug)
	if err != nil {
		return ports.InventoryIngestScopePath{}, err
	}
	environment, err := h.resolveEnvironmentPath(ctx, orgSlug, projectSlug, environmentSlug)
	if err != nil {
		return ports.InventoryIngestScopePath{}, err
	}
	host, err := h.resolveHostPath(ctx, orgSlug, projectSlug, environmentSlug, hostSlug)
	if err != nil {
		return ports.InventoryIngestScopePath{}, err
	}
	agent, err := h.resolveAgent(ctx, host.ID, agentID)
	if err != nil {
		return ports.InventoryIngestScopePath{}, err
	}

	var app domain.MonitoredApp
	if appSlug != "" {
		app, err = h.resolveAppPath(ctx, orgSlug, projectSlug, environmentSlug, appSlug)
		if err != nil {
			return ports.InventoryIngestScopePath{}, err
		}
	}

	var service domain.Service
	if serviceSlug != "" {
		service, err = h.resolveServicePath(ctx, orgSlug, projectSlug, environmentSlug, appSlug, serviceSlug)
		if err != nil {
			return ports.InventoryIngestScopePath{}, err
		}
	}

	return ports.InventoryIngestScopePath{
		Organization: org,
		Project:      project,
		Environment:  environment,
		Host:         host,
		Agent:        agent,
		App:          app,
		Service:      service,
	}, nil
}

func (h *Hub) enqueueAutoCorrelation(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string, events []domain.IngestEvent) bool {
	if h.jobs == nil || h.findings == nil || len(events) == 0 || !shouldAutoCorrelateIngestEvents(events) {
		return false
	}
	queuedAt := time.Now().UTC()
	if !h.reserveAutoCorrelationEnqueue(autoCorrelationScopeKey(organizationSlug, projectSlug, environmentSlug, appSlug), queuedAt) {
		return true
	}
	since := earliestIngestEventTime(events)
	if since.IsZero() {
		since = queuedAt
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
		QueuedAt:         queuedAt,
	})
	if err != nil {
		return false
	}
	if err := h.jobs.Enqueue(ctx, ingestCorrelationQueueName, payload); err != nil {
		h.releaseAutoCorrelationEnqueue(autoCorrelationScopeKey(organizationSlug, projectSlug, environmentSlug, appSlug), queuedAt)
		if h.backgroundError != nil {
			h.backgroundError(err)
		}
		return false
	}
	return true
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
			eventType == "log.php_error" ||
			(eventType == "log.access" && isIngestLogAccessCorrelationCandidate(event)) {
			return true
		}
	}
	return false
}

func (h *Hub) reserveAutoCorrelationEnqueue(scopeKey string, now time.Time) bool {
	if h == nil {
		return false
	}
	h.correlationEnqueueMu.Lock()
	defer h.correlationEnqueueMu.Unlock()
	if h.correlationEnqueueLast == nil {
		h.correlationEnqueueLast = map[string]time.Time{}
	}
	if previous := h.correlationEnqueueLast[scopeKey]; !previous.IsZero() && now.Sub(previous) < autoCorrelationEnqueueMinInterval {
		return false
	}
	h.correlationEnqueueLast[scopeKey] = now
	if len(h.correlationEnqueueLast) > 1024 {
		for key, value := range h.correlationEnqueueLast {
			if now.Sub(value) > 10*autoCorrelationEnqueueMinInterval {
				delete(h.correlationEnqueueLast, key)
			}
		}
	}
	return true
}

func (h *Hub) releaseAutoCorrelationEnqueue(scopeKey string, reservedAt time.Time) {
	if h == nil {
		return
	}
	h.correlationEnqueueMu.Lock()
	defer h.correlationEnqueueMu.Unlock()
	if h.correlationEnqueueLast == nil {
		return
	}
	if h.correlationEnqueueLast[scopeKey].Equal(reservedAt) {
		delete(h.correlationEnqueueLast, scopeKey)
	}
}

func (h *Hub) reserveAutoCorrelationRun(scopeKey string, now time.Time) bool {
	if h == nil {
		return false
	}
	h.correlationRunMu.Lock()
	defer h.correlationRunMu.Unlock()
	if h.correlationRunLast == nil {
		h.correlationRunLast = map[string]time.Time{}
	}
	if previous := h.correlationRunLast[scopeKey]; !previous.IsZero() && now.Sub(previous) < autoCorrelationEnqueueMinInterval {
		return false
	}
	h.correlationRunLast[scopeKey] = now
	if len(h.correlationRunLast) > 1024 {
		for key, value := range h.correlationRunLast {
			if now.Sub(value) > 10*autoCorrelationEnqueueMinInterval {
				delete(h.correlationRunLast, key)
			}
		}
	}
	return true
}

func autoCorrelationScopeKey(organizationSlug string, projectSlug string, environmentSlug string, appSlug string) string {
	return strings.Join([]string{
		strings.TrimSpace(organizationSlug),
		strings.TrimSpace(projectSlug),
		strings.TrimSpace(environmentSlug),
		strings.TrimSpace(appSlug),
	}, "\x00")
}

func isIngestLogAccessCorrelationCandidate(event domain.IngestEvent) bool {
	status := payloadInt(event.Payload, "status_code")
	method := strings.ToUpper(strings.TrimSpace(payloadStringAny(event.Payload, "method", "")))
	path := strings.ToLower(payloadStringAny(event.Payload, "path", event.Target))
	remoteNetwork := strings.ToLower(payloadStringAny(event.Payload, "remote_network", ""))
	if remoteNetwork == "tor_exit" || payloadBoolAny(event.Payload, "remote_is_tor") {
		return true
	}
	if isRoutineLocalizedRestAPIAccess(path, method, status, event.Payload) {
		return false
	}
	if status >= 500 || status == 401 || status == 403 {
		return true
	}
	if isAdminLikePath(path) {
		return true
	}
	return method == "POST" && (strings.Contains(path, "login") || strings.Contains(path, "password") || strings.Contains(path, "reset"))
}

func payloadBoolAny(payload map[string]any, key string) bool {
	switch value := payload[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "1", "yes":
			return true
		default:
			return false
		}
	default:
		return false
	}
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
		return domain.Service{}, fmt.Errorf("%w: service %q does not exist in app %q", ErrHubNotFound, slug, app.Slug)
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
		return domain.Agent{}, fmt.Errorf("%w: agent %q does not exist", ErrHubNotFound, agentID)
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
