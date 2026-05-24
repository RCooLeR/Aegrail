package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

type CorrelateEventsInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Since            time.Time
	Window           time.Duration
	Limit            int
	SaveFindings     bool
}

type CorrelateEventsResult struct {
	Organization domain.Organization
	Project      domain.Project
	Environment  domain.Environment
	App          domain.MonitoredApp
	Since        time.Time
	Window       time.Duration
	Events       int
	Chains       []CorrelationChain
	Findings     []domain.HubFinding
}

type CorrelationChain struct {
	ID         string
	RuleID     string
	Title      string
	Severity   domain.Severity
	Confidence domain.Confidence
	Summary    string
	Events     []CorrelationEvent
	Metadata   map[string]any
}

type CorrelationEvent struct {
	EventID   domain.ID
	EventTime time.Time
	HostSlug  string
	EventType string
	Target    string
	Severity  domain.Severity
	Message   string
}

const correlationRuleVersion = currentRuleVersion

func (h *Hub) CorrelateEvents(ctx context.Context, input CorrelateEventsInput) (CorrelateEventsResult, error) {
	if h.ingest == nil {
		return CorrelateEventsResult{}, errors.New("ingest repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return CorrelateEventsResult{}, err
	}
	org, project, environment, err := h.resolveEnvironmentContext(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return CorrelateEventsResult{}, err
	}
	var app domain.MonitoredApp
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err = h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return CorrelateEventsResult{}, err
		}
		appID = app.ID
	}
	window := input.Window
	if window <= 0 {
		window = 30 * time.Minute
	}

	events, err := h.listCorrelationTimelineEvents(ctx, environment.ID, appID, input.Since, input.Limit)
	if err != nil {
		return CorrelateEventsResult{}, err
	}
	if h.fileIgnoreRules != nil {
		ignoreRules, err := h.fileIgnoreRules.ListActiveHubFileIgnoreRules(ctx, environment.ID, appID)
		if err != nil {
			return CorrelateEventsResult{}, err
		}
		events = filterIgnoredTimelineEvents(events, ignoreRules)
	}
	chains := correlateTimelineEvents(events, window)
	findings := correlationFindings(org, project, environment, app, chains)
	findings, err = h.applyDeploymentContextToFindings(ctx, environment.ID, appID, findings)
	if err != nil {
		return CorrelateEventsResult{}, err
	}
	findings = filterDeploymentExpectedFindings(findings)
	findings = applyRiskScoringToFindings(findings)
	if input.SaveFindings && len(findings) > 0 {
		if h.findings == nil {
			return CorrelateEventsResult{}, errors.New("finding repository is not configured")
		}
		findings, err = h.findings.SaveHubFindings(ctx, findings)
		if err != nil {
			return CorrelateEventsResult{}, err
		}
		if err := h.notifyHubFindings(ctx, "finding.observed", findings, map[string]any{"source": "correlation"}); err != nil {
			return CorrelateEventsResult{}, err
		}
	}
	return CorrelateEventsResult{
		Organization: org,
		Project:      project,
		Environment:  environment,
		App:          app,
		Since:        input.Since,
		Window:       window,
		Events:       len(events),
		Chains:       chains,
		Findings:     findings,
	}, nil
}

func (h *Hub) listCorrelationTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error) {
	if repository, ok := h.ingest.(ports.IngestCorrelationTimelineRepository); ok {
		return repository.ListCorrelationTimelineEvents(ctx, environmentID, appID, since, limit)
	}
	events, err := h.ingest.ListTimelineEvents(ctx, environmentID, appID, since, limit)
	if err != nil {
		return nil, err
	}
	return filterCorrelationCandidateTimelineEvents(events), nil
}

func filterCorrelationCandidateTimelineEvents(events []domain.TimelineEvent) []domain.TimelineEvent {
	if len(events) == 0 {
		return events
	}
	filtered := events[:0]
	for _, event := range events {
		if isCorrelationCandidateTimelineEvent(event) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func isCorrelationCandidateTimelineEvent(event domain.TimelineEvent) bool {
	eventType := strings.ToLower(strings.TrimSpace(event.EventType))
	if strings.HasPrefix(eventType, "db.") ||
		isFileMutationEventType(eventType) ||
		eventType == "log.php_error" {
		return true
	}
	if eventType != "log.access" {
		return false
	}
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
	if status >= 400 {
		return true
	}
	if isAdminLikePath(path) {
		return true
	}
	return method == "POST" && (strings.Contains(path, "login") || strings.Contains(path, "password") || strings.Contains(path, "reset"))
}

func correlateTimelineEvents(events []domain.TimelineEvent, window time.Duration) []CorrelationChain {
	var chains []CorrelationChain
	seen := map[string]struct{}{}
	suppressedFollowups := map[string]struct{}{}
	coveredFileEvents := map[string]struct{}{}
	coveredWebEvents := map[string]struct{}{}
	for i, event := range events {
		if isDatabaseSnapshotDiffEvent(event) {
			addCorrelationChain(&chains, seen, buildDatabaseSnapshotDiffChain(event))
		}

		if isSuspiciousWebEvent(event) {
			fileEvent, fileIndex, ok := findNextEventAt(events, i+1, event.EventTime.Add(window), func(candidate domain.TimelineEvent) bool {
				return isHighSignalFileEvent(candidate) && sameHostOrApp(event, candidate)
			})
			if ok {
				chainEvents := []domain.TimelineEvent{event, fileEvent}
				ruleID := "web-to-file-change"
				title := "Suspicious web activity followed by file change"
				tail, hasTail := findIncidentEscalationTail(events, fileIndex+1, fileEvent, window)
				if hasTail && isIncidentWebTrigger(event) && isIncidentFileEvent(fileEvent) {
					chainEvents = append(chainEvents, tail)
					ruleID = "probable-incident-chain"
					title = "Probable incident chain"
					suppressedFollowups[correlationPairKey(fileEvent, tail)] = struct{}{}
				}
				coveredFileEvents[correlationEventKey(fileEvent)] = struct{}{}
				coveredWebEvents[correlationEventKey(event)] = struct{}{}
				chain := buildCorrelationChain(ruleID, title, chainEvents)
				addCorrelationChain(&chains, seen, chain)
			}
		}

		if isHighSignalFileEvent(event) {
			if next, ok := findIncidentTail(events, i+1, event, window); ok {
				if _, suppressed := suppressedFollowups[correlationPairKey(event, next)]; suppressed {
					continue
				}
				ruleID := "file-change-to-sensitive-followup"
				title := "File change followed by sensitive follow-up"
				if isDatabaseSecurityEvent(next) {
					ruleID = "file-change-to-db-security-change"
					title = "File change followed by database security change"
				}
				if isPersistenceEvent(next) {
					ruleID = "file-change-to-persistence"
					title = "File change followed by persistence signal"
				}
				coveredFileEvents[correlationEventKey(event)] = struct{}{}
				addCorrelationChain(&chains, seen, buildCorrelationChain(ruleID, title, []domain.TimelineEvent{event, next}))
			}
		}
	}
	for _, chain := range buildSuspiciousFilePathChains(events, coveredFileEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range buildAdminRequestAnomalyChains(events, coveredWebEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range buildWebRequestTrafficChains(events, coveredWebEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	slices.SortFunc(chains, func(a CorrelationChain, b CorrelationChain) int {
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(b.Severity) - severityRank(a.Severity)
		}
		aTime := firstCorrelationEventTime(a)
		bTime := firstCorrelationEventTime(b)
		if aTime.Equal(bTime) {
			return strings.Compare(a.ID, b.ID)
		}
		if aTime.Before(bTime) {
			return -1
		}
		return 1
	})
	return chains
}

func firstCorrelationEventTime(chain CorrelationChain) time.Time {
	if len(chain.Events) == 0 {
		return time.Time{}
	}
	return chain.Events[0].EventTime
}

func correlationPairKey(a domain.TimelineEvent, b domain.TimelineEvent) string {
	return correlationEventKey(a) + "->" + correlationEventKey(b)
}

func correlationEventKey(event domain.TimelineEvent) string {
	if event.ID != "" {
		return string(event.ID)
	}
	return event.EventTime.Format(time.RFC3339Nano) + ":" + event.EventType + ":" + event.Target
}

func findIncidentTail(events []domain.TimelineEvent, start int, fileEvent domain.TimelineEvent, window time.Duration) (domain.TimelineEvent, bool) {
	return findNextEvent(events, start, fileEvent.EventTime.Add(window), func(candidate domain.TimelineEvent) bool {
		if !candidate.EventTime.After(fileEvent.EventTime) {
			return false
		}
		return isDatabaseSecurityEvent(candidate) || isPersistenceEvent(candidate)
	})
}

func findIncidentEscalationTail(events []domain.TimelineEvent, start int, fileEvent domain.TimelineEvent, window time.Duration) (domain.TimelineEvent, bool) {
	return findNextEvent(events, start, fileEvent.EventTime.Add(window), func(candidate domain.TimelineEvent) bool {
		if !candidate.EventTime.After(fileEvent.EventTime) {
			return false
		}
		return isDatabaseIdentitySecurityEvent(candidate) || isPersistenceEvent(candidate)
	})
}

func findNextEvent(events []domain.TimelineEvent, start int, until time.Time, match func(domain.TimelineEvent) bool) (domain.TimelineEvent, bool) {
	event, _, ok := findNextEventAt(events, start, until, match)
	return event, ok
}

func findNextEventAt(events []domain.TimelineEvent, start int, until time.Time, match func(domain.TimelineEvent) bool) (domain.TimelineEvent, int, bool) {
	for index := start; index < len(events); index++ {
		candidate := events[index]
		if candidate.EventTime.After(until) {
			break
		}
		if match(candidate) {
			return candidate, index, true
		}
	}
	return domain.TimelineEvent{}, -1, false
}

func isIncidentWebTrigger(event domain.TimelineEvent) bool {
	switch event.EventType {
	case "log.php_error":
		return severityRank(event.Severity) >= severityRank(domain.SeverityMedium)
	case "log.access":
		status := payloadInt(event.Payload, "status_code")
		method := strings.ToUpper(strings.TrimSpace(payloadStringAny(event.Payload, "method", "")))
		path := strings.ToLower(payloadStringAny(event.Payload, "path", event.Target))
		if status >= 500 {
			return true
		}
		if status == 401 || status == 403 {
			return isAdminLikePath(path)
		}
		return method == "POST" && status >= 200 && status < 400 && isAdminLikePath(path)
	default:
		return false
	}
}

func isSuspiciousWebEvent(event domain.TimelineEvent) bool {
	switch event.EventType {
	case "log.php_error":
		return severityRank(event.Severity) >= severityRank(domain.SeverityMedium)
	case "log.access":
		status := payloadInt(event.Payload, "status_code")
		method := strings.ToUpper(strings.TrimSpace(payloadStringAny(event.Payload, "method", "")))
		path := strings.ToLower(payloadStringAny(event.Payload, "path", event.Target))
		if isRoutineLocalizedRestAPIAccess(path, method, status, event.Payload) {
			return false
		}
		return status >= 500 ||
			status == 401 ||
			status == 403 ||
			isAdminLikePath(path)
	default:
		return false
	}
}

func isAdminLikePath(path string) bool {
	return strings.Contains(path, "wp-login") ||
		strings.Contains(path, "admin") ||
		strings.Contains(path, "login")
}

func isHighSignalFileEvent(event domain.TimelineEvent) bool {
	if !isFileMutationEventType(event.EventType) {
		return false
	}
	path := strings.ToLower(payloadStringAny(event.Payload, "relative_path", event.Target))
	if path == "" {
		path = strings.ToLower(event.Target)
	}
	return severityRank(event.Severity) >= severityRank(domain.SeverityMedium) ||
		(strings.Contains(path, "upload") && looksPHP(path)) ||
		strings.Contains(path, "wp-config.php") ||
		strings.Contains(path, "settings.inc.php") ||
		strings.Contains(path, "/.env") ||
		strings.Contains(path, "plugins/") ||
		strings.Contains(path, "themes/") ||
		strings.Contains(path, "modules/")
}

func isIncidentFileEvent(event domain.TimelineEvent) bool {
	if !isFileMutationEventType(event.EventType) {
		return false
	}
	path := strings.ToLower(payloadStringAny(event.Payload, "relative_path", event.Target))
	if path == "" {
		path = strings.ToLower(event.Target)
	}
	if severityRank(event.Severity) >= severityRank(domain.SeverityHigh) {
		return true
	}
	return (looksPHP(path) && isWritableWebPath(path)) ||
		isSensitiveConfigPath(path) ||
		isSuspiciousExecutablePath(path)
}

func isWritableWebPath(path string) bool {
	normalized := strings.Trim(strings.ReplaceAll(path, "\\", "/"), "/")
	return strings.Contains(normalized, "/upload") ||
		strings.Contains(normalized, "uploads/") ||
		strings.Contains(normalized, "/media/") ||
		strings.Contains(normalized, "/cache/") ||
		strings.Contains(normalized, "/tmp/") ||
		strings.Contains(normalized, "/temp/")
}

func isSensitiveConfigPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	return strings.Contains(normalized, "wp-config.php") ||
		strings.Contains(normalized, "wp-config-local.php") ||
		strings.Contains(normalized, "settings.inc.php") ||
		strings.Contains(normalized, "/.env") ||
		strings.HasSuffix(normalized, ".env")
}

func isSuspiciousExecutablePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if !looksPHP(normalized) {
		return false
	}
	return strings.Contains(normalized, "shell") ||
		strings.Contains(normalized, "backdoor") ||
		strings.Contains(normalized, "wso") ||
		strings.Contains(normalized, "c99") ||
		strings.Contains(normalized, "r57")
}

func isDatabaseSecurityEvent(event domain.TimelineEvent) bool {
	if !strings.HasPrefix(event.EventType, "db.") {
		return false
	}
	if isDatabaseSnapshotDiffEvent(event) {
		return true
	}
	if !isDatabaseChangeEventType(event.EventType) {
		return false
	}
	lower := strings.ToLower(event.EventType + " " + event.Message + " " + event.Target)
	return strings.Contains(lower, "role") ||
		strings.Contains(lower, "privilege") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "admin") ||
		strings.Contains(lower, "user") ||
		strings.Contains(lower, "capabilities") ||
		strings.Contains(lower, "plugin") ||
		strings.Contains(lower, "theme") ||
		strings.Contains(lower, "module") ||
		strings.Contains(lower, "employee") ||
		strings.Contains(lower, "configuration") ||
		strings.Contains(lower, "access") ||
		strings.Contains(lower, "schema") ||
		strings.Contains(lower, "api") ||
		strings.Contains(lower, "webhook") ||
		strings.Contains(lower, "payment") ||
		strings.Contains(lower, "email")
}

func isDatabaseIdentitySecurityEvent(event domain.TimelineEvent) bool {
	if !strings.HasPrefix(event.EventType, "db.") {
		return false
	}
	if !isDatabaseChangeEventType(event.EventType) {
		return false
	}
	lower := strings.ToLower(event.EventType + " " + event.Message + " " + event.Target)
	return strings.Contains(lower, "role") ||
		strings.Contains(lower, "privilege") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "admin") ||
		strings.Contains(lower, "user") ||
		strings.Contains(lower, "capabilities") ||
		strings.Contains(lower, "employee") ||
		strings.Contains(lower, "access") ||
		strings.Contains(lower, "oauth") ||
		strings.Contains(lower, "webhook") ||
		strings.Contains(lower, "api key")
}

func isDatabaseChangeEventType(eventType string) bool {
	lower := strings.ToLower(eventType)
	return strings.Contains(lower, "changed") ||
		strings.Contains(lower, "created") ||
		strings.Contains(lower, "added") ||
		strings.Contains(lower, "removed") ||
		strings.Contains(lower, "deleted") ||
		strings.Contains(lower, "granted") ||
		strings.Contains(lower, "revoked")
}

func isPersistenceEvent(event domain.TimelineEvent) bool {
	lower := strings.ToLower(event.EventType + " " + event.Message + " " + event.Target)
	return strings.Contains(lower, "cron.") ||
		strings.Contains(lower, "cron ") ||
		strings.Contains(lower, "scheduled_task") ||
		strings.Contains(lower, "service.created") ||
		strings.Contains(lower, "service.modified") ||
		strings.Contains(lower, "systemd") ||
		strings.Contains(lower, "process.created")
}

func sameHostOrApp(a domain.TimelineEvent, b domain.TimelineEvent) bool {
	return a.HostID == b.HostID || a.AppID == "" || b.AppID == "" || a.AppID == b.AppID
}

func buildCorrelationChain(ruleID string, title string, events []domain.TimelineEvent) CorrelationChain {
	chainEvents := make([]CorrelationEvent, 0, len(events))
	for _, event := range events {
		chainEvents = append(chainEvents, CorrelationEvent{
			EventID:   event.ID,
			EventTime: event.EventTime,
			HostSlug:  event.HostSlug,
			EventType: event.EventType,
			Target:    event.Target,
			Severity:  event.Severity,
			Message:   event.Message,
		})
	}
	severity := maxTimelineSeverity(events)
	confidence := domain.ConfidenceMedium
	if len(events) >= 3 {
		confidence = domain.ConfidenceHigh
		if severityRank(severity) < severityRank(domain.SeverityHigh) {
			severity = domain.SeverityHigh
		}
	}
	return CorrelationChain{
		ID:         correlationID(ruleID, events),
		RuleID:     ruleID,
		Title:      title,
		Severity:   severity,
		Confidence: confidence,
		Summary:    correlationSummary(events),
		Events:     chainEvents,
	}
}

func addCorrelationChain(chains *[]CorrelationChain, seen map[string]struct{}, chain CorrelationChain) {
	if _, ok := seen[chain.ID]; ok {
		return
	}
	seen[chain.ID] = struct{}{}
	*chains = append(*chains, chain)
}

func correlationID(ruleID string, events []domain.TimelineEvent) string {
	parts := []string{ruleID}
	for _, event := range events {
		id := string(event.ID)
		if id == "" {
			id = event.EventTime.Format(time.RFC3339Nano) + ":" + event.EventType + ":" + event.Target
		}
		parts = append(parts, id)
	}
	return "corr-" + sha256Short(strings.Join(parts, "\n"))
}

func correlationSummary(events []domain.TimelineEvent) string {
	parts := make([]string, 0, len(events))
	for _, event := range events {
		host := event.HostSlug
		if host == "" {
			host = "unknown-host"
		}
		target := event.Target
		if target == "" {
			target = event.Message
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", host, event.EventType, target))
	}
	return strings.Join(parts, " -> ")
}

func maxTimelineSeverity(events []domain.TimelineEvent) domain.Severity {
	max := domain.SeverityInfo
	for _, event := range events {
		if severityRank(event.Severity) > severityRank(max) {
			max = event.Severity
		}
	}
	return max
}

func looksPHP(path string) bool {
	return strings.HasSuffix(path, ".php") ||
		strings.HasSuffix(path, ".phtml") ||
		strings.HasSuffix(path, ".phar")
}

func payloadStringAny(payload map[string]any, key string, fallback string) string {
	value, ok := payload[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func payloadInt(payload map[string]any, key string) int {
	switch value := payload[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		var parsed int
		_, _ = fmt.Sscanf(value, "%d", &parsed)
		return parsed
	default:
		return 0
	}
}

func sha256Short(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:24]
}

func correlationFindings(org domain.Organization, project domain.Project, environment domain.Environment, app domain.MonitoredApp, chains []CorrelationChain) []domain.HubFinding {
	findings := make([]domain.HubFinding, 0, len(chains))
	for _, chain := range chains {
		if len(chain.Events) == 0 {
			continue
		}
		eventIDs := make([]domain.ID, 0, len(chain.Events))
		for _, event := range chain.Events {
			if event.EventID != "" {
				eventIDs = append(eventIDs, event.EventID)
			}
		}
		findings = append(findings, domain.HubFinding{
			OrganizationID: org.ID,
			ProjectID:      project.ID,
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         chain.RuleID,
			RuleVersion:    ruleVersion(chain.RuleID),
			DedupeKey:      chain.ID,
			Severity:       chain.Severity,
			Confidence:     chain.Confidence,
			Title:          chain.Title,
			Summary:        chain.Summary,
			Description:    correlationDescription(chain),
			EventIDs:       eventIDs,
			FirstEventAt:   chain.Events[0].EventTime,
			LastEventAt:    chain.Events[len(chain.Events)-1].EventTime,
			Metadata:       ruleMetadata(chain.RuleID, correlationMetadata(chain)),
		})
	}
	return findings
}

func correlationDescription(chain CorrelationChain) string {
	return fmt.Sprintf("Aegrail correlated %d timeline event(s): %s", len(chain.Events), chain.Summary)
}

func correlationMetadata(chain CorrelationChain) map[string]any {
	events := make([]map[string]any, 0, len(chain.Events))
	for _, event := range chain.Events {
		events = append(events, map[string]any{
			"event_id":   string(event.EventID),
			"event_time": event.EventTime.Format(time.RFC3339Nano),
			"host":       event.HostSlug,
			"type":       event.EventType,
			"target":     event.Target,
			"severity":   string(event.Severity),
			"message":    event.Message,
		})
	}
	metadata := cloneAnyMap(chain.Metadata)
	metadata["chain_id"] = chain.ID
	metadata["source"] = "hub.correlation"
	metadata["events"] = events
	return metadata
}
