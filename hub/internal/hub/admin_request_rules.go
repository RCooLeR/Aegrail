package hub

import (
	"fmt"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

const (
	adminFailureBurstThreshold = 3
	adminLoginBurstThreshold   = 5
	adminAnomalyWindow         = 10 * time.Minute
)

type adminRequestObservation struct {
	Event             domain.TimelineEvent
	Key               string
	RemoteFingerprint string
	RemoteKnown       bool
	Method            string
	Path              string
	Status            int
}

type adminRequestRule struct {
	RuleID     string
	Title      string
	Severity   domain.Severity
	Confidence domain.Confidence
	Summary    string
	Events     []adminRequestObservation
}

func buildAdminRequestAnomalyChains(events []domain.TimelineEvent, coveredWebEvents map[string]struct{}) []CorrelationChain {
	observations := adminRequestObservations(events, coveredWebEvents)
	var chains []CorrelationChain
	seen := map[string]struct{}{}
	coveredAdminEvents := map[string]struct{}{}

	for _, chain := range adminSuccessAfterFailuresChains(observations, coveredAdminEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range adminBurstChains(observations, coveredAdminEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range adminToolProbeChains(observations, coveredAdminEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	return chains
}

func adminRequestObservations(events []domain.TimelineEvent, coveredWebEvents map[string]struct{}) []adminRequestObservation {
	observations := make([]adminRequestObservation, 0)
	for _, event := range events {
		if event.EventType != "log.access" {
			continue
		}
		if _, covered := coveredWebEvents[correlationEventKey(event)]; covered {
			continue
		}
		observation, ok := adminRequestObservationFromEvent(event)
		if !ok {
			continue
		}
		observations = append(observations, observation)
	}
	return observations
}

func adminRequestObservationFromEvent(event domain.TimelineEvent) (adminRequestObservation, bool) {
	path := normalizedRequestPath(payloadStringAny(event.Payload, "path", event.Target))
	if path == "" || !isAdminRequestPath(path) {
		return adminRequestObservation{}, false
	}
	method := strings.ToUpper(payloadStringAny(event.Payload, "method", ""))
	remoteFingerprint, remoteKnown := remoteAddressFingerprint(event.Payload)
	status := payloadInt(event.Payload, "status_code")
	return adminRequestObservation{
		Event:             event,
		Key:               correlationEventKey(event),
		RemoteFingerprint: remoteFingerprint,
		RemoteKnown:       remoteKnown,
		Method:            method,
		Path:              path,
		Status:            status,
	}, true
}

func adminSuccessAfterFailuresChains(observations []adminRequestObservation, covered map[string]struct{}) []CorrelationChain {
	var chains []CorrelationChain
	seenRemoteWindow := map[string]struct{}{}
	for index, observation := range observations {
		if !observation.RemoteKnown || !isAdminSuccessObservation(observation) || adminObservationCovered(observation, covered) {
			continue
		}
		start := observation.Event.EventTime.Add(-adminAnomalyWindow)
		failures := make([]adminRequestObservation, 0)
		for previousIndex := index - 1; previousIndex >= 0; previousIndex-- {
			previous := observations[previousIndex]
			if previous.Event.EventTime.Before(start) {
				break
			}
			if adminObservationCovered(previous, covered) ||
				previous.RemoteFingerprint != observation.RemoteFingerprint ||
				!isAdminFailureObservation(previous) {
				continue
			}
			failures = append(failures, previous)
		}
		if len(failures) < adminFailureBurstThreshold {
			continue
		}
		reverseAdminObservations(failures)
		ruleEvents := append(failures, observation)
		windowKey := observation.RemoteFingerprint + ":" + observation.Event.EventTime.Truncate(adminAnomalyWindow).Format(time.RFC3339)
		if _, ok := seenRemoteWindow[windowKey]; ok {
			continue
		}
		seenRemoteWindow[windowKey] = struct{}{}
		for _, item := range ruleEvents {
			covered[item.Key] = struct{}{}
		}
		chains = append(chains, buildAdminRequestChain(adminRequestRule{
			RuleID:     "web-admin-success-after-failures",
			Title:      "Admin request succeeded after failures",
			Severity:   domain.SeverityHigh,
			Confidence: domain.ConfidenceMedium,
			Summary:    fmt.Sprintf("admin request from remote %s succeeded after %d failed/probe request(s)", observation.RemoteFingerprint, len(failures)),
			Events:     ruleEvents,
		}))
	}
	return chains
}

func adminBurstChains(observations []adminRequestObservation, covered map[string]struct{}) []CorrelationChain {
	var chains []CorrelationChain
	chains = append(chains, adminBurstChainsByKind(observations, covered, "web-admin-failed-request-burst", "Admin failed request burst", adminFailureBurstThreshold, isAdminFailureObservation, domain.SeverityMedium, domain.ConfidenceHigh)...)
	chains = append(chains, adminBurstChainsByKind(observations, covered, "web-admin-login-post-burst", "Admin login POST burst", adminLoginBurstThreshold, isAdminLoginPostObservation, domain.SeverityMedium, domain.ConfidenceMedium)...)
	return chains
}

func adminBurstChainsByKind(observations []adminRequestObservation, covered map[string]struct{}, ruleID string, title string, threshold int, match func(adminRequestObservation) bool, severity domain.Severity, confidence domain.Confidence) []CorrelationChain {
	var chains []CorrelationChain
	for index, observation := range observations {
		if !observation.RemoteKnown || adminObservationCovered(observation, covered) || !match(observation) {
			continue
		}
		until := observation.Event.EventTime.Add(adminAnomalyWindow)
		group := []adminRequestObservation{observation}
		for nextIndex := index + 1; nextIndex < len(observations); nextIndex++ {
			next := observations[nextIndex]
			if next.Event.EventTime.After(until) {
				break
			}
			if adminObservationCovered(next, covered) ||
				next.RemoteFingerprint != observation.RemoteFingerprint ||
				!match(next) {
				continue
			}
			group = append(group, next)
			if len(group) >= threshold {
				break
			}
		}
		if len(group) < threshold {
			continue
		}
		for _, item := range group {
			covered[item.Key] = struct{}{}
		}
		chains = append(chains, buildAdminRequestChain(adminRequestRule{
			RuleID:     ruleID,
			Title:      title,
			Severity:   severity,
			Confidence: confidence,
			Summary:    fmt.Sprintf("%d admin request(s) from remote %s within %s", len(group), observation.RemoteFingerprint, adminAnomalyWindow),
			Events:     group,
		}))
	}
	return chains
}

func adminToolProbeChains(observations []adminRequestObservation, covered map[string]struct{}) []CorrelationChain {
	var chains []CorrelationChain
	for _, observation := range observations {
		if adminObservationCovered(observation, covered) ||
			!isAdminToolProbePath(observation.Path) ||
			!isFailureStatus(observation.Status) {
			continue
		}
		covered[observation.Key] = struct{}{}
		chains = append(chains, buildAdminRequestChain(adminRequestRule{
			RuleID:     "web-admin-tool-probe",
			Title:      "Admin tool probe",
			Severity:   domain.SeverityLow,
			Confidence: domain.ConfidenceMedium,
			Summary:    fmt.Sprintf("admin tool probe from remote %s: %s", observation.RemoteFingerprint, observation.Path),
			Events:     []adminRequestObservation{observation},
		}))
	}
	return chains
}

func buildAdminRequestChain(rule adminRequestRule) CorrelationChain {
	events := make([]CorrelationEvent, 0, len(rule.Events))
	for _, item := range rule.Events {
		events = append(events, CorrelationEvent{
			EventID:   item.Event.ID,
			EventTime: item.Event.EventTime,
			HostSlug:  item.Event.HostSlug,
			EventType: item.Event.EventType,
			Target:    fmt.Sprintf("%s %s %d", item.Method, item.Path, item.Status),
			Severity:  item.Event.Severity,
			Message:   item.Event.Message,
		})
	}
	return CorrelationChain{
		ID:         adminRequestChainID(rule.RuleID, rule.Events),
		RuleID:     rule.RuleID,
		Title:      rule.Title,
		Severity:   rule.Severity,
		Confidence: rule.Confidence,
		Summary:    rule.Summary,
		Events:     events,
	}
}

func adminRequestChainID(ruleID string, events []adminRequestObservation) string {
	parts := []string{ruleID}
	if len(events) > 0 {
		parts = append(parts, events[0].RemoteFingerprint, events[0].Event.EventTime.Truncate(adminAnomalyWindow).Format(time.RFC3339))
	}
	for _, event := range events {
		parts = append(parts, string(event.Event.ID), event.Path, fmt.Sprint(event.Status))
	}
	return "web-admin-" + sha256Short(strings.Join(parts, "\n"))
}

func isAdminRequestPath(path string) bool {
	path = normalizedRequestPath(path)
	return strings.Contains(path, "/wp-login.php") ||
		strings.Contains(path, "/wp-admin") ||
		strings.Contains(path, "/administrator") ||
		strings.Contains(path, "/admin") ||
		strings.Contains(path, "/login") ||
		strings.Contains(path, "/user/login") ||
		strings.Contains(path, "/backend") ||
		strings.Contains(path, "/manager") ||
		isAdminToolProbePath(path)
}

func isAdminToolProbePath(path string) bool {
	path = normalizedRequestPath(path)
	return strings.Contains(path, "phpmyadmin") ||
		strings.Contains(path, "/pma") ||
		strings.Contains(path, "adminer") ||
		strings.Contains(path, "/xmlrpc.php") ||
		strings.Contains(path, "/wp-admin/install.php") ||
		strings.Contains(path, "/wp-admin/setup-config.php")
}

func isAdminFailureObservation(observation adminRequestObservation) bool {
	return isFailureStatus(observation.Status) && isAdminRequestPath(observation.Path)
}

func isAdminLoginPostObservation(observation adminRequestObservation) bool {
	return observation.Method == "POST" &&
		(strings.Contains(observation.Path, "login") || strings.Contains(observation.Path, "admin")) &&
		isAdminRequestPath(observation.Path)
}

func isAdminSuccessObservation(observation adminRequestObservation) bool {
	if observation.Method != "POST" || !isAdminRequestPath(observation.Path) {
		return false
	}
	return observation.Status >= 300 && observation.Status < 400
}

func isFailureStatus(status int) bool {
	return status == 401 || status == 403 || status == 404 || status == 429
}

func adminObservationCovered(observation adminRequestObservation, covered map[string]struct{}) bool {
	_, ok := covered[observation.Key]
	return ok
}

func normalizedRequestPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func remoteAddressFingerprint(payload map[string]any) (string, bool) {
	remote := payloadStringAny(payload, "remote_addr", "")
	if remote == "" {
		remote = payloadStringAny(payload, "client_ip", "")
	}
	if remote == "" {
		remote = payloadStringAny(payload, "real_ip", "")
	}
	if remote == "" {
		return "unknown", false
	}
	return sha256Short(remote), true
}

func reverseAdminObservations(values []adminRequestObservation) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
