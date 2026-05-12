package hub

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

const (
	webRequestSpikeWindow              = 10 * time.Minute
	webRequestVolumeThreshold          = 20
	webErrorRateThreshold              = 6
	webAdminPostVolumeThreshold        = 10
	webAdminPostDistinctRemoteMinCount = 3
)

type webRequestObservation struct {
	Event             domain.TimelineEvent
	Key               string
	RemoteFingerprint string
	RemoteKnown       bool
	Method            string
	Path              string
	PathFamily        string
	Status            int
}

type webRequestRule struct {
	RuleID     string
	Title      string
	Severity   domain.Severity
	Confidence domain.Confidence
	Summary    string
	Events     []webRequestObservation
}

func buildWebRequestTrafficChains(events []domain.TimelineEvent, coveredWebEvents map[string]struct{}) []CorrelationChain {
	observations := webRequestObservations(events, coveredWebEvents)
	var chains []CorrelationChain
	seen := map[string]struct{}{}
	coveredTrafficEvents := map[string]struct{}{}

	for _, chain := range webErrorRateSpikeChains(observations, coveredTrafficEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range webAdminPostVolumeSpikeChains(observations, coveredTrafficEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range webRequestVolumeSpikeChains(observations, coveredTrafficEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range webTorNetworkChains(observations, map[string]struct{}{}) {
		addCorrelationChain(&chains, seen, chain)
	}
	return chains
}

func webRequestObservations(events []domain.TimelineEvent, coveredWebEvents map[string]struct{}) []webRequestObservation {
	observations := make([]webRequestObservation, 0)
	for _, event := range events {
		if event.EventType != "log.access" {
			continue
		}
		if _, covered := coveredWebEvents[correlationEventKey(event)]; covered {
			continue
		}
		observation, ok := webRequestObservationFromEvent(event)
		if !ok {
			continue
		}
		observations = append(observations, observation)
	}
	return observations
}

func webRequestObservationFromEvent(event domain.TimelineEvent) (webRequestObservation, bool) {
	path := normalizedRequestPath(payloadStringAny(event.Payload, "path", event.Target))
	if path == "" {
		return webRequestObservation{}, false
	}
	method := strings.ToUpper(payloadStringAny(event.Payload, "method", ""))
	remoteFingerprint, remoteKnown := remoteAddressFingerprint(event.Payload)
	status := payloadInt(event.Payload, "status_code")
	return webRequestObservation{
		Event:             event,
		Key:               correlationEventKey(event),
		RemoteFingerprint: remoteFingerprint,
		RemoteKnown:       remoteKnown,
		Method:            method,
		Path:              path,
		PathFamily:        webRequestPathFamily(path),
		Status:            status,
	}, true
}

func webRequestVolumeSpikeChains(observations []webRequestObservation, covered map[string]struct{}) []CorrelationChain {
	return webRequestWindowChains(observations, covered, webRequestWindowRule{
		ruleID:     "web-request-volume-spike",
		title:      "Web request volume spike",
		threshold:  webRequestVolumeThreshold,
		severity:   domain.SeverityMedium,
		confidence: domain.ConfidenceMedium,
		match: func(observation webRequestObservation) bool {
			return observation.RemoteKnown && !isAdminRequestPath(observation.Path)
		},
		groupKey: func(observation webRequestObservation) string {
			return observation.RemoteFingerprint + ":" + observation.PathFamily
		},
		summary: func(group []webRequestObservation) string {
			first := group[0]
			return fmt.Sprintf("%d request(s) from remote %s to %s within %s", len(group), first.RemoteFingerprint, first.PathFamily, webRequestSpikeWindow)
		},
	})
}

func webErrorRateSpikeChains(observations []webRequestObservation, covered map[string]struct{}) []CorrelationChain {
	return webRequestWindowChains(observations, covered, webRequestWindowRule{
		ruleID:     "web-error-rate-spike",
		title:      "Web error rate spike",
		threshold:  webErrorRateThreshold,
		severity:   domain.SeverityMedium,
		confidence: domain.ConfidenceHigh,
		match: func(observation webRequestObservation) bool {
			return observation.Status >= 500
		},
		groupKey: func(observation webRequestObservation) string {
			return observation.PathFamily
		},
		summary: func(group []webRequestObservation) string {
			return fmt.Sprintf("%d server-error response(s) on %s within %s", len(group), group[0].PathFamily, webRequestSpikeWindow)
		},
	})
}

func webAdminPostVolumeSpikeChains(observations []webRequestObservation, covered map[string]struct{}) []CorrelationChain {
	return webRequestWindowChains(observations, covered, webRequestWindowRule{
		ruleID:     "web-admin-post-volume-spike",
		title:      "Distributed admin POST volume spike",
		threshold:  webAdminPostVolumeThreshold,
		severity:   domain.SeverityMedium,
		confidence: domain.ConfidenceHigh,
		match: func(observation webRequestObservation) bool {
			return observation.Method == "POST" && isAdminRequestPath(observation.Path)
		},
		groupKey: func(observation webRequestObservation) string {
			return observation.PathFamily
		},
		validate: func(group []webRequestObservation) bool {
			return countDistinctWebRequestRemotes(group) >= webAdminPostDistinctRemoteMinCount
		},
		summary: func(group []webRequestObservation) string {
			return fmt.Sprintf("%d admin POST request(s) from %d remote fingerprint(s) to %s within %s", len(group), countDistinctWebRequestRemotes(group), group[0].PathFamily, webRequestSpikeWindow)
		},
	})
}

type webRequestWindowRule struct {
	ruleID     string
	title      string
	threshold  int
	severity   domain.Severity
	confidence domain.Confidence
	match      func(webRequestObservation) bool
	groupKey   func(webRequestObservation) string
	validate   func([]webRequestObservation) bool
	summary    func([]webRequestObservation) string
}

func webRequestWindowChains(observations []webRequestObservation, covered map[string]struct{}, rule webRequestWindowRule) []CorrelationChain {
	var chains []CorrelationChain
	seenWindow := map[string]struct{}{}
	for index, observation := range observations {
		if webRequestObservationCovered(observation, covered) || !rule.match(observation) {
			continue
		}
		windowStart := observation.Event.EventTime.Truncate(webRequestSpikeWindow)
		windowKey := rule.ruleID + ":" + rule.groupKey(observation) + ":" + windowStart.Format(time.RFC3339)
		if _, ok := seenWindow[windowKey]; ok {
			continue
		}
		until := observation.Event.EventTime.Add(webRequestSpikeWindow)
		group := []webRequestObservation{observation}
		for nextIndex := index + 1; nextIndex < len(observations); nextIndex++ {
			next := observations[nextIndex]
			if next.Event.EventTime.After(until) {
				break
			}
			if webRequestObservationCovered(next, covered) ||
				!rule.match(next) ||
				rule.groupKey(next) != rule.groupKey(observation) {
				continue
			}
			group = append(group, next)
			if len(group) >= rule.threshold {
				break
			}
		}
		if len(group) < rule.threshold {
			continue
		}
		if rule.validate != nil && !rule.validate(group) {
			continue
		}
		seenWindow[windowKey] = struct{}{}
		for _, item := range group {
			covered[item.Key] = struct{}{}
		}
		chains = append(chains, buildWebRequestChain(webRequestRule{
			RuleID:     rule.ruleID,
			Title:      rule.title,
			Severity:   rule.severity,
			Confidence: rule.confidence,
			Summary:    rule.summary(group),
			Events:     group,
		}))
	}
	return chains
}

func webTorNetworkChains(observations []webRequestObservation, covered map[string]struct{}) []CorrelationChain {
	var chains []CorrelationChain
	seen := map[string]struct{}{}
	for _, observation := range observations {
		if webRequestObservationCovered(observation, covered) || !isTorMarkedRequest(observation.Event.Payload) {
			continue
		}
		ruleID := "web-tor-request-observed"
		title := "Tor network request observed"
		severity := domain.SeverityLow
		confidence := domain.ConfidenceMedium
		if isAdminRequestPath(observation.Path) {
			ruleID = "web-tor-admin-request"
			title = "Tor network request to admin path"
			severity = domain.SeverityMedium
			confidence = domain.ConfidenceHigh
		}
		windowKey := ruleID + ":" + observation.RemoteFingerprint + ":" + observation.PathFamily + ":" + observation.Event.EventTime.Truncate(webRequestSpikeWindow).Format(time.RFC3339)
		if _, ok := seen[windowKey]; ok {
			continue
		}
		seen[windowKey] = struct{}{}
		covered[observation.Key] = struct{}{}
		chains = append(chains, buildWebRequestChain(webRequestRule{
			RuleID:     ruleID,
			Title:      title,
			Severity:   severity,
			Confidence: confidence,
			Summary:    fmt.Sprintf("Tor-marked request observed on %s from remote %s", observation.PathFamily, observation.RemoteFingerprint),
			Events:     []webRequestObservation{observation},
		}))
	}
	return chains
}

func buildWebRequestChain(rule webRequestRule) CorrelationChain {
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
		ID:         webRequestChainID(rule.RuleID, rule.Events),
		RuleID:     rule.RuleID,
		Title:      rule.Title,
		Severity:   rule.Severity,
		Confidence: rule.Confidence,
		Summary:    rule.Summary,
		Events:     events,
	}
}

func webRequestChainID(ruleID string, events []webRequestObservation) string {
	parts := []string{ruleID}
	if len(events) > 0 {
		parts = append(parts, events[0].PathFamily, events[0].RemoteFingerprint, events[0].Event.EventTime.Truncate(webRequestSpikeWindow).Format(time.RFC3339))
	}
	for _, event := range events {
		parts = append(parts, string(event.Event.ID), event.Path, fmt.Sprint(event.Status))
	}
	return "web-request-" + sha256Short(strings.Join(parts, "\n"))
}

func webRequestPathFamily(path string) string {
	path = normalizedRequestPath(path)
	switch {
	case path == "":
		return "/"
	case path == "/wp-login.php":
		return "/wp-login.php"
	case strings.HasPrefix(path, "/wp-admin"):
		return "/wp-admin"
	case isAdminToolProbePath(path):
		return "/admin-tool"
	case isAdminRequestPath(path):
		return "/admin"
	case path == "/":
		return "/"
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "/"
	}
	return "/" + parts[0]
}

func countDistinctWebRequestRemotes(group []webRequestObservation) int {
	seen := map[string]struct{}{}
	for _, observation := range group {
		if !observation.RemoteKnown {
			continue
		}
		seen[observation.RemoteFingerprint] = struct{}{}
	}
	return len(seen)
}

func webRequestObservationCovered(observation webRequestObservation, covered map[string]struct{}) bool {
	_, ok := covered[observation.Key]
	return ok
}

func isTorMarkedRequest(payload map[string]any) bool {
	if payloadBool(payload, "remote_is_tor") || payloadBool(payload, "is_tor") {
		return true
	}
	for _, key := range []string{"remote_network", "client_network", "network", "remote_reputation", "ip_reputation"} {
		if torMarkerString(payloadStringAny(payload, key, "")) {
			return true
		}
	}
	for _, key := range []string{"remote_tags", "network_tags", "reputation_tags", "tags"} {
		if torMarkerList(payloadStringList(payload, key)) {
			return true
		}
	}
	return false
}

func torMarkerString(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "tor" ||
		value == "tor_exit" ||
		value == "tor-exit" ||
		strings.Contains(value, "tor exit") ||
		strings.Contains(value, "tor_exit") ||
		strings.Contains(value, "tor-exit")
}

func torMarkerList(values []string) bool {
	return slices.ContainsFunc(values, torMarkerString)
}

func payloadStringList(payload map[string]any, key string) []string {
	switch value := payload[key].(type) {
	case []string:
		return append([]string(nil), value...)
	case []any:
		values := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				continue
			}
			values = append(values, text)
		}
		return values
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		parts := strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == '|' || r == ' '
		})
		values := make([]string, 0, len(parts))
		for _, part := range parts {
			if strings.TrimSpace(part) != "" {
				values = append(values, part)
			}
		}
		return values
	default:
		return nil
	}
}
