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
	DisplayPath       string
	RequestText       string
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
	for _, chain := range passwordResetRequestChains(observations, coveredAdminEvents) {
		addCorrelationChain(&chains, seen, chain)
	}
	for _, chain := range adminLoginRequestChains(observations, coveredAdminEvents) {
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
	rawPath := payloadStringAny(event.Payload, "path", event.Target)
	path := normalizedRequestPath(rawPath)
	requestText := requestObservationText(event.Payload, rawPath)
	if path == "" || (!isAdminRequestPath(path) && !isPasswordResetRequestText(path, requestText)) {
		return adminRequestObservation{}, false
	}
	method := strings.ToUpper(payloadStringAny(event.Payload, "method", ""))
	remoteFingerprint, remoteKnown := remoteAddressFingerprint(event.Payload)
	status := payloadInt(event.Payload, "status_code")
	displayPath := path
	if isPasswordResetRequestText(path, requestText) {
		displayPath = resetRequestDisplayPath(event.Payload, path)
	}
	return adminRequestObservation{
		Event:             event,
		Key:               correlationEventKey(event),
		RemoteFingerprint: remoteFingerprint,
		RemoteKnown:       remoteKnown,
		Method:            method,
		Path:              path,
		DisplayPath:       displayPath,
		RequestText:       requestText,
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

func passwordResetRequestChains(observations []adminRequestObservation, covered map[string]struct{}) []CorrelationChain {
	return adminRequestWindowChains(observations, covered, adminRequestWindowRule{
		ruleID:     "web-password-reset-request",
		title:      "Password reset request observed",
		severity:   domain.SeverityMedium,
		confidence: domain.ConfidenceMedium,
		match: func(observation adminRequestObservation) bool {
			return observation.RemoteKnown && isPasswordResetRequestObservation(observation)
		},
		groupKey: func(observation adminRequestObservation) string {
			return observation.RemoteFingerprint + ":" + observation.Path
		},
		summary: func(group []adminRequestObservation) string {
			first := group[0]
			return fmt.Sprintf("%d password reset request(s) from remote %s on %s within %s", len(group), first.RemoteFingerprint, first.Path, adminAnomalyWindow)
		},
	})
}

func adminLoginRequestChains(observations []adminRequestObservation, covered map[string]struct{}) []CorrelationChain {
	return adminRequestWindowChains(observations, covered, adminRequestWindowRule{
		ruleID:     "web-admin-login-request",
		title:      "Admin login request observed",
		severity:   domain.SeverityLow,
		confidence: domain.ConfidenceMedium,
		match:      isAdminLoginRequestObservation,
		groupKey: func(observation adminRequestObservation) string {
			return observation.RemoteFingerprint + ":" + observation.Path
		},
		summary: func(group []adminRequestObservation) string {
			first := group[0]
			outcome := "submitted"
			if anyAdminLoginLikelySuccess(group) {
				outcome = "success likely"
			}
			return fmt.Sprintf("%d admin login request(s) from remote %s on %s within %s; outcome: %s", len(group), first.RemoteFingerprint, first.Path, adminAnomalyWindow, outcome)
		},
	})
}

type adminRequestWindowRule struct {
	ruleID     string
	title      string
	severity   domain.Severity
	confidence domain.Confidence
	match      func(adminRequestObservation) bool
	groupKey   func(adminRequestObservation) string
	summary    func([]adminRequestObservation) string
}

func adminRequestWindowChains(observations []adminRequestObservation, covered map[string]struct{}, rule adminRequestWindowRule) []CorrelationChain {
	var chains []CorrelationChain
	seenWindow := map[string]struct{}{}
	for index, observation := range observations {
		if adminObservationCovered(observation, covered) || !rule.match(observation) {
			continue
		}
		windowStart := observation.Event.EventTime.Truncate(adminAnomalyWindow)
		windowKey := rule.ruleID + ":" + rule.groupKey(observation) + ":" + windowStart.Format(time.RFC3339)
		if _, ok := seenWindow[windowKey]; ok {
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
				!rule.match(next) ||
				rule.groupKey(next) != rule.groupKey(observation) {
				continue
			}
			group = append(group, next)
		}
		seenWindow[windowKey] = struct{}{}
		for _, item := range group {
			covered[item.Key] = struct{}{}
		}
		chains = append(chains, buildAdminRequestChain(adminRequestRule{
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

func buildAdminRequestChain(rule adminRequestRule) CorrelationChain {
	events := make([]CorrelationEvent, 0, len(rule.Events))
	for _, item := range rule.Events {
		events = append(events, CorrelationEvent{
			EventID:   item.Event.ID,
			EventTime: item.Event.EventTime,
			HostSlug:  item.Event.HostSlug,
			EventType: item.Event.EventType,
			Target:    fmt.Sprintf("%s %s %d", item.Method, item.DisplayPath, item.Status),
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
	return isAdminLoginPostCandidate(observation)
}

func isAdminSuccessObservation(observation adminRequestObservation) bool {
	if !isAdminLoginPostCandidate(observation) {
		return false
	}
	return observation.Status >= 300 && observation.Status < 400
}

func isAdminLoginRequestObservation(observation adminRequestObservation) bool {
	return observation.RemoteKnown &&
		isAdminLoginPostCandidate(observation) &&
		observation.Status >= 300 &&
		observation.Status < 400
}

func isAdminLoginPostCandidate(observation adminRequestObservation) bool {
	if observation.Method != "POST" || !isAdminRequestPath(observation.Path) || isPasswordResetRequestObservation(observation) {
		return false
	}
	return isAdminLoginRequestText(observation.Path, observation.RequestText)
}

func isAdminLoginRequestText(path string, requestText string) bool {
	path = normalizedRequestPath(path)
	text := strings.ToLower(requestText)
	return path == "/wp-login.php" ||
		strings.Contains(path, "/login") ||
		strings.Contains(path, "/user/login") ||
		strings.Contains(path, "/site/login") ||
		strings.Contains(path, "/s/login") ||
		strings.Contains(text, "controller=adminlogin") ||
		strings.Contains(text, "submitlogin") ||
		strings.Contains(text, "adminlogin")
}

func isPasswordResetRequestObservation(observation adminRequestObservation) bool {
	switch observation.Method {
	case "GET", "POST":
	default:
		return false
	}
	return isPasswordResetRequestText(observation.Path, observation.RequestText)
}

func isPasswordResetRequestText(path string, requestText string) bool {
	path = normalizedRequestPath(path)
	text := strings.ToLower(requestText)
	if strings.Contains(text, "lostpassword") ||
		strings.Contains(text, "lost-password") ||
		strings.Contains(text, "retrievepassword") ||
		strings.Contains(text, "resetpass") ||
		strings.Contains(text, "forgot_password") ||
		strings.Contains(text, "forgot-password") ||
		strings.Contains(text, "passwordreset") ||
		strings.Contains(text, "reset_password") ||
		strings.Contains(text, "request-password-reset") {
		return true
	}
	for _, marker := range []string{
		"/password/reset",
		"/password/email",
		"/reset-password",
		"/forgot-password",
		"/request-password-reset",
		"/site/request-password-reset",
		"/site/reset-password",
		"/user/request-password-reset",
		"/user/reset-password",
		"/account/reset",
	} {
		if path == marker || strings.HasPrefix(path, marker+"/") {
			return true
		}
	}
	return false
}

func anyAdminLoginLikelySuccess(observations []adminRequestObservation) bool {
	for _, observation := range observations {
		if observation.Status >= 300 && observation.Status < 400 {
			return true
		}
	}
	return false
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

func requestObservationText(payload map[string]any, rawPath string) string {
	parts := []string{rawPath}
	for _, key := range []string{"request_target_redacted", "query_redacted"} {
		if value := payloadStringAny(payload, key, ""); value != "" {
			parts = append(parts, value)
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func resetRequestDisplayPath(payload map[string]any, path string) string {
	target := payloadStringAny(payload, "request_target_redacted", "")
	if target != "" {
		return strings.ToLower(strings.TrimSpace(target))
	}
	query := payloadStringAny(payload, "query_redacted", "")
	if query != "" {
		return normalizedRequestPath(path) + "?" + strings.ToLower(strings.TrimSpace(query))
	}
	return normalizedRequestPath(path)
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
