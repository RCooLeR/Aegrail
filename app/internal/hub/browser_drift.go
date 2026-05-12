package hub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

type AnalyzeBrowserScriptDriftInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	BaselineSince    time.Time
	ObserveSince     time.Time
	Limit            int
	SaveFindings     bool
}

type BrowserScriptDriftResult struct {
	Organization   domain.Organization
	Project        domain.Project
	Environment    domain.Environment
	App            domain.MonitoredApp
	BaselineSince  time.Time
	ObserveSince   time.Time
	Events         int
	BaselineEvents int
	ObservedEvents int
	Drifts         []BrowserScriptDrift
	Findings       []domain.HubFinding
}

type BrowserScriptDrift struct {
	Kind        string
	RuleID      string
	Title       string
	Severity    domain.Severity
	Confidence  domain.Confidence
	PageURL     string
	Value       string
	Target      string
	EventID     domain.ID
	EventTime   time.Time
	HostSlug    string
	Description string
	Metadata    map[string]any
}

const browserDriftRuleVersion = currentRuleVersion

func (h *Hub) AnalyzeBrowserScriptDrift(ctx context.Context, input AnalyzeBrowserScriptDriftInput) (BrowserScriptDriftResult, error) {
	if h.ingest == nil {
		return BrowserScriptDriftResult{}, errors.New("ingest repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return BrowserScriptDriftResult{}, err
	}
	if strings.TrimSpace(input.AppSlug) == "" {
		return BrowserScriptDriftResult{}, errors.New("app slug is required")
	}

	org, project, environment, err := h.resolveEnvironmentContext(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return BrowserScriptDriftResult{}, err
	}
	app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return BrowserScriptDriftResult{}, err
	}
	if input.ObserveSince.IsZero() {
		input.ObserveSince = time.Now().UTC().Add(-24 * time.Hour)
	}
	if input.BaselineSince.IsZero() || input.BaselineSince.After(input.ObserveSince) {
		input.BaselineSince = input.ObserveSince.Add(-30 * 24 * time.Hour)
	}

	events, err := h.ingest.ListTimelineEvents(ctx, environment.ID, app.ID, input.BaselineSince, input.Limit)
	if err != nil {
		return BrowserScriptDriftResult{}, err
	}
	baseline, observed := splitBrowserScriptEvents(events, input.ObserveSince)
	allowlist, err := h.browserScriptAllowlistMatcher(ctx, environment.ID, app.ID)
	if err != nil {
		return BrowserScriptDriftResult{}, err
	}
	drifts := detectBrowserScriptDrifts(baseline, observed, allowlist)
	findings := browserScriptDriftFindings(org, project, environment, app, drifts)
	findings, err = h.applyDeploymentContextToFindings(ctx, environment.ID, app.ID, findings)
	if err != nil {
		return BrowserScriptDriftResult{}, err
	}
	if input.SaveFindings && len(findings) > 0 {
		if h.findings == nil {
			return BrowserScriptDriftResult{}, errors.New("finding repository is not configured")
		}
		findings, err = h.findings.SaveHubFindings(ctx, findings)
		if err != nil {
			return BrowserScriptDriftResult{}, err
		}
	}

	return BrowserScriptDriftResult{
		Organization:   org,
		Project:        project,
		Environment:    environment,
		App:            app,
		BaselineSince:  input.BaselineSince,
		ObserveSince:   input.ObserveSince,
		Events:         len(events),
		BaselineEvents: len(baseline),
		ObservedEvents: len(observed),
		Drifts:         drifts,
		Findings:       findings,
	}, nil
}

func splitBrowserScriptEvents(events []domain.TimelineEvent, observeSince time.Time) ([]domain.TimelineEvent, []domain.TimelineEvent) {
	var baseline []domain.TimelineEvent
	var observed []domain.TimelineEvent
	for _, event := range events {
		if !isBrowserScriptObservation(event) {
			continue
		}
		if event.EventTime.Before(observeSince) {
			baseline = append(baseline, event)
			continue
		}
		observed = append(observed, event)
	}
	return baseline, observed
}

func isBrowserScriptObservation(event domain.TimelineEvent) bool {
	return event.EventType == "browser.script.observed" || event.EventType == "browser.tag_manager.detected"
}

func detectBrowserScriptDrifts(baselineEvents []domain.TimelineEvent, observedEvents []domain.TimelineEvent, allowlist *browserScriptAllowlistMatcher) []BrowserScriptDrift {
	baseline := newBrowserScriptBaseline()
	for _, event := range baselineEvents {
		baseline.observe(event)
	}
	if allowlist == nil {
		allowlist = newBrowserScriptAllowlistMatcher(nil)
	}

	var drifts []BrowserScriptDrift
	seen := map[string]struct{}{}
	for _, event := range observedEvents {
		page := browserPageKey(event)
		if page == "" || !baseline.hasPage(page) {
			continue
		}
		domain := payloadStringAny(event.Payload, "domain", "")
		if domain != "" && !baseline.hasDomain(page, domain) && !allowlist.allows(page, "domain", domain) {
			addBrowserScriptDrift(&drifts, seen, buildBrowserScriptDrift("domain", event, domain))
		}

		sourceType := strings.ToLower(payloadStringAny(event.Payload, "source_type", ""))
		inlineHash := payloadStringAny(event.Payload, "sha256", "")
		if sourceType == "inline" && inlineHash != "" && !baseline.hasInlineHash(page, inlineHash) && !allowlist.allows(page, "inline_hash", inlineHash) {
			addBrowserScriptDrift(&drifts, seen, buildBrowserScriptDrift("inline_hash", event, inlineHash))
		}

		for _, id := range payloadStringSlice(event.Payload, "tag_manager_ids") {
			if id != "" && !baseline.hasTagManagerID(page, id) && !allowlist.allows(page, "tag_manager_id", id) {
				addBrowserScriptDrift(&drifts, seen, buildBrowserScriptDrift("tag_manager_id", event, id))
			}
		}
	}

	slices.SortFunc(drifts, func(a BrowserScriptDrift, b BrowserScriptDrift) int {
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(b.Severity) - severityRank(a.Severity)
		}
		if a.EventTime.Equal(b.EventTime) {
			return strings.Compare(a.Value, b.Value)
		}
		if a.EventTime.Before(b.EventTime) {
			return -1
		}
		return 1
	})
	return drifts
}

func (h *Hub) browserScriptAllowlistMatcher(ctx context.Context, environmentID domain.ID, appID domain.ID) (*browserScriptAllowlistMatcher, error) {
	if h.browserAllowlist == nil {
		return newBrowserScriptAllowlistMatcher(nil), nil
	}
	entries, err := h.browserAllowlist.ListBrowserScriptAllowlistEntries(ctx, environmentID, appID)
	if err != nil {
		return nil, err
	}
	return newBrowserScriptAllowlistMatcher(entries), nil
}

type browserScriptAllowlistMatcher struct {
	values map[string]struct{}
}

func newBrowserScriptAllowlistMatcher(entries []domain.BrowserScriptAllowlistEntry) *browserScriptAllowlistMatcher {
	matcher := &browserScriptAllowlistMatcher{values: map[string]struct{}{}}
	for _, entry := range entries {
		if entry.Status != "" && entry.Status != "active" {
			continue
		}
		kind, err := normalizeBrowserScriptAllowlistKind(entry.Kind)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(entry.Value)
		if value == "" {
			continue
		}
		page := normalizeBrowserPageURL(entry.PageURL)
		matcher.values[browserScriptAllowlistKey(page, kind, value)] = struct{}{}
		if page == "" {
			continue
		}
	}
	return matcher
}

func (m *browserScriptAllowlistMatcher) allows(page string, kind string, value string) bool {
	if m == nil {
		return false
	}
	kind, err := normalizeBrowserScriptAllowlistKind(kind)
	if err != nil {
		return false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	page = normalizeBrowserPageURL(page)
	if _, ok := m.values[browserScriptAllowlistKey(page, kind, value)]; ok {
		return true
	}
	_, ok := m.values[browserScriptAllowlistKey("", kind, value)]
	return ok
}

func browserScriptAllowlistKey(page string, kind string, value string) string {
	return page + "\x00" + kind + "\x00" + value
}

type browserScriptBaseline struct {
	pages         map[string]struct{}
	domains       map[string]map[string]struct{}
	inlineHashes  map[string]map[string]struct{}
	tagManagerIDs map[string]map[string]struct{}
}

func newBrowserScriptBaseline() *browserScriptBaseline {
	return &browserScriptBaseline{
		pages:         map[string]struct{}{},
		domains:       map[string]map[string]struct{}{},
		inlineHashes:  map[string]map[string]struct{}{},
		tagManagerIDs: map[string]map[string]struct{}{},
	}
}

func (b *browserScriptBaseline) observe(event domain.TimelineEvent) {
	page := browserPageKey(event)
	if page == "" {
		return
	}
	b.pages[page] = struct{}{}
	if domain := payloadStringAny(event.Payload, "domain", ""); domain != "" {
		addNestedSetValue(b.domains, page, domain)
	}
	sourceType := strings.ToLower(payloadStringAny(event.Payload, "source_type", ""))
	if sourceType == "inline" {
		if hash := payloadStringAny(event.Payload, "sha256", ""); hash != "" {
			addNestedSetValue(b.inlineHashes, page, hash)
		}
	}
	for _, id := range payloadStringSlice(event.Payload, "tag_manager_ids") {
		if id != "" {
			addNestedSetValue(b.tagManagerIDs, page, id)
		}
	}
}

func (b *browserScriptBaseline) hasPage(page string) bool {
	_, ok := b.pages[page]
	return ok
}

func (b *browserScriptBaseline) hasDomain(page string, domain string) bool {
	return nestedSetHas(b.domains, page, domain)
}

func (b *browserScriptBaseline) hasInlineHash(page string, hash string) bool {
	return nestedSetHas(b.inlineHashes, page, hash)
}

func (b *browserScriptBaseline) hasTagManagerID(page string, id string) bool {
	return nestedSetHas(b.tagManagerIDs, page, id)
}

func addNestedSetValue(values map[string]map[string]struct{}, outer string, inner string) {
	inner = strings.TrimSpace(inner)
	if outer == "" || inner == "" {
		return
	}
	set := values[outer]
	if set == nil {
		set = map[string]struct{}{}
		values[outer] = set
	}
	set[inner] = struct{}{}
}

func nestedSetHas(values map[string]map[string]struct{}, outer string, inner string) bool {
	set := values[outer]
	if set == nil {
		return false
	}
	_, ok := set[inner]
	return ok
}

func buildBrowserScriptDrift(kind string, event domain.TimelineEvent, value string) BrowserScriptDrift {
	page := browserPageKey(event)
	value = strings.TrimSpace(value)
	drift := BrowserScriptDrift{
		Kind:       kind,
		PageURL:    page,
		Value:      value,
		Target:     event.Target,
		EventID:    event.ID,
		EventTime:  event.EventTime,
		HostSlug:   event.HostSlug,
		Confidence: domain.ConfidenceMedium,
		Metadata: map[string]any{
			"kind":       kind,
			"page_url":   page,
			"value":      value,
			"event_id":   string(event.ID),
			"event_time": event.EventTime.Format(time.RFC3339Nano),
			"host":       event.HostSlug,
			"target":     event.Target,
			"payload":    event.Payload,
		},
	}
	switch kind {
	case "domain":
		drift.RuleID = "browser-script-domain-new"
		drift.Title = "New browser script domain"
		drift.Severity = domain.SeverityMedium
		drift.Description = fmt.Sprintf("Aegrail observed script domain %s on %s, but that domain was not present in the baseline window for this page.", value, page)
	case "inline_hash":
		drift.RuleID = "browser-inline-script-changed"
		drift.Title = "New browser inline script hash"
		drift.Severity = domain.SeverityMedium
		drift.Description = fmt.Sprintf("Aegrail observed a new inline script hash on %s. Inline JavaScript drift can indicate page-builder, option, widget, or injection changes.", page)
	case "tag_manager_id":
		drift.RuleID = "browser-tag-manager-id-new"
		drift.Title = "New tag manager container"
		drift.Severity = domain.SeverityHigh
		drift.Confidence = domain.ConfidenceHigh
		drift.Description = fmt.Sprintf("Aegrail observed tag manager id %s on %s, but that id was not present in the baseline window for this page.", value, page)
	default:
		drift.RuleID = "browser-script-drift"
		drift.Title = "Browser script drift"
		drift.Severity = domain.SeverityMedium
		drift.Description = fmt.Sprintf("Aegrail observed browser script drift %s on %s.", value, page)
	}
	return drift
}

func addBrowserScriptDrift(drifts *[]BrowserScriptDrift, seen map[string]struct{}, drift BrowserScriptDrift) {
	key := drift.RuleID + ":" + drift.PageURL + ":" + drift.Value
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*drifts = append(*drifts, drift)
}

func browserScriptDriftFindings(org domain.Organization, project domain.Project, environment domain.Environment, app domain.MonitoredApp, drifts []BrowserScriptDrift) []domain.HubFinding {
	findings := make([]domain.HubFinding, 0, len(drifts))
	for _, drift := range drifts {
		eventIDs := []domain.ID{}
		if drift.EventID != "" {
			eventIDs = append(eventIDs, drift.EventID)
		}
		findings = append(findings, domain.HubFinding{
			OrganizationID: org.ID,
			ProjectID:      project.ID,
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         drift.RuleID,
			RuleVersion:    ruleVersion(drift.RuleID),
			DedupeKey:      "browser-drift-" + sha256Short(drift.RuleID+"\n"+drift.PageURL+"\n"+drift.Value),
			Severity:       drift.Severity,
			Confidence:     drift.Confidence,
			Title:          drift.Title,
			Summary:        fmt.Sprintf("%s on %s: %s", drift.Title, drift.PageURL, drift.Value),
			Description:    drift.Description,
			EventIDs:       eventIDs,
			FirstEventAt:   drift.EventTime,
			LastEventAt:    drift.EventTime,
			Metadata:       ruleMetadata(drift.RuleID, drift.Metadata),
		})
	}
	return findings
}

func browserPageKey(event domain.TimelineEvent) string {
	page := payloadStringAny(event.Payload, "final_url", "")
	if page == "" {
		page = payloadStringAny(event.Payload, "page_url", "")
	}
	if page == "" {
		page = event.Target
	}
	page = strings.TrimSpace(page)
	page = strings.TrimSuffix(page, "#")
	return strings.TrimRight(page, "/")
}

func payloadStringSlice(payload map[string]any, key string) []string {
	value, ok := payload[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return cleanStringSlice(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				values = append(values, text)
			}
		}
		return values
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		parts := strings.Split(typed, ",")
		return cleanStringSlice(parts)
	default:
		return nil
	}
}

func cleanStringSlice(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}
