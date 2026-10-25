package hub

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/servicefingerprints"
	"github.com/rcooler/aegrail/hub/internal/useragent"
)

const (
	defaultTrafficWindow = 24 * time.Hour
	// The dashboard exposes bounded presets through 30 days. Keep the server-side
	// bound so arbitrary callers cannot turn the traffic endpoints into
	// unbounded access-log scans.
	maximumTrafficWindow = 30 * 24 * time.Hour
	defaultTrafficLimit  = 25
	maximumTrafficLimit  = 100
	trafficDNSLookupTTL  = 24 * time.Hour
	trafficDNSErrorTTL   = 15 * time.Minute
	trafficLocalIPTTL    = 7 * 24 * time.Hour
)

type TrafficQueryInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Since            time.Time
	Until            time.Time
	Limit            int
}

type TrafficIPInput struct {
	TrafficQueryInput
	IP string
}

type TrafficUserAgentInput struct {
	TrafficQueryInput
	Hash string
}

type UpdateTrafficIPPolicyInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	IP               string
	Policy           string
	Reason           string
	Actor            string
}

type TrafficBotsResult struct {
	Since                 time.Time                        `json:"since"`
	Until                 time.Time                        `json:"until"`
	TotalClients          int64                            `json:"total_clients"`
	TotalRequests         int64                            `json:"total_requests"`
	TotalVerifiedRequests int64                            `json:"total_verified_requests"`
	TotalErrorRequests    int64                            `json:"total_error_requests"`
	Returned              int                              `json:"returned"`
	Truncated             bool                             `json:"truncated"`
	Bots                  []domain.TrafficUserAgentSummary `json:"bots"`
}

func (h *Hub) GetTrafficOverview(ctx context.Context, input TrafficQueryInput) (domain.TrafficOverview, error) {
	filter, err := h.resolveTrafficFilter(ctx, input)
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	overview, err := h.traffic.GetTrafficOverview(ctx, filter)
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	for index := range overview.TopUserAgents {
		refreshTrafficUserAgentAnalysis(&overview.TopUserAgents[index])
	}
	return overview, nil
}

func (h *Hub) GetTrafficIPDetail(ctx context.Context, input TrafficIPInput) (domain.TrafficIPDetail, error) {
	filter, err := h.resolveTrafficFilter(ctx, input.TrafficQueryInput)
	if err != nil {
		return domain.TrafficIPDetail{}, err
	}
	ip, err := normalizeTrafficIP(input.IP)
	if err != nil {
		return domain.TrafficIPDetail{}, err
	}
	detail, found, err := h.traffic.GetTrafficIPDetail(ctx, filter, ip)
	if err != nil {
		return domain.TrafficIPDetail{}, err
	}
	if !found {
		return domain.TrafficIPDetail{}, fmt.Errorf("%w: IP %q has no traffic in this scope and time window", ErrHubNotFound, ip)
	}
	for index := range detail.UserAgents {
		refreshTrafficUserAgentAnalysis(&detail.UserAgents[index])
	}
	policy, policyFound, err := h.traffic.GetTrafficIPPolicy(ctx, filter.Scope.OrganizationID, ip)
	if err != nil {
		return domain.TrafficIPDetail{}, err
	}
	if !policyFound {
		policy = domain.TrafficIPPolicy{IP: ip, Policy: "neutral"}
	}
	intel, err := h.cachedTrafficIPIntel(ctx, filter.Scope.OrganizationID, ip)
	if err != nil {
		return domain.TrafficIPDetail{}, err
	}
	detail.Intel = intel
	detail.Policy = policy
	detail.Trusted = policy.Policy == "trusted"
	detail.Blocked = policy.Policy == "blocked"
	return detail, nil
}

func (h *Hub) UpdateTrafficIPPolicy(ctx context.Context, input UpdateTrafficIPPolicyInput) (domain.TrafficIPPolicy, error) {
	if err := h.requireTraffic(); err != nil {
		return domain.TrafficIPPolicy{}, err
	}
	scope, err := h.resolveTrafficScope(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return domain.TrafficIPPolicy{}, err
	}
	ip, err := normalizeTrafficIP(input.IP)
	if err != nil {
		return domain.TrafficIPPolicy{}, err
	}
	policy := strings.ToLower(strings.TrimSpace(input.Policy))
	switch policy {
	case "neutral", "trusted", "blocked":
	default:
		return domain.TrafficIPPolicy{}, errors.New("policy must be neutral, trusted, or blocked")
	}
	reason := strings.TrimSpace(input.Reason)
	if len(reason) > 2000 {
		return domain.TrafficIPPolicy{}, errors.New("policy reason must be at most 2000 characters")
	}
	actor := strings.TrimSpace(input.Actor)
	if len(actor) > 320 {
		return domain.TrafficIPPolicy{}, errors.New("policy actor must be at most 320 characters")
	}
	if actor == "" {
		actor = "local-owner"
	}
	return h.traffic.SaveTrafficIPPolicy(ctx, scope.OrganizationID, domain.TrafficIPPolicy{
		IP:        ip,
		Policy:    policy,
		Reason:    reason,
		UpdatedBy: actor,
	})
}

func (h *Hub) GetTrafficUserAgentDetail(ctx context.Context, input TrafficUserAgentInput) (domain.TrafficUserAgentDetail, error) {
	filter, err := h.resolveTrafficFilter(ctx, input.TrafficQueryInput)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, err
	}
	hash, err := normalizeTrafficUserAgentHash(input.Hash)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, err
	}
	detail, found, err := h.traffic.GetTrafficUserAgentDetail(ctx, filter, hash)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, err
	}
	if !found {
		return domain.TrafficUserAgentDetail{}, fmt.Errorf("%w: user agent %q has no traffic in this scope and time window", ErrHubNotFound, hash)
	}
	refreshTrafficUserAgentAnalysis(&detail.TrafficUserAgentSummary)
	return detail, nil
}

func (h *Hub) ListTrafficBots(ctx context.Context, input TrafficQueryInput) (TrafficBotsResult, error) {
	filter, err := h.resolveTrafficFilter(ctx, input)
	if err != nil {
		return TrafficBotsResult{}, err
	}
	page, err := h.traffic.ListTrafficBots(ctx, filter)
	if err != nil {
		return TrafficBotsResult{}, err
	}
	for index := range page.Bots {
		refreshTrafficUserAgentAnalysis(&page.Bots[index])
	}
	returned := len(page.Bots)
	return TrafficBotsResult{
		Since:                 filter.Since,
		Until:                 filter.Until,
		TotalClients:          page.TotalClients,
		TotalRequests:         page.TotalRequests,
		TotalVerifiedRequests: page.TotalVerifiedRequests,
		TotalErrorRequests:    page.TotalErrorRequests,
		Returned:              returned,
		Truncated:             int64(returned) < page.TotalClients,
		Bots:                  page.Bots,
	}, nil
}

func (h *Hub) resolveTrafficFilter(ctx context.Context, input TrafficQueryInput) (domain.TrafficFilter, error) {
	if err := h.requireTraffic(); err != nil {
		return domain.TrafficFilter{}, err
	}
	scope, err := h.resolveTrafficScope(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return domain.TrafficFilter{}, err
	}
	until := input.Until.UTC()
	if until.IsZero() {
		until = time.Now().UTC()
	}
	since := input.Since.UTC()
	if since.IsZero() {
		since = until.Add(-defaultTrafficWindow)
	}
	if !since.Before(until) {
		return domain.TrafficFilter{}, errors.New("traffic since time must be before until time")
	}
	if until.Sub(since) > maximumTrafficWindow {
		return domain.TrafficFilter{}, errors.New("traffic time window must not exceed 30 days")
	}
	limit := input.Limit
	if limit <= 0 {
		limit = defaultTrafficLimit
	}
	if limit > maximumTrafficLimit {
		limit = maximumTrafficLimit
	}
	return domain.TrafficFilter{Scope: scope, Since: since, Until: until, Limit: limit}, nil
}

func (h *Hub) resolveTrafficScope(ctx context.Context, organizationSlug string, projectSlug string, environmentSlug string, appSlug string) (domain.TrafficScope, error) {
	if err := h.requireTraffic(); err != nil {
		return domain.TrafficScope{}, err
	}
	if err := h.requireInventory(); err != nil {
		return domain.TrafficScope{}, err
	}
	organization, project, environment, err := h.resolveEnvironmentContext(ctx, organizationSlug, projectSlug, environmentSlug)
	if err != nil {
		return domain.TrafficScope{}, err
	}
	scope := domain.TrafficScope{
		OrganizationID: organization.ID,
		ProjectID:      project.ID,
		EnvironmentID:  environment.ID,
	}
	if strings.TrimSpace(appSlug) != "" {
		app, err := h.resolveAppPath(ctx, organizationSlug, projectSlug, environmentSlug, appSlug)
		if err != nil {
			return domain.TrafficScope{}, err
		}
		scope.AppID = app.ID
	}
	return scope, nil
}

func (h *Hub) requireTraffic() error {
	if h == nil || h.traffic == nil {
		return errors.New("traffic repository is not configured")
	}
	return nil
}

func (h *Hub) cachedTrafficIPIntel(ctx context.Context, organizationID domain.ID, ip string) (domain.TrafficIPIntel, error) {
	now := time.Now().UTC()
	cached, found, err := h.traffic.GetTrafficIPIntel(ctx, organizationID, ip)
	if err != nil {
		return domain.TrafficIPIntel{}, err
	}
	if found && cached.ExpiresAt.After(now) {
		return cached, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	refreshed := lookupTrafficIPIntel(lookupCtx, ip, now)
	if found && refreshed.LookupStatus == "error" {
		refreshed = trafficIPIntelWithStaleHints(cached, refreshed)
	}
	saved, saveErr := h.traffic.SaveTrafficIPIntel(ctx, organizationID, refreshed)
	if saveErr != nil {
		// The current lookup result is safer than an expired cache entry. In
		// particular, a failed refresh has already cleared DNS/provider
		// verification while retaining only non-authoritative identity hints.
		return refreshed, nil
	}
	return saved, nil
}

func trafficIPIntelWithStaleHints(cached domain.TrafficIPIntel, refreshed domain.TrafficIPIntel) domain.TrafficIPIntel {
	refreshed.NetworkClass = cached.NetworkClass
	refreshed.ReverseDNS = append([]string(nil), cached.ReverseDNS...)
	refreshed.ProviderFamily = cached.ProviderFamily
	refreshed.RecognizedProvider = cached.RecognizedProvider
	refreshed.ProviderActorType = cached.ProviderActorType
	// A failed current lookup can preserve identity hints, but it cannot carry
	// forward-confirmation or provider-verification state past cache expiry.
	refreshed.DNSVerified = false
	refreshed.ProviderVerified = false
	return refreshed
}

func lookupTrafficIPIntel(ctx context.Context, value string, now time.Time) domain.TrafficIPIntel {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return domain.TrafficIPIntel{IP: value, ReverseDNS: []string{}, LookupStatus: "error", LastLookupAt: now, ExpiresAt: now.Add(trafficDNSErrorTTL), LastError: "invalid IP address"}
	}
	address = address.Unmap()
	result := domain.TrafficIPIntel{
		IP:           address.String(),
		NetworkClass: trafficIPNetworkClass(address),
		ReverseDNS:   []string{},
		LookupStatus: "not_applicable",
		LastLookupAt: now,
		ExpiresAt:    now.Add(trafficLocalIPTTL),
		DNSVerified:  false,
		LastError:    "",
	}
	if result.NetworkClass != "public" {
		return result
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, address.String())
	if err != nil {
		result.LookupStatus = "error"
		result.ExpiresAt = now.Add(trafficDNSErrorTTL)
		result.LastError = boundedTrafficLookupError(err)
		return result
	}
	result.ReverseDNS = normalizeReverseDNSNames(names)
	verifiedNames := forwardConfirmedTrafficNames(ctx, address, result.ReverseDNS)
	result.DNSVerified = len(verifiedNames) > 0
	result.LookupStatus = "fresh"
	result.ExpiresAt = now.Add(trafficDNSLookupTTL)
	if match, recognized, providerVerified := recognizeTrafficProvider(result.ReverseDNS, verifiedNames); recognized {
		result.ProviderFamily = match.Family
		result.RecognizedProvider = match.KnownActor
		result.ProviderActorType = match.ActorType
		result.ProviderVerified = providerVerified
	}
	return result
}

func forwardConfirmedTrafficNames(ctx context.Context, address netip.Addr, names []string) map[string]struct{} {
	verified := map[string]struct{}{}
	for _, name := range names {
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, name)
		if err != nil {
			continue
		}
		for _, candidate := range addresses {
			candidateAddress, ok := netip.AddrFromSlice(candidate.IP)
			if ok && candidateAddress.Unmap() == address {
				verified[name] = struct{}{}
				break
			}
		}
	}
	return verified
}

func recognizeTrafficProvider(names []string, verifiedNames map[string]struct{}) (servicefingerprints.Match, bool, bool) {
	for _, name := range names {
		if _, verified := verifiedNames[name]; !verified {
			continue
		}
		if match, ok := servicefingerprints.MatchAuthoritativeReverseDNS(name); ok {
			return match, true, true
		}
	}
	var fallback servicefingerprints.Match
	foundFallback := false
	for _, name := range names {
		match, ok := servicefingerprints.MatchReverseDNS([]string{name})
		if !ok {
			continue
		}
		if !foundFallback {
			fallback = match
			foundFallback = true
		}
	}
	return fallback, foundFallback, false
}

func normalizeReverseDNSNames(values []string) []string {
	seen := map[string]struct{}{}
	names := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
		if len(names) == 10 {
			break
		}
	}
	sort.Strings(names)
	return names
}

func trafficIPNetworkClass(address netip.Addr) string {
	switch {
	case address.IsUnspecified():
		return "unspecified"
	case address.IsLoopback():
		return "loopback"
	case address.IsPrivate():
		return "private"
	case address.IsLinkLocalUnicast(), address.IsLinkLocalMulticast():
		return "link_local"
	case address.IsMulticast():
		return "multicast"
	case !address.IsGlobalUnicast():
		return "reserved"
	default:
		return "public"
	}
}

func normalizeTrafficIP(value string) (string, error) {
	value = strings.TrimSpace(value)
	address, err := netip.ParseAddr(value)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(value)
		if prefixErr != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return "", errors.New("valid IP address is required")
		}
		address = prefix.Addr()
	}
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	return address.Unmap().String(), nil
}

func normalizeTrafficUserAgentHash(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return "", errors.New("user agent hash must be a 64-character SHA-256 hex value")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("user agent hash must be a 64-character SHA-256 hex value")
	}
	return value, nil
}

func refreshTrafficUserAgentAnalysis(summary *domain.TrafficUserAgentSummary) {
	if summary == nil {
		return
	}
	analysis := useragent.Analyze(summary.UserAgent, summary.Requests)
	summary.Family = analysis.Family
	summary.BrowserFamily = analysis.BrowserFamily
	summary.BrowserVersion = analysis.BrowserVersion
	summary.OSFamily = analysis.OSFamily
	summary.OSVersion = analysis.OSVersion
	summary.DeviceFamily = analysis.DeviceFamily
	summary.ActorType = analysis.ActorType
	summary.KnownActor = analysis.KnownActor
	summary.IsBot = analysis.IsBot
	summary.IsTool = analysis.IsTool
	summary.RiskScore = analysis.RiskScore
}

func boundedTrafficLookupError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 500 {
		return value[:500]
	}
	return value
}
