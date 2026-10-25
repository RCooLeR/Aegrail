package hub

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestTrafficOverviewResolvesAndPassesFullScope(t *testing.T) {
	repository := newMemoryTrafficRepository()
	hub, inventory := newTrafficTestHub(t, repository)
	since := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	until := since.Add(6 * time.Hour)

	_, err := hub.GetTrafficOverview(t.Context(), TrafficQueryInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Since:            since,
		Until:            until,
		Limit:            500,
	})
	if err != nil {
		t.Fatalf("GetTrafficOverview returned error: %v", err)
	}
	filter := repository.lastFilter
	if filter.Scope.OrganizationID != inventory.Organization.ID ||
		filter.Scope.ProjectID != inventory.Project.ID ||
		filter.Scope.EnvironmentID != inventory.Environment.ID ||
		filter.Scope.AppID != inventory.App.ID {
		t.Fatalf("resolved scope = %#v, want inventory path %#v", filter.Scope, inventory)
	}
	if !filter.Since.Equal(since) || !filter.Until.Equal(until) || filter.Limit != maximumTrafficLimit {
		t.Fatalf("normalized filter = %#v", filter)
	}
}

func TestTrafficQueryAcceptsThirtyDaysAndRejectsLongerWindows(t *testing.T) {
	repository := newMemoryTrafficRepository()
	hub, _ := newTrafficTestHub(t, repository)
	until := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)

	_, err := hub.GetTrafficOverview(t.Context(), TrafficQueryInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		Since:            until.Add(-maximumTrafficWindow),
		Until:            until,
	})
	if err != nil {
		t.Fatalf("GetTrafficOverview rejected 30-day window: %v", err)
	}
	if got := repository.lastFilter.Until.Sub(repository.lastFilter.Since); got != maximumTrafficWindow {
		t.Fatalf("resolved window = %s, want %s", got, maximumTrafficWindow)
	}

	_, err = hub.GetTrafficOverview(t.Context(), TrafficQueryInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		Since:            until.Add(-maximumTrafficWindow - time.Second),
		Until:            until,
	})
	if err == nil || !strings.Contains(err.Error(), "must not exceed 30 days") {
		t.Fatalf("GetTrafficOverview error = %v, want 30-day bound", err)
	}
}

func TestTrafficIPTrustComesOnlyFromManualPolicy(t *testing.T) {
	repository := newMemoryTrafficRepository()
	hub, inventory := newTrafficTestHub(t, repository)
	// Keep the fixture fresh relative to the Hub's real cache clock. A fixed
	// historical expiry silently turns this unit test into a live DNS test as
	// soon as wall time passes it.
	now := time.Now().UTC()
	repository.ipDetail = domain.TrafficIPDetail{IP: "8.8.8.8", Requests: 12}
	repository.ipDetailFound = true
	repository.intel[trafficTestKey(inventory.Organization.ID, "8.8.8.8")] = domain.TrafficIPIntel{
		IP:                 "8.8.8.8",
		ReverseDNS:         []string{"dns.google"},
		DNSVerified:        true,
		ProviderFamily:     "googlebot",
		RecognizedProvider: "Google",
		ProviderVerified:   true,
		LookupStatus:       "fresh",
		LastLookupAt:       now,
		ExpiresAt:          now.Add(24 * time.Hour),
	}

	detail, err := hub.GetTrafficIPDetail(t.Context(), TrafficIPInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		Since:            now.Add(-time.Hour),
		Until:            now,
		IP:               "8.8.8.8/32",
	})
	if err != nil {
		t.Fatalf("GetTrafficIPDetail returned error: %v", err)
	}
	if !detail.Intel.ProviderVerified || detail.Trusted || detail.Policy.Policy != "neutral" {
		t.Fatalf("detail = %#v, verified recognition must remain untrusted", detail)
	}
	if repository.lastIP != "8.8.8.8" {
		t.Fatalf("repository IP = %q, want canonical host address", repository.lastIP)
	}

	repository.policies[trafficTestKey(inventory.Organization.ID, "8.8.8.8")] = domain.TrafficIPPolicy{IP: "8.8.8.8", Policy: "trusted"}
	detail, err = hub.GetTrafficIPDetail(t.Context(), TrafficIPInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		Since:            now.Add(-time.Hour),
		Until:            now,
		IP:               "8.8.8.8/32",
	})
	if err != nil {
		t.Fatalf("trusted GetTrafficIPDetail returned error: %v", err)
	}
	if !detail.Trusted || detail.Blocked {
		t.Fatalf("detail policy = %#v, want manually trusted", detail.Policy)
	}
}

func TestUpdateTrafficIPPolicyIsOrganizationScoped(t *testing.T) {
	repository := newMemoryTrafficRepository()
	hub, inventory := newTrafficTestHub(t, repository)

	policy, err := hub.UpdateTrafficIPPolicy(t.Context(), UpdateTrafficIPPolicyInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		IP:               "2001:0db8::1/128",
		Policy:           "trusted",
		Reason:           "office egress",
		Actor:            "operator@example.test",
	})
	if err != nil {
		t.Fatalf("UpdateTrafficIPPolicy returned error: %v", err)
	}
	if repository.savedPolicyOrganizationID != inventory.Organization.ID || policy.IP != "2001:db8::1" || policy.Policy != "trusted" {
		t.Fatalf("saved policy org=%q policy=%#v", repository.savedPolicyOrganizationID, policy)
	}
}

func TestNormalizeTrafficIPAcceptsHostValuesAndRemovesDatabaseFormatting(t *testing.T) {
	tests := map[string]string{
		"fe80::1%eth0":     "fe80::1",
		"81.250.241.21/32": "81.250.241.21",
		"2001:db8::21/128": "2001:db8::21",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := normalizeTrafficIP(input)
			if err != nil {
				t.Fatalf("normalizeTrafficIP returned error: %v", err)
			}
			if got != want {
				t.Fatalf("normalizeTrafficIP = %q, want %q", got, want)
			}
		})
	}
	if _, err := normalizeTrafficIP("81.250.241.0/24"); err == nil {
		t.Fatal("normalizeTrafficIP accepted a non-host network prefix")
	}
}

func TestExpiredTrafficIPIntelSaveFailureDoesNotReturnStaleVerification(t *testing.T) {
	repository := newMemoryTrafficRepository()
	hub, inventory := newTrafficTestHub(t, repository)
	previousLookup := time.Now().UTC().Add(-48 * time.Hour)
	repository.ipDetail = domain.TrafficIPDetail{IP: "127.0.0.1", Requests: 1}
	repository.ipDetailFound = true
	repository.intel[trafficTestKey(inventory.Organization.ID, "127.0.0.1")] = domain.TrafficIPIntel{
		IP:                 "127.0.0.1",
		NetworkClass:       "public",
		ReverseDNS:         []string{"crawl.googlebot.com"},
		DNSVerified:        true,
		ProviderFamily:     "googlebot",
		RecognizedProvider: "Google",
		ProviderVerified:   true,
		LookupStatus:       "fresh",
		LastLookupAt:       previousLookup,
		ExpiresAt:          previousLookup.Add(time.Hour),
	}
	repository.saveIntelErr = errors.New("database unavailable")

	detail, err := hub.GetTrafficIPDetail(t.Context(), TrafficIPInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		IP:               "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("GetTrafficIPDetail returned error: %v", err)
	}
	if detail.Intel.DNSVerified || detail.Intel.ProviderVerified {
		t.Fatalf("expired verification survived failed save: %#v", detail.Intel)
	}
	if detail.Intel.LookupStatus != "not_applicable" || detail.Intel.NetworkClass != "loopback" {
		t.Fatalf("detail intel = %#v, want current loopback lookup despite failed cache write", detail.Intel)
	}
}

func TestTrafficBotsResultSeparatesTotalsFromReturnedPage(t *testing.T) {
	repository := newMemoryTrafficRepository()
	repository.botsPage = domain.TrafficBotsPage{
		TotalClients:          12,
		TotalRequests:         345,
		TotalVerifiedRequests: 120,
		TotalErrorRequests:    23,
		Bots: []domain.TrafficUserAgentSummary{
			{Hash: strings.Repeat("a", 64), UserAgent: "Googlebot/2.1", Requests: 200},
			{Hash: strings.Repeat("b", 64), UserAgent: "curl/8.0", Requests: 145},
		},
	}
	hub, _ := newTrafficTestHub(t, repository)

	result, err := hub.ListTrafficBots(t.Context(), TrafficQueryInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
	})
	if err != nil {
		t.Fatalf("ListTrafficBots returned error: %v", err)
	}
	if result.TotalClients != 12 || result.TotalRequests != 345 || result.TotalVerifiedRequests != 120 || result.TotalErrorRequests != 23 {
		t.Fatalf("aggregate totals = %#v", result)
	}
	if result.Returned != 2 || !result.Truncated || len(result.Bots) != 2 {
		t.Fatalf("page metadata = %#v, want 2 returned and truncated", result)
	}
}

func newTrafficTestHub(t *testing.T, traffic *memoryTrafficRepository) (*Hub, BootstrapSingleSiteResult) {
	t.Helper()
	inventory := newMemoryInventoryRepository()
	hub := New(Dependencies{Inventory: inventory, Traffic: traffic})
	result, err := hub.BootstrapSingleSite(t.Context(), BootstrapSingleSiteInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		Kind:             "wordpress",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		Fingerprint:      "SHA256:test",
	})
	if err != nil {
		t.Fatalf("BootstrapSingleSite returned error: %v", err)
	}
	return hub, result
}

type memoryTrafficRepository struct {
	lastFilter                domain.TrafficFilter
	lastIP                    string
	ipDetail                  domain.TrafficIPDetail
	ipDetailFound             bool
	userAgentDetail           domain.TrafficUserAgentDetail
	userAgentDetailFound      bool
	intel                     map[string]domain.TrafficIPIntel
	policies                  map[string]domain.TrafficIPPolicy
	savedPolicyOrganizationID domain.ID
	saveIntelErr              error
	botsPage                  domain.TrafficBotsPage
}

func newMemoryTrafficRepository() *memoryTrafficRepository {
	return &memoryTrafficRepository{
		intel:    map[string]domain.TrafficIPIntel{},
		policies: map[string]domain.TrafficIPPolicy{},
	}
}

func (r *memoryTrafficRepository) GetTrafficOverview(_ context.Context, filter domain.TrafficFilter) (domain.TrafficOverview, error) {
	r.lastFilter = filter
	return domain.TrafficOverview{Since: filter.Since, Until: filter.Until}, nil
}

func (r *memoryTrafficRepository) GetTrafficIPDetail(_ context.Context, filter domain.TrafficFilter, ip string) (domain.TrafficIPDetail, bool, error) {
	r.lastFilter = filter
	r.lastIP = ip
	return r.ipDetail, r.ipDetailFound, nil
}

func (r *memoryTrafficRepository) GetTrafficUserAgentDetail(_ context.Context, filter domain.TrafficFilter, _ string) (domain.TrafficUserAgentDetail, bool, error) {
	r.lastFilter = filter
	return r.userAgentDetail, r.userAgentDetailFound, nil
}

func (r *memoryTrafficRepository) ListTrafficBots(_ context.Context, filter domain.TrafficFilter) (domain.TrafficBotsPage, error) {
	r.lastFilter = filter
	if r.botsPage.Bots == nil {
		r.botsPage.Bots = []domain.TrafficUserAgentSummary{}
	}
	return r.botsPage, nil
}

func (r *memoryTrafficRepository) GetTrafficIPIntel(_ context.Context, organizationID domain.ID, ip string) (domain.TrafficIPIntel, bool, error) {
	intel, ok := r.intel[trafficTestKey(organizationID, ip)]
	return intel, ok, nil
}

func (r *memoryTrafficRepository) SaveTrafficIPIntel(_ context.Context, organizationID domain.ID, intel domain.TrafficIPIntel) (domain.TrafficIPIntel, error) {
	if r.saveIntelErr != nil {
		return domain.TrafficIPIntel{}, r.saveIntelErr
	}
	r.intel[trafficTestKey(organizationID, intel.IP)] = intel
	return intel, nil
}

func (r *memoryTrafficRepository) GetTrafficIPPolicy(_ context.Context, organizationID domain.ID, ip string) (domain.TrafficIPPolicy, bool, error) {
	policy, ok := r.policies[trafficTestKey(organizationID, ip)]
	return policy, ok, nil
}

func (r *memoryTrafficRepository) SaveTrafficIPPolicy(_ context.Context, organizationID domain.ID, policy domain.TrafficIPPolicy) (domain.TrafficIPPolicy, error) {
	r.savedPolicyOrganizationID = organizationID
	r.policies[trafficTestKey(organizationID, policy.IP)] = policy
	return policy, nil
}

func trafficTestKey(organizationID domain.ID, value string) string {
	return string(organizationID) + "\x00" + value
}
