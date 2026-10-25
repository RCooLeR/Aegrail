package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
)

func TestHubRouterTrafficEndpointsAreLazyAndScoped(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	traffic := newHTTPTestTrafficRepository()
	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		hubapp.New(hubapp.Dependencies{Inventory: inventory, Traffic: traffic}),
		HubOptions{},
	)
	query := "?org=acme&project=customer-site&environment=production&app=main-web&since=2026-07-05T10:00:00Z&until=2026-08-04T10:00:00Z"

	tests := []struct {
		name     string
		path     string
		bodyKey  string
		wantCode int
	}{
		{name: "overview", path: "/api/v1/traffic" + query, bodyKey: "traffic", wantCode: http.StatusOK},
		{name: "ip host CIDR", path: "/api/v1/traffic/ips/203.0.113.9%2F32" + query, bodyKey: "ip", wantCode: http.StatusOK},
		{name: "user agent", path: "/api/v1/traffic/user-agents/" + strings.Repeat("a", 64) + query, bodyKey: "user_agent", wantCode: http.StatusOK},
		{name: "bots", path: "/api/v1/traffic/bots" + query, bodyKey: "bots", wantCode: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.wantCode {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			var body map[string]any
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if _, ok := body[test.bodyKey]; !ok {
				t.Fatalf("body = %#v, missing %q", body, test.bodyKey)
			}
		})
	}

	if traffic.lastFilter.Scope.OrganizationID != inventory.org.ID ||
		traffic.lastFilter.Scope.ProjectID != inventory.project.ID ||
		traffic.lastFilter.Scope.EnvironmentID != inventory.environment.ID ||
		traffic.lastFilter.Scope.AppID != inventory.apps[0].ID {
		t.Fatalf("traffic filter escaped scope: %#v", traffic.lastFilter.Scope)
	}
	if traffic.lastIP != "203.0.113.9" {
		t.Fatalf("traffic IP = %q, want canonical host address", traffic.lastIP)
	}
	if got := traffic.lastFilter.Until.Sub(traffic.lastFilter.Since); got != 30*24*time.Hour {
		t.Fatalf("traffic window = %s, want 30 days", got)
	}

	beforeCalls := traffic.queryCalls
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/traffic?org=other&project=customer-site&environment=production", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("wrong-org status = %d body = %s", response.Code, response.Body.String())
	}
	if traffic.queryCalls != beforeCalls {
		t.Fatal("traffic repository was queried before the organization scope was resolved")
	}
}

func TestHubRouterTrafficBotsExposeAggregateAndPaginationMetadata(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	traffic := newHTTPTestTrafficRepository()
	traffic.botsPage = domain.TrafficBotsPage{
		TotalClients:          25,
		TotalRequests:         800,
		TotalVerifiedRequests: 300,
		TotalErrorRequests:    40,
		Bots: []domain.TrafficUserAgentSummary{
			{Hash: strings.Repeat("a", 64), UserAgent: "Googlebot/2.1", Requests: 500},
			{Hash: strings.Repeat("b", 64), UserAgent: "curl/8.0", Requests: 300},
		},
	}
	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		hubapp.New(hubapp.Dependencies{Inventory: inventory, Traffic: traffic}),
		HubOptions{},
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/traffic/bots?org=acme&project=customer-site&environment=production&limit=100",
		nil,
	))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		TotalClients          int64 `json:"total_clients"`
		TotalRequests         int64 `json:"total_requests"`
		TotalVerifiedRequests int64 `json:"total_verified_requests"`
		TotalErrorRequests    int64 `json:"total_error_requests"`
		Returned              int   `json:"returned"`
		Truncated             bool  `json:"truncated"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TotalClients != 25 || body.TotalRequests != 800 || body.TotalVerifiedRequests != 300 || body.TotalErrorRequests != 40 {
		t.Fatalf("aggregate metadata = %#v", body)
	}
	if body.Returned != 2 || !body.Truncated {
		t.Fatalf("page metadata = %#v, want returned=2 truncated=true", body)
	}
	if traffic.lastFilter.Limit != 100 {
		t.Fatalf("repository limit = %d, want requested maximum 100", traffic.lastFilter.Limit)
	}
}

func TestHubRouterUpdatesTrafficIPPolicy(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	traffic := newHTTPTestTrafficRepository()
	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		hubapp.New(hubapp.Dependencies{Inventory: inventory, Traffic: traffic}),
		HubOptions{},
	)
	body := bytes.NewBufferString(`{"policy":"trusted","reason":"office egress"}`)
	request := httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/traffic/ips/2001:db8::1%2F128/policy?org=acme&project=customer-site&environment=production&app=main-web",
		body,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if traffic.savedPolicyOrganizationID != inventory.org.ID || traffic.savedPolicy.IP != "2001:db8::1" || traffic.savedPolicy.Policy != "trusted" {
		t.Fatalf("saved policy org=%q policy=%#v", traffic.savedPolicyOrganizationID, traffic.savedPolicy)
	}
}

type httpTestTrafficRepository struct {
	lastFilter                domain.TrafficFilter
	lastIP                    string
	queryCalls                int
	savedPolicyOrganizationID domain.ID
	savedPolicy               domain.TrafficIPPolicy
	intel                     domain.TrafficIPIntel
	botsPage                  domain.TrafficBotsPage
}

func newHTTPTestTrafficRepository() *httpTestTrafficRepository {
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	return &httpTestTrafficRepository{intel: domain.TrafficIPIntel{
		IP:           "203.0.113.9",
		ReverseDNS:   []string{},
		LookupStatus: "fresh",
		LastLookupAt: now,
		ExpiresAt:    time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		NetworkClass: "public",
		DNSVerified:  false,
		LastError:    "",
	}}
}

func (r *httpTestTrafficRepository) GetTrafficOverview(_ context.Context, filter domain.TrafficFilter) (domain.TrafficOverview, error) {
	r.lastFilter = filter
	r.queryCalls++
	return domain.TrafficOverview{Since: filter.Since, Until: filter.Until, TimelineBucket: "hour"}, nil
}

func (r *httpTestTrafficRepository) GetTrafficIPDetail(_ context.Context, filter domain.TrafficFilter, ip string) (domain.TrafficIPDetail, bool, error) {
	r.lastFilter = filter
	r.lastIP = ip
	r.queryCalls++
	return domain.TrafficIPDetail{IP: ip, Requests: 1}, true, nil
}

func (r *httpTestTrafficRepository) GetTrafficUserAgentDetail(_ context.Context, filter domain.TrafficFilter, hash string) (domain.TrafficUserAgentDetail, bool, error) {
	r.lastFilter = filter
	r.queryCalls++
	return domain.TrafficUserAgentDetail{Hash: hash, UserAgent: "Googlebot/2.1", Requests: 1}, true, nil
}

func (r *httpTestTrafficRepository) ListTrafficBots(_ context.Context, filter domain.TrafficFilter) (domain.TrafficBotsPage, error) {
	r.lastFilter = filter
	r.queryCalls++
	if r.botsPage.Bots == nil {
		r.botsPage = domain.TrafficBotsPage{
			TotalClients:  1,
			TotalRequests: 1,
			Bots:          []domain.TrafficUserAgentSummary{{Hash: strings.Repeat("a", 64), UserAgent: "Googlebot/2.1", Requests: 1}},
		}
	}
	return r.botsPage, nil
}

func (r *httpTestTrafficRepository) GetTrafficIPIntel(_ context.Context, _ domain.ID, _ string) (domain.TrafficIPIntel, bool, error) {
	return r.intel, true, nil
}

func (r *httpTestTrafficRepository) SaveTrafficIPIntel(_ context.Context, _ domain.ID, intel domain.TrafficIPIntel) (domain.TrafficIPIntel, error) {
	r.intel = intel
	return intel, nil
}

func (r *httpTestTrafficRepository) GetTrafficIPPolicy(_ context.Context, _ domain.ID, ip string) (domain.TrafficIPPolicy, bool, error) {
	return domain.TrafficIPPolicy{IP: ip, Policy: "neutral"}, true, nil
}

func (r *httpTestTrafficRepository) SaveTrafficIPPolicy(_ context.Context, organizationID domain.ID, policy domain.TrafficIPPolicy) (domain.TrafficIPPolicy, error) {
	r.savedPolicyOrganizationID = organizationID
	r.savedPolicy = policy
	return policy, nil
}
