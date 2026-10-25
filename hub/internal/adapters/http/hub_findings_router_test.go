package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestHubRouterUpdatesFindingStatus(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestFindingRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings}), HubOptions{})

	requestBody := bytes.NewBufferString(`{"status":"false_positive","reason":"expected-plugin","note":"Known plugin activation.","actor":"roman"}`)
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/findings/finding-1/status?org=acme&project=customer-site&environment=production", requestBody)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Finding struct {
			ID           string `json:"id"`
			Status       string `json:"status"`
			StatusReason string `json:"status_reason"`
			StatusNote   string `json:"status_note"`
			StatusActor  string `json:"status_actor"`
		} `json:"finding"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Finding.ID != "finding-1" || body.Finding.Status != "false_positive" || body.Finding.StatusReason != "expected-plugin" || body.Finding.StatusActor != "roman" {
		t.Fatalf("finding = %#v, want false_positive status", body.Finding)
	}
}

func TestHubRouterGetsFindingByID(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestFindingRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings}), HubOptions{})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/findings/finding-1?org=acme&project=customer-site&environment=production&app=main-web", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Finding struct {
			ID     string `json:"id"`
			RuleID string `json:"rule_id"`
		} `json:"finding"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Finding.ID != "finding-1" || body.Finding.RuleID != "wordpress-admin-user-added" {
		t.Fatalf("body = %#v, want finding-1", body)
	}
}

func TestHubRouterPaginatesFindingsWithAccurateSummary(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestFindingRepository()
	first := findings.findings["finding-1"]
	first.ID = "11111111-1111-1111-1111-111111111111"
	first.LastEventAt = first.LastEventAt.Add(2 * time.Minute)
	first.CreatedAt = first.CreatedAt.Add(2 * time.Minute)
	delete(findings.findings, "finding-1")
	findings.findings[first.ID] = first

	second := first
	second.ID = "22222222-2222-2222-2222-222222222222"
	second.LastEventAt = second.LastEventAt.Add(-time.Minute)
	second.CreatedAt = second.CreatedAt.Add(-time.Minute)
	second.Severity = domain.SeverityMedium
	findings.findings[second.ID] = second

	third := first
	third.ID = "33333333-3333-3333-3333-333333333333"
	third.LastEventAt = third.LastEventAt.Add(-2 * time.Minute)
	third.CreatedAt = third.CreatedAt.Add(-2 * time.Minute)
	third.Status = "resolved"
	findings.findings[third.ID] = third

	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings}), HubOptions{})

	firstRequest := httptest.NewRequest(http.MethodGet, "/api/v1/findings?org=acme&project=customer-site&environment=production&app=main-web&limit=2", nil)
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first page status = %d body = %s", firstResponse.Code, firstResponse.Body.String())
	}
	var firstPage struct {
		Count        int    `json:"count"`
		Total        int64  `json:"total"`
		MatchedTotal int64  `json:"matched_total"`
		NextCursor   string `json:"next_cursor"`
		Summary      struct {
			Total              int64            `json:"total"`
			StatusCounts       map[string]int64 `json:"status_counts"`
			SeverityCounts     map[string]int64 `json:"severity_counts"`
			OpenSeverityCounts map[string]int64 `json:"open_severity_counts"`
		} `json:"summary"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(firstResponse.Body).Decode(&firstPage); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	if firstPage.Count != 2 || firstPage.Total != 3 || firstPage.MatchedTotal != 3 || firstPage.Summary.Total != 3 || firstPage.NextCursor == "" {
		t.Fatalf("first page = %#v, want two of three records and a cursor", firstPage)
	}
	if firstPage.Summary.StatusCounts["open"] != 2 || firstPage.Summary.StatusCounts["resolved"] != 1 {
		t.Fatalf("status counts = %#v", firstPage.Summary.StatusCounts)
	}
	if firstPage.Summary.SeverityCounts["high"] != 2 || firstPage.Summary.SeverityCounts["medium"] != 1 {
		t.Fatalf("severity counts = %#v", firstPage.Summary.SeverityCounts)
	}
	if firstPage.Summary.OpenSeverityCounts["high"] != 1 || firstPage.Summary.OpenSeverityCounts["medium"] != 1 {
		t.Fatalf("open severity counts = %#v", firstPage.Summary.OpenSeverityCounts)
	}

	secondRequest := httptest.NewRequest(http.MethodGet, "/api/v1/findings?org=acme&project=customer-site&environment=production&app=main-web&limit=2&cursor="+url.QueryEscape(firstPage.NextCursor), nil)
	secondResponse := httptest.NewRecorder()
	router.ServeHTTP(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusOK {
		t.Fatalf("second page status = %d body = %s", secondResponse.Code, secondResponse.Body.String())
	}
	var secondPage struct {
		Count        int    `json:"count"`
		Total        *int64 `json:"total"`
		MatchedTotal *int64 `json:"matched_total"`
		NextCursor   string `json:"next_cursor"`
		Findings     []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(secondResponse.Body).Decode(&secondPage); err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	if secondPage.Count != 1 || secondPage.Total != nil || secondPage.MatchedTotal != nil || secondPage.NextCursor != "" {
		t.Fatalf("second page = %#v, want final record", secondPage)
	}
	if secondPage.Findings[0].ID == firstPage.Findings[0].ID || secondPage.Findings[0].ID == firstPage.Findings[1].ID {
		t.Fatalf("second page repeated a first-page finding: %#v then %#v", firstPage.Findings, secondPage.Findings)
	}
}

func TestHubRouterFiltersFindingPagesAndKeepsUnfilteredSummary(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestFindingRepository()
	first := findings.findings["finding-1"]
	first.ID = "11111111-1111-1111-1111-111111111111"
	first.CreatedAt = first.CreatedAt.Add(2 * time.Minute)
	delete(findings.findings, "finding-1")
	findings.findings[first.ID] = first

	second := first
	second.ID = "22222222-2222-2222-2222-222222222222"
	second.CreatedAt = second.CreatedAt.Add(-time.Minute)
	second.Severity = domain.SeverityMedium
	findings.findings[second.ID] = second

	third := first
	third.ID = "33333333-3333-3333-3333-333333333333"
	third.CreatedAt = third.CreatedAt.Add(-2 * time.Minute)
	third.Status = "resolved"
	findings.findings[third.ID] = third

	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings}), HubOptions{})
	params := url.Values{
		"org":         {"acme"},
		"project":     {"customer-site"},
		"environment": {"production"},
		"app":         {"main-web"},
		"limit":       {"1"},
		"status":      {"", " OPEN ", "resolved", "open"},
		"severity":    {"HIGH", ""},
		"q":           {"FINDING-KEY"},
	}
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, httptest.NewRequest(http.MethodGet, "/api/v1/findings?"+params.Encode(), nil))
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first filtered page status = %d body = %s", firstResponse.Code, firstResponse.Body.String())
	}
	var firstPage struct {
		Count        int    `json:"count"`
		Total        int64  `json:"total"`
		MatchedTotal int64  `json:"matched_total"`
		NextCursor   string `json:"next_cursor"`
		Summary      struct {
			StatusCounts map[string]int64 `json:"status_counts"`
		} `json:"summary"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(firstResponse.Body).Decode(&firstPage); err != nil {
		t.Fatalf("decode first filtered page: %v", err)
	}
	if firstPage.Count != 1 || firstPage.Total != 3 || firstPage.MatchedTotal != 2 || firstPage.NextCursor == "" {
		t.Fatalf("first filtered page = %#v, want one of two matches and unfiltered total three", firstPage)
	}
	if firstPage.Summary.StatusCounts["open"] != 2 || firstPage.Summary.StatusCounts["resolved"] != 1 {
		t.Fatalf("unfiltered summary = %#v", firstPage.Summary.StatusCounts)
	}

	params.Set("cursor", firstPage.NextCursor)
	secondResponse := httptest.NewRecorder()
	router.ServeHTTP(secondResponse, httptest.NewRequest(http.MethodGet, "/api/v1/findings?"+params.Encode(), nil))
	if secondResponse.Code != http.StatusOK {
		t.Fatalf("second filtered page status = %d body = %s", secondResponse.Code, secondResponse.Body.String())
	}
	var secondPage struct {
		Count        int    `json:"count"`
		Total        *int64 `json:"total"`
		MatchedTotal *int64 `json:"matched_total"`
		NextCursor   string `json:"next_cursor"`
		Findings     []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(secondResponse.Body).Decode(&secondPage); err != nil {
		t.Fatalf("decode second filtered page: %v", err)
	}
	if secondPage.Count != 1 || secondPage.Total != nil || secondPage.MatchedTotal != nil || secondPage.NextCursor != "" {
		t.Fatalf("second filtered page = %#v, want final match without recomputed totals", secondPage)
	}
	if secondPage.Findings[0].ID == firstPage.Findings[0].ID {
		t.Fatalf("filtered cursor repeated finding %q", secondPage.Findings[0].ID)
	}
}

func TestHubRouterRejectsUnsupportedFindingFilters(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestFindingRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings}), HubOptions{})

	for _, path := range []string{
		"/api/v1/findings?org=acme&project=customer-site&environment=production&app=main-web&status=closed",
		"/api/v1/findings?org=acme&project=customer-site&environment=production&app=main-web&severity=urgent",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s status = %d body = %s, want 400", path, response.Code, response.Body.String())
		}
	}
}

func TestHubRouterAcceptsFindingBaseline(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestFindingRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings}), HubOptions{})

	requestBody := bytes.NewBufferString(`{"actor":"roman"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/findings/baseline?org=acme&project=customer-site&environment=production&app=main-web", requestBody)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Updated int    `json:"updated"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		Actor   string `json:"actor"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Updated != 1 || body.Status != "acknowledged" || body.Reason != "baseline_accepted" || body.Actor != "roman" {
		t.Fatalf("body = %#v, want accepted baseline result", body)
	}
	if findings.findings["finding-1"].Status != "acknowledged" || findings.findings["finding-1"].StatusReason != "baseline_accepted" {
		t.Fatalf("finding = %#v, want acknowledged baseline status", findings.findings["finding-1"])
	}
}

type httpTestFindingRepository struct {
	findings map[domain.ID]domain.HubFinding
}

func newHTTPTestFindingRepository() *httpTestFindingRepository {
	now := time.Date(2026, 5, 12, 18, 0, 0, 0, time.UTC)
	return &httpTestFindingRepository{
		findings: map[domain.ID]domain.HubFinding{
			"finding-1": {
				ID:              "finding-1",
				OrganizationID:  "org-1",
				ProjectID:       "project-1",
				EnvironmentID:   "env-1",
				AppID:           "app-1",
				RuleID:          "wordpress-admin-user-added",
				RuleVersion:     "2026-05-12.1",
				DedupeKey:       "finding-key",
				Severity:        domain.SeverityHigh,
				Confidence:      domain.ConfidenceHigh,
				Title:           "WordPress administrator added",
				FirstEventAt:    now,
				LastEventAt:     now,
				Status:          "open",
				StatusUpdatedAt: now,
				CreatedAt:       now,
				UpdatedAt:       now,
			},
		},
	}
}

func (r *httpTestFindingRepository) SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error) {
	return findings, nil
}

func (r *httpTestFindingRepository) ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error) {
	var findings []domain.HubFinding
	for _, finding := range r.findings {
		if finding.EnvironmentID != environmentID {
			continue
		}
		if appID != "" && finding.AppID != appID {
			continue
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (r *httpTestFindingRepository) ListHubFindingsPage(ctx context.Context, environmentID domain.ID, appID domain.ID, options ports.HubFindingPageOptions) (ports.HubFindingPage, error) {
	var findings []domain.HubFinding
	summary := ports.HubFindingSummary{
		StatusCounts:       map[string]int64{"open": 0, "acknowledged": 0, "false_positive": 0, "resolved": 0},
		SeverityCounts:     map[string]int64{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
		OpenSeverityCounts: map[string]int64{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
	}
	var matchedTotal int64
	for _, finding := range r.findings {
		if finding.EnvironmentID != environmentID || (appID != "" && finding.AppID != appID) {
			continue
		}
		status := finding.Status
		if status == "" {
			status = "open"
		}
		severity := string(finding.Severity)
		summary.Total++
		summary.StatusCounts[status]++
		summary.SeverityCounts[severity]++
		if status == "open" {
			summary.OpenSeverityCounts[severity]++
		}
		if !httpTestFindingMatchesPageOptions(finding, options) {
			continue
		}
		matchedTotal++
		if options.After == nil || hubFindingIsAfterCursor(finding, *options.After) {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if !findings[i].CreatedAt.Equal(findings[j].CreatedAt) {
			return findings[i].CreatedAt.After(findings[j].CreatedAt)
		}
		return findings[i].ID > findings[j].ID
	})
	limit := options.Limit
	if limit <= 0 {
		limit = 20
	}
	hasMore := len(findings) > limit
	if hasMore {
		findings = findings[:limit]
	}
	return ports.HubFindingPage{
		Findings:             findings,
		Summary:              summary,
		SummaryIncluded:      !options.SkipSummary,
		MatchedTotal:         matchedTotal,
		MatchedTotalIncluded: !options.SkipSummary,
		HasMore:              hasMore,
	}, nil
}

func httpTestFindingMatchesPageOptions(finding domain.HubFinding, options ports.HubFindingPageOptions) bool {
	status := strings.ToLower(strings.TrimSpace(finding.Status))
	if status == "" {
		status = "open"
	}
	severity := strings.ToLower(strings.TrimSpace(string(finding.Severity)))
	if len(options.Statuses) > 0 && !containsString(options.Statuses, status) {
		return false
	}
	if len(options.Severities) > 0 && !containsString(options.Severities, severity) {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(options.Query))
	if query == "" {
		return true
	}
	for _, value := range []string{finding.Title, finding.Summary, finding.Description, finding.RuleID, finding.DedupeKey} {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func hubFindingIsAfterCursor(finding domain.HubFinding, cursor ports.HubFindingPageCursor) bool {
	if !finding.CreatedAt.Equal(cursor.CreatedAt) {
		return finding.CreatedAt.Before(cursor.CreatedAt)
	}
	return finding.ID < cursor.ID
}

func (r *httpTestFindingRepository) GetHubFinding(ctx context.Context, findingID domain.ID, environmentID domain.ID, appID domain.ID) (domain.HubFinding, error) {
	finding, ok := r.findings[findingID]
	if !ok || finding.EnvironmentID != environmentID {
		return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
	}
	if appID != "" && finding.AppID != appID {
		return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
	}
	return finding, nil
}

func (r *httpTestFindingRepository) UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error) {
	finding, ok := r.findings[findingID]
	if !ok || finding.EnvironmentID != environmentID {
		return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
	}
	now := time.Date(2026, 5, 12, 18, 5, 0, 0, time.UTC)
	finding.Status = update.Status
	finding.StatusReason = update.Reason
	finding.StatusNote = update.Note
	finding.StatusActor = update.Actor
	finding.StatusUpdatedAt = now
	finding.UpdatedAt = now
	r.findings[findingID] = finding
	return finding, nil
}

func (r *httpTestFindingRepository) UpdateOpenHubFindingStatuses(ctx context.Context, environmentID domain.ID, appID domain.ID, update domain.HubFindingStatusUpdate) (int, error) {
	now := time.Date(2026, 5, 12, 18, 10, 0, 0, time.UTC)
	updated := 0
	for id, finding := range r.findings {
		if finding.EnvironmentID != environmentID || finding.Status != "open" {
			continue
		}
		if appID != "" && finding.AppID != appID {
			continue
		}
		finding.Status = update.Status
		finding.StatusReason = update.Reason
		finding.StatusNote = update.Note
		finding.StatusActor = update.Actor
		finding.StatusUpdatedAt = now
		finding.UpdatedAt = now
		r.findings[id] = finding
		updated++
	}
	return updated, nil
}
