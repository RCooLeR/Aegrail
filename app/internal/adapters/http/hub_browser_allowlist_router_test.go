package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
)

func TestHubRouterManagesBrowserScriptAllowlist(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	allowlist := newHTTPTestBrowserScriptAllowlistRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, BrowserAllowlist: allowlist}), HubOptions{})

	createBody := bytes.NewBufferString(`{"page_url":"https://example.test/","kind":"script-domain","value":"cdn.vendor.example","reason":"reviewed vendor","approved_by":"roman"}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/browser/script-allowlist?org=acme&project=customer-site&environment=production&app=main-web", createBody)
	createResponse := httptest.NewRecorder()
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createResponse.Code, createResponse.Body.String())
	}
	var createResult struct {
		Entry struct {
			ID         string `json:"id"`
			PageURL    string `json:"page_url"`
			Kind       string `json:"kind"`
			Value      string `json:"value"`
			Reason     string `json:"reason"`
			ApprovedBy string `json:"approved_by"`
			Status     string `json:"status"`
		} `json:"entry"`
	}
	if err := json.NewDecoder(createResponse.Body).Decode(&createResult); err != nil {
		t.Fatalf("Decode create returned error: %v", err)
	}
	if createResult.Entry.PageURL != "https://example.test" || createResult.Entry.Kind != "domain" || createResult.Entry.Status != "active" {
		t.Fatalf("created entry = %#v, want normalized active domain entry", createResult.Entry)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/browser/script-allowlist?org=acme&project=customer-site&environment=production&app=main-web&kind=domain&page=https://example.test/", nil)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listResponse.Code, listResponse.Body.String())
	}
	var listResult struct {
		Count     int `json:"count"`
		Allowlist []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"allowlist"`
	}
	if err := json.NewDecoder(listResponse.Body).Decode(&listResult); err != nil {
		t.Fatalf("Decode list returned error: %v", err)
	}
	if listResult.Count != 1 || listResult.Allowlist[0].ID != createResult.Entry.ID {
		t.Fatalf("list result = %#v, want created entry", listResult)
	}

	patchBody := bytes.NewBufferString(`{"status":"disabled","reason":"vendor removed","approved_by":"security"}`)
	patchRequest := httptest.NewRequest(http.MethodPatch, "/api/v1/browser/script-allowlist/"+createResult.Entry.ID+"/status?org=acme&project=customer-site&environment=production&app=main-web", patchBody)
	patchResponse := httptest.NewRecorder()
	router.ServeHTTP(patchResponse, patchRequest)
	if patchResponse.Code != http.StatusOK {
		t.Fatalf("patch status = %d body = %s", patchResponse.Code, patchResponse.Body.String())
	}
	var patchResult struct {
		Entry struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			Reason     string `json:"reason"`
			ApprovedBy string `json:"approved_by"`
		} `json:"entry"`
	}
	if err := json.NewDecoder(patchResponse.Body).Decode(&patchResult); err != nil {
		t.Fatalf("Decode patch returned error: %v", err)
	}
	if patchResult.Entry.Status != "disabled" || patchResult.Entry.Reason != "vendor removed" || patchResult.Entry.ApprovedBy != "security" {
		t.Fatalf("patched entry = %#v, want disabled status metadata", patchResult.Entry)
	}
}

func TestHubRouterAllowsBrowserScriptFromFinding(t *testing.T) {
	inventory := newHTTPTestInventoryRepository()
	findings := newHTTPTestBrowserDriftFindingRepository()
	allowlist := newHTTPTestBrowserScriptAllowlistRepository()
	router := NewHubRouter(domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"}, hubapp.New(hubapp.Dependencies{Inventory: inventory, Findings: findings, BrowserAllowlist: allowlist}), HubOptions{})

	requestBody := bytes.NewBufferString(`{"reason":"reviewed vendor","approved_by":"roman"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/findings/finding-browser-1/browser-script-allowlist?org=acme&project=customer-site&environment=production&app=main-web", requestBody)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Finding struct {
			ID string `json:"id"`
		} `json:"finding"`
		Entry struct {
			Kind       string `json:"kind"`
			Value      string `json:"value"`
			PageURL    string `json:"page_url"`
			Reason     string `json:"reason"`
			ApprovedBy string `json:"approved_by"`
			Status     string `json:"status"`
		} `json:"entry"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if body.Finding.ID != "finding-browser-1" {
		t.Fatalf("finding = %#v, want browser finding", body.Finding)
	}
	if body.Entry.Kind != "domain" || body.Entry.Value != "cdn.reviewed.example" || body.Entry.PageURL != "https://example.test" || body.Entry.Status != "active" {
		t.Fatalf("entry = %#v, want browser script allowlist entry from finding", body.Entry)
	}
}

type httpTestBrowserScriptAllowlistRepository struct {
	entries map[domain.ID]domain.BrowserScriptAllowlistEntry
	next    int
}

type httpTestBrowserDriftFindingRepository struct {
	finding domain.HubFinding
}

func newHTTPTestBrowserDriftFindingRepository() *httpTestBrowserDriftFindingRepository {
	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	return &httpTestBrowserDriftFindingRepository{
		finding: domain.HubFinding{
			ID:              "finding-browser-1",
			OrganizationID:  "org-1",
			ProjectID:       "project-1",
			EnvironmentID:   "env-1",
			AppID:           "app-1",
			RuleID:          "browser-script-domain-new",
			RuleVersion:     "2026-05-12.1",
			DedupeKey:       "browser-drift-test",
			Severity:        domain.SeverityMedium,
			Confidence:      domain.ConfidenceMedium,
			Title:           "New browser script domain",
			FirstEventAt:    now,
			LastEventAt:     now,
			Status:          "open",
			StatusUpdatedAt: now,
			Metadata: map[string]any{
				"kind":     "domain",
				"page_url": "https://example.test/",
				"value":    "cdn.reviewed.example",
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
}

func (r *httpTestBrowserDriftFindingRepository) SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error) {
	return findings, nil
}

func (r *httpTestBrowserDriftFindingRepository) GetHubFinding(ctx context.Context, findingID domain.ID, environmentID domain.ID, appID domain.ID) (domain.HubFinding, error) {
	if r.finding.ID != findingID || r.finding.EnvironmentID != environmentID {
		return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
	}
	if appID != "" && r.finding.AppID != appID {
		return domain.HubFinding{}, fmt.Errorf("finding %q was not found", findingID)
	}
	return r.finding, nil
}

func (r *httpTestBrowserDriftFindingRepository) ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error) {
	finding, err := r.GetHubFinding(ctx, r.finding.ID, environmentID, appID)
	if err != nil {
		return nil, nil
	}
	return []domain.HubFinding{finding}, nil
}

func (r *httpTestBrowserDriftFindingRepository) UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error) {
	finding, err := r.GetHubFinding(ctx, findingID, environmentID, "")
	if err != nil {
		return domain.HubFinding{}, err
	}
	finding.Status = update.Status
	finding.StatusReason = update.Reason
	finding.StatusNote = update.Note
	finding.StatusActor = update.Actor
	r.finding = finding
	return finding, nil
}

func newHTTPTestBrowserScriptAllowlistRepository() *httpTestBrowserScriptAllowlistRepository {
	return &httpTestBrowserScriptAllowlistRepository{entries: map[domain.ID]domain.BrowserScriptAllowlistEntry{}}
}

func (r *httpTestBrowserScriptAllowlistRepository) SaveBrowserScriptAllowlistEntry(ctx context.Context, entry domain.BrowserScriptAllowlistEntry) (domain.BrowserScriptAllowlistEntry, error) {
	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	for id, existing := range r.entries {
		if existing.EnvironmentID == entry.EnvironmentID && existing.AppID == entry.AppID && existing.PageURL == entry.PageURL && existing.Kind == entry.Kind && existing.Value == entry.Value {
			entry.ID = id
			entry.CreatedAt = existing.CreatedAt
			entry.UpdatedAt = now
			r.entries[id] = entry
			return entry, nil
		}
	}
	r.next++
	entry.ID = domain.ID(fmt.Sprintf("allow-%d", r.next))
	entry.CreatedAt = now
	entry.UpdatedAt = now
	r.entries[entry.ID] = entry
	return entry, nil
}

func (r *httpTestBrowserScriptAllowlistRepository) ListBrowserScriptAllowlistEntries(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.BrowserScriptAllowlistEntry, error) {
	var entries []domain.BrowserScriptAllowlistEntry
	for _, entry := range r.entries {
		if entry.EnvironmentID == environmentID && entry.AppID == appID {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (r *httpTestBrowserScriptAllowlistRepository) UpdateBrowserScriptAllowlistEntryStatus(ctx context.Context, entryID domain.ID, environmentID domain.ID, appID domain.ID, update domain.BrowserScriptAllowlistStatusUpdate) (domain.BrowserScriptAllowlistEntry, error) {
	entry, ok := r.entries[entryID]
	if !ok || entry.EnvironmentID != environmentID || entry.AppID != appID {
		return domain.BrowserScriptAllowlistEntry{}, fmt.Errorf("allowlist entry %q was not found", entryID)
	}
	entry.Status = update.Status
	entry.Reason = update.Reason
	entry.ApprovedBy = update.ApprovedBy
	entry.UpdatedAt = time.Date(2026, 5, 13, 10, 5, 0, 0, time.UTC)
	r.entries[entryID] = entry
	return entry, nil
}
