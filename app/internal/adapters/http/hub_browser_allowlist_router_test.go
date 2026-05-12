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

type httpTestBrowserScriptAllowlistRepository struct {
	entries map[domain.ID]domain.BrowserScriptAllowlistEntry
	next    int
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
