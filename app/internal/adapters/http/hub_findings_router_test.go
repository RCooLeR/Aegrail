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
