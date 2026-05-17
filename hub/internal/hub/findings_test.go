package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestUpdateHubFindingStatusValidatesAndUpdatesFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	notifications := &memoryNotificationSink{}
	hub := New(Dependencies{Inventory: inventory, Findings: findings, Notifications: notifications})
	ctx := context.Background()

	environment, app, _, _ := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 15, 0, 0, 0, time.UTC)
	saved, err := findings.SaveHubFindings(ctx, []domain.HubFinding{
		{
			OrganizationID: environment.ProjectID,
			ProjectID:      "project-1",
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         "wordpress-admin-user-added",
			RuleVersion:    "2026-05-12.1",
			DedupeKey:      "finding-key",
			Severity:       domain.SeverityHigh,
			Confidence:     domain.ConfidenceHigh,
			Title:          "WordPress administrator added",
			FirstEventAt:   now,
			LastEventAt:    now,
		},
	})
	if err != nil {
		t.Fatalf("SaveHubFindings returned error: %v", err)
	}

	updated, err := hub.UpdateHubFindingStatus(ctx, UpdateHubFindingStatusInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		FindingID:        string(saved[0].ID),
		Status:           "ack",
		Reason:           "reviewed",
		Note:             "Looks expected after migration.",
		Actor:            "roman",
	})
	if err != nil {
		t.Fatalf("UpdateHubFindingStatus returned error: %v", err)
	}
	if updated.Status != "acknowledged" || updated.StatusReason != "reviewed" || updated.StatusActor != "roman" {
		t.Fatalf("updated finding = %#v, want acknowledged status metadata", updated)
	}
	if len(notifications.items) != 1 ||
		notifications.items[0].Type != "finding.status_updated" ||
		notifications.items[0].OldStatus != "open" ||
		notifications.items[0].NewStatus != "acknowledged" ||
		notifications.items[0].Actor != "roman" {
		t.Fatalf("notifications = %#v, want status update notification", notifications.items)
	}

	if _, err := hub.UpdateHubFindingStatus(ctx, UpdateHubFindingStatusInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		FindingID:        string(saved[0].ID),
		Status:           "ignored",
	}); err == nil {
		t.Fatal("UpdateHubFindingStatus returned nil error for unsupported status")
	}
}

type memoryNotificationSink struct {
	items []ports.HubFindingNotification
}

func (s *memoryNotificationSink) NotifyHubFinding(_ context.Context, notification ports.HubFindingNotification) error {
	s.items = append(s.items, notification)
	return nil
}

func TestAcceptHubFindingsBaselineMarksOpenFindingsAcknowledged(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Findings: findings})
	ctx := context.Background()

	environment, app, _, _ := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 16, 0, 0, 0, time.UTC)
	saved, err := findings.SaveHubFindings(ctx, []domain.HubFinding{
		{
			OrganizationID: environment.ProjectID,
			ProjectID:      "project-1",
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         "wordpress-admin-user-added",
			RuleVersion:    "2026-05-12.1",
			DedupeKey:      "finding-key-1",
			Severity:       domain.SeverityHigh,
			Confidence:     domain.ConfidenceHigh,
			Title:          "WordPress administrator added",
			FirstEventAt:   now,
			LastEventAt:    now,
		},
		{
			OrganizationID: environment.ProjectID,
			ProjectID:      "project-1",
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         "browser-script-domain-new",
			RuleVersion:    "2026-05-12.1",
			DedupeKey:      "finding-key-2",
			Severity:       domain.SeverityMedium,
			Confidence:     domain.ConfidenceMedium,
			Title:          "New browser script domain",
			FirstEventAt:   now,
			LastEventAt:    now,
		},
	})
	if err != nil {
		t.Fatalf("SaveHubFindings returned error: %v", err)
	}
	if _, err := hub.UpdateHubFindingStatus(ctx, UpdateHubFindingStatusInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		FindingID:        string(saved[1].ID),
		Status:           "resolved",
		Reason:           "fixed",
	}); err != nil {
		t.Fatalf("UpdateHubFindingStatus returned error: %v", err)
	}

	result, err := hub.AcceptHubFindingsBaseline(ctx, AcceptHubFindingsBaselineInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Actor:            "roman",
	})
	if err != nil {
		t.Fatalf("AcceptHubFindingsBaseline returned error: %v", err)
	}
	if result.Updated != 1 || result.Status != "acknowledged" || result.Reason != "baseline_accepted" || result.Actor != "roman" {
		t.Fatalf("result = %#v, want one acknowledged baseline update", result)
	}

	records, err := hub.ListHubFindings(ctx, ListHubFindingsInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Limit:            10,
	})
	if err != nil {
		t.Fatalf("ListHubFindings returned error: %v", err)
	}
	statusByID := map[domain.ID]string{}
	reasonByID := map[domain.ID]string{}
	for _, finding := range records {
		statusByID[finding.ID] = finding.Status
		reasonByID[finding.ID] = finding.StatusReason
	}
	if statusByID[saved[0].ID] != "acknowledged" || reasonByID[saved[0].ID] != "baseline_accepted" {
		t.Fatalf("first finding status = %q/%q, want accepted baseline", statusByID[saved[0].ID], reasonByID[saved[0].ID])
	}
	if statusByID[saved[1].ID] != "resolved" {
		t.Fatalf("resolved finding status = %q, want unchanged", statusByID[saved[1].ID])
	}
}
