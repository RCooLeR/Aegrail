package hub

import (
	"context"
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestUpdateHubFindingStatusValidatesAndUpdatesFinding(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Findings: findings})
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
