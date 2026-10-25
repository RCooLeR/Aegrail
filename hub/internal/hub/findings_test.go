package hub

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
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
	mu    sync.Mutex
	items []ports.HubFindingNotification
	err   error
}

func (s *memoryNotificationSink) NotifyHubFinding(_ context.Context, notification ports.HubFindingNotification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, notification)
	if s.err != nil {
		return s.err
	}
	return nil
}

func TestUpdateHubFindingStatusDoesNotFailWhenNotificationFails(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	notifications := &memoryNotificationSink{err: errors.New("push provider unavailable")}
	hub := New(Dependencies{Inventory: inventory, Findings: findings, Notifications: notifications})
	ctx := context.Background()

	environment, app, _, _ := bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")
	now := time.Date(2026, 5, 12, 15, 30, 0, 0, time.UTC)
	saved, err := findings.SaveHubFindings(ctx, []domain.HubFinding{{
		OrganizationID: environment.ProjectID,
		ProjectID:      "project-1",
		EnvironmentID:  environment.ID,
		AppID:          app.ID,
		RuleID:         "wordpress-admin-user-added",
		RuleVersion:    "2026-05-12.1",
		DedupeKey:      "finding-key-notify-fails",
		Severity:       domain.SeverityHigh,
		Confidence:     domain.ConfidenceHigh,
		Title:          "WordPress administrator added",
		FirstEventAt:   now,
		LastEventAt:    now,
	}})
	if err != nil {
		t.Fatalf("SaveHubFindings returned error: %v", err)
	}

	updated, err := hub.UpdateHubFindingStatus(ctx, UpdateHubFindingStatusInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		FindingID:        string(saved[0].ID),
		Status:           "ack",
		Actor:            "roman",
	})
	if err != nil {
		t.Fatalf("UpdateHubFindingStatus returned error: %v", err)
	}
	if updated.Status != "acknowledged" {
		t.Fatalf("updated finding = %#v, want acknowledged despite notification failure", updated)
	}
	if len(notifications.items) != 1 {
		t.Fatalf("notifications = %#v, want attempted delivery", notifications.items)
	}
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
		{
			OrganizationID: environment.ProjectID,
			ProjectID:      "project-1",
			EnvironmentID:  environment.ID,
			AppID:          app.ID,
			RuleID:         "file-baseline-drift",
			RuleVersion:    "2026-05-12.1",
			DedupeKey:      "finding-key-3",
			Severity:       domain.SeverityMedium,
			Confidence:     domain.ConfidenceMedium,
			Title:          "File baseline drift",
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
	if statusByID[saved[0].ID] != "open" {
		t.Fatalf("high finding status = %q, want left open for manual acknowledgement", statusByID[saved[0].ID])
	}
	if statusByID[saved[1].ID] != "resolved" {
		t.Fatalf("resolved finding status = %q, want unchanged", statusByID[saved[1].ID])
	}
	if statusByID[saved[2].ID] != "acknowledged" || reasonByID[saved[2].ID] != "baseline_accepted" {
		t.Fatalf("medium finding status = %q/%q, want accepted baseline", statusByID[saved[2].ID], reasonByID[saved[2].ID])
	}
}

func TestListHubFindingsPageRejectsFiltersForLegacyRepository(t *testing.T) {
	inventory := newMemoryInventoryRepository()
	findings := newMemoryHubFindingRepository()
	hub := New(Dependencies{Inventory: inventory, Findings: findings})
	ctx := context.Background()
	bootstrapDatabaseDiffInventory(t, ctx, hub, "wordpress")

	page, err := hub.ListHubFindingsPage(ctx, ListHubFindingsPageInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Limit:            20,
	})
	if err != nil {
		t.Fatalf("unfiltered ListHubFindingsPage returned error: %v", err)
	}
	if page.SummaryIncluded || page.MatchedTotalIncluded {
		t.Fatalf("legacy page claimed exact counts: %#v", page)
	}

	_, err = hub.ListHubFindingsPage(ctx, ListHubFindingsPageInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		AppSlug:          "main-web",
		Limit:            20,
		Statuses:         []string{"open"},
	})
	if err == nil || !strings.Contains(err.Error(), "does not support filtered pagination") {
		t.Fatalf("ListHubFindingsPage error = %v, want unsupported filtered pagination", err)
	}
}

func TestHubFindingCursorRoundTrip(t *testing.T) {
	createdAt := time.Date(2026, 7, 29, 8, 4, 4, 654321000, time.FixedZone("test", 3*60*60))
	value, err := encodeHubFindingCursor(domain.HubFinding{
		ID:        "11111111-1111-1111-1111-111111111111",
		CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatalf("encodeHubFindingCursor returned error: %v", err)
	}
	cursor, err := decodeHubFindingCursor(value)
	if err != nil {
		t.Fatalf("decodeHubFindingCursor returned error: %v", err)
	}
	if cursor.ID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("cursor id = %q", cursor.ID)
	}
	if !cursor.CreatedAt.Equal(createdAt) || cursor.CreatedAt.Location() != time.UTC {
		t.Fatalf("cursor created = %v, want %v in UTC", cursor.CreatedAt, createdAt)
	}
}

func TestDecodeHubFindingCursorRejectsInvalidValues(t *testing.T) {
	invalidUUIDCursor := base64.RawURLEncoding.EncodeToString([]byte(`{"v":2,"created_at":"2026-07-29T08:04:04Z","id":"not-a-uuid"}`))
	for _, value := range []string{"not-base64", "e30", invalidUUIDCursor} {
		if _, err := decodeHubFindingCursor(value); err == nil {
			t.Fatalf("decodeHubFindingCursor(%q) returned nil error", value)
		}
	}
}
