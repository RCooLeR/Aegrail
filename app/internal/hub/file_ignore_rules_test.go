package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

func TestFilterIgnoredTimelineEventsDropsMatchingFilePathPrefix(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	events := []domain.TimelineEvent{
		{
			ID:        "ignored",
			EventTime: now,
			EventType: "file.modified",
			Target:    "modules/netreviews/logs/logs.txt",
			Severity:  domain.SeverityMedium,
			Payload: map[string]any{
				"relative_path": "modules/netreviews/logs/logs.txt",
			},
		},
		{
			ID:        "kept",
			EventTime: now,
			EventType: "file.modified",
			Target:    "modules/netreviews/netreviews.php",
			Severity:  domain.SeverityMedium,
			Payload: map[string]any{
				"relative_path": "modules/netreviews/netreviews.php",
			},
		},
		{
			ID:        "db",
			EventTime: now,
			EventType: "db.entity.added",
			Target:    "prestashop:employee:admin@example.test",
			Severity:  domain.SeverityHigh,
			Payload:   map[string]any{},
		},
	}

	filtered := filterIgnoredTimelineEvents(events, []domain.HubFileIgnoreRule{
		{
			MatchKind:       "file_path_prefix",
			NormalizedValue: "modules/netreviews/logs",
			Status:          "active",
		},
	})

	if len(filtered) != 2 {
		t.Fatalf("filtered events = %#v, want two kept events", filtered)
	}
	if filtered[0].ID != "kept" || filtered[1].ID != "db" {
		t.Fatalf("filtered event IDs = %s/%s, want kept/db", filtered[0].ID, filtered[1].ID)
	}
}

func TestDeriveFileIgnorePathPrefersChangedFileCommonParent(t *testing.T) {
	finding := domain.HubFinding{
		Metadata: map[string]any{
			"file_group_root": "modules/netreviews",
			"files": []any{
				"modules/netreviews/logs/logs.txt",
				"modules/netreviews/logs/errors.log",
			},
		},
	}

	path := deriveFileIgnorePathFromFinding(finding)
	if path != "modules/netreviews/logs" {
		t.Fatalf("path = %q, want logs directory", path)
	}
}
