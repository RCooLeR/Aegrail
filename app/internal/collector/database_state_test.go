package collector

import (
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateDatabaseSnapshotStateBaselinesThenDiffs(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "db-main.json")
	first := databaseStateTestResult(1, "aaa")
	diff, err := UpdateDatabaseSnapshotState(statePath, first)
	if err != nil {
		t.Fatalf("UpdateDatabaseSnapshotState returned error: %v", err)
	}
	if !diff.Baselined || diff.Skipped || len(diff.Changes) != 0 {
		t.Fatalf("first diff = %+v, want baseline only", diff)
	}

	second := databaseStateTestResult(2, "bbb")
	diff, err = UpdateDatabaseSnapshotState(statePath, second)
	if err != nil {
		t.Fatalf("UpdateDatabaseSnapshotState returned error on second update: %v", err)
	}
	if diff.Baselined || diff.Skipped || len(diff.Changes) != 2 {
		t.Fatalf("second diff = %+v, want two changes", diff)
	}
	changesByName := map[string]DatabaseSnapshotChange{}
	for _, change := range diff.Changes {
		changesByName[change.Current.Name] = change
	}
	usersChange := changesByName["wordpress.users.count"]
	if usersChange.Type != "changed" || usersChange.Previous.Count != 1 || usersChange.Current.Count != 2 {
		t.Fatalf("users change = %+v, want count 1 -> 2", usersChange)
	}
	pluginsChange := changesByName["wordpress.active_plugins.digest"]
	if pluginsChange.Type != "changed" || pluginsChange.Previous.ValueSHA256 != "aaa" || pluginsChange.Current.ValueSHA256 != "bbb" {
		t.Fatalf("plugins change = %+v, want digest aaa -> bbb", pluginsChange)
	}
}

func TestUpdateDatabaseSnapshotStateSkipsWarningOnlySnapshots(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "db-main.json")
	diff, err := UpdateDatabaseSnapshotState(statePath, DatabaseCollectResult{
		Name:       "main",
		Engine:     "mysql",
		Profile:    "wordpress",
		FinishedAt: time.Now().UTC(),
		Checks: []DatabaseCheckResult{
			{
				Name:    "wordpress.users.count",
				Status:  "warning",
				Metric:  "users",
				Table:   "wp_users",
				Message: "count query failed",
			},
		},
	})
	if err != nil {
		t.Fatalf("UpdateDatabaseSnapshotState returned error: %v", err)
	}
	if !diff.Skipped || diff.Baselined || len(diff.Changes) != 0 {
		t.Fatalf("diff = %+v, want skipped warning-only snapshot", diff)
	}
	if _, found, err := LoadDatabaseSnapshotState(statePath); err != nil || found {
		t.Fatalf("LoadDatabaseSnapshotState found=%t err=%v, want no state", found, err)
	}
}

func TestBuildDatabaseSnapshotDiffEvents(t *testing.T) {
	result := databaseStateTestResult(3, "ccc")
	diff := DatabaseSnapshotDiffResult{
		Changes: []DatabaseSnapshotChange{
			{
				Type: "changed",
				Previous: DatabaseSnapshotCheckState{
					Name:       "wordpress.admin_users.count",
					Status:     "ok",
					Metric:     "admin_users",
					Table:      "wp_usermeta",
					Count:      1,
					CountValid: true,
					Signature:  "count:1",
				},
				Current: DatabaseSnapshotCheckState{
					Name:       "wordpress.admin_users.count",
					Status:     "ok",
					Metric:     "admin_users",
					Table:      "wp_usermeta",
					Count:      2,
					CountValid: true,
					Signature:  "count:2",
				},
			},
		},
	}
	events := BuildDatabaseSnapshotDiffEvents(result, diff, map[string]string{"site_slug": "example-com"})
	if len(events) != 1 {
		t.Fatalf("events = %d, want one diff event", len(events))
	}
	event := events[0]
	if event.Type != "db.snapshot.check_changed" || event.Severity != "medium" {
		t.Fatalf("event type/severity = %s/%s, want changed/medium", event.Type, event.Severity)
	}
	if event.Labels["db_change_type"] != "changed" || event.Labels["site_slug"] != "example-com" {
		t.Fatalf("labels = %#v, want change and site labels", event.Labels)
	}
	if _, ok := event.Payload["previous"]; !ok {
		t.Fatalf("payload = %#v, want previous state", event.Payload)
	}
}

func databaseStateTestResult(users int64, pluginsHash string) DatabaseCollectResult {
	now := time.Now().UTC()
	return DatabaseCollectResult{
		StartedAt:  now.Add(-time.Second),
		FinishedAt: now,
		Name:       "main",
		Engine:     "mysql",
		Profile:    "wordpress",
		Checks: []DatabaseCheckResult{
			{
				Name:       "wordpress.users.count",
				Status:     "ok",
				Metric:     "users",
				Table:      "wp_users",
				Count:      users,
				CountValid: true,
			},
			{
				Name:        "wordpress.active_plugins.digest",
				Status:      "ok",
				Metric:      "active_plugins",
				Table:       "wp_options",
				OptionName:  "active_plugins",
				ValueSHA256: pluginsHash,
				ValueBytes:  42,
			},
		},
	}
}
