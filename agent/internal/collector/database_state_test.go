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
	if diff.Baselined || diff.Skipped || len(diff.Changes) != 2 || len(diff.EntityChanges) != 1 {
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
	entityChange := diff.EntityChanges[0]
	if entityChange.Type != "changed" || !entityChange.Current.Privileged {
		t.Fatalf("entity change = %+v, want changed privileged user", entityChange)
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

func TestDatabaseSnapshotStateIgnoresPIIEvidenceFormatMigration(t *testing.T) {
	previous := DatabaseSnapshotState{
		Checks: map[string]DatabaseSnapshotCheckState{},
		Entities: map[string]DatabaseEntityState{
			"wordpress_user:abc": {
				Type:       "wordpress_user",
				Key:        "wordpress_user:abc",
				Label:      "wordpress_user:abc",
				Privileged: true,
				Signature:  "legacy",
				Attributes: map[string]any{
					"administrator":       true,
					"capabilities_sha256": "roles",
					"email_sha256":        "legacy-email",
					"has_capabilities":    true,
					"login_sha256":        "legacy-login",
					"user_id_hash":        "id",
				},
			},
		},
	}
	current := DatabaseSnapshotState{
		Checks: map[string]DatabaseSnapshotCheckState{},
		Entities: map[string]DatabaseEntityState{
			"wordpress_user:abc": {
				Type:       "wordpress_user",
				Key:        "wordpress_user:abc",
				Label:      "wordpress_user:r***n@example.com",
				Privileged: true,
				Signature:  "masked",
				Attributes: map[string]any{
					"account_display":     "r***n@example.com",
					"administrator":       true,
					"capabilities_sha256": "roles",
					"email_hmac_sha256":   "keyed-email",
					"email_masked":        "r***n@example.com",
					"has_capabilities":    true,
					"login_hmac_sha256":   "keyed-login",
					"login_masked":        "r***n",
					"user_id_hash":        "id",
				},
			},
		},
	}

	diff := DiffDatabaseSnapshotState(previous, true, current)
	if len(diff.EntityChanges) != 0 {
		t.Fatalf("entity changes = %+v, want no migration-only diff", diff.EntityChanges)
	}

	current.Entities["wordpress_user:abc"] = DatabaseEntityState{
		Type:       "wordpress_user",
		Key:        "wordpress_user:abc",
		Label:      "wordpress_user:r***n@example.com",
		Privileged: true,
		Signature:  "masked-role-change",
		Attributes: map[string]any{
			"account_display":     "r***n@example.com",
			"administrator":       true,
			"capabilities_sha256": "new-roles",
			"email_hmac_sha256":   "keyed-email",
			"email_masked":        "r***n@example.com",
			"has_capabilities":    true,
			"user_id_hash":        "id",
		},
	}
	diff = DiffDatabaseSnapshotState(previous, true, current)
	if len(diff.EntityChanges) != 1 || diff.EntityChanges[0].Type != "changed" {
		t.Fatalf("entity changes = %+v, want real capability change", diff.EntityChanges)
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

func TestBuildDatabaseSnapshotEntityDiffEvents(t *testing.T) {
	result := databaseStateTestResult(3, "ccc")
	diff := DatabaseSnapshotDiffResult{
		EntityChanges: []DatabaseEntityChange{
			{
				Type: "added",
				Current: DatabaseEntityState{
					Type:       "wordpress_user",
					Key:        "wordpress_user:abc",
					Label:      "wordpress_user:abc",
					Privileged: true,
					Signature:  "sig",
					Attributes: map[string]any{
						"administrator": true,
						"email_masked":  "a***n@example.com",
					},
				},
			},
		},
	}
	events := BuildDatabaseSnapshotDiffEvents(result, diff, map[string]string{"site_slug": "example-com"})
	if len(events) != 1 {
		t.Fatalf("events = %d, want one entity event", len(events))
	}
	event := events[0]
	if event.Type != "db.entity.added" || event.Severity != "high" {
		t.Fatalf("event type/severity = %s/%s, want entity added/high", event.Type, event.Severity)
	}
	if event.Labels["db_entity_type"] != "wordpress_user" || event.Labels["db_privileged"] != "true" {
		t.Fatalf("labels = %#v, want entity labels", event.Labels)
	}
	current, ok := event.Payload["current"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want current entity", event.Payload)
	}
	attributes, ok := current["attributes"].(map[string]any)
	if !ok || attributes["email_masked"] != "a***n@example.com" {
		t.Fatalf("current = %#v, want redacted attributes", current)
	}
}

func TestBuildDatabaseSnapshotEntityDiffEventsUsesSourceCreatedTime(t *testing.T) {
	previousSnapshotAt := time.Date(2026, 5, 17, 1, 0, 0, 0, time.UTC)
	sourceCreatedAt := previousSnapshotAt.Add(10 * time.Minute)
	observedAt := previousSnapshotAt.Add(15 * time.Minute)
	result := databaseStateTestResult(3, "ccc")
	result.FinishedAt = observedAt
	diff := DatabaseSnapshotDiffResult{
		PreviousUpdatedAt: previousSnapshotAt,
		EntityChanges: []DatabaseEntityChange{
			{
				Type: "added",
				Current: DatabaseEntityState{
					Type:            "wordpress_user",
					Key:             "wordpress_user:abc",
					Label:           "wordpress_user:admin@example.com",
					Privileged:      true,
					SourceCreatedAt: sourceCreatedAt,
					Signature:       "sig",
				},
			},
		},
	}

	events := BuildDatabaseSnapshotDiffEvents(result, diff, nil)
	if len(events) != 1 {
		t.Fatalf("events = %d, want one entity event", len(events))
	}
	event := events[0]
	if !event.EventTime.Equal(sourceCreatedAt) {
		t.Fatalf("event time = %s, want source created time %s", event.EventTime, sourceCreatedAt)
	}
	if event.Payload["event_time_source"] != "source_created_at" || event.Payload["event_time_confidence"] != "source" {
		t.Fatalf("payload = %#v, want source-created timing", event.Payload)
	}
	current := event.Payload["current"].(map[string]any)
	if current["source_created_at"] != sourceCreatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("current = %#v, want source_created_at", current)
	}
}

func TestBuildDatabaseSnapshotEntityDiffEventsFlagsBackdatedSourceTime(t *testing.T) {
	previousSnapshotAt := time.Date(2026, 5, 17, 1, 0, 0, 0, time.UTC)
	sourceCreatedAt := previousSnapshotAt.AddDate(-1, 0, 0)
	observedAt := previousSnapshotAt.Add(15 * time.Minute)
	result := databaseStateTestResult(3, "ccc")
	result.FinishedAt = observedAt
	diff := DatabaseSnapshotDiffResult{
		PreviousUpdatedAt: previousSnapshotAt,
		EntityChanges: []DatabaseEntityChange{
			{
				Type: "added",
				Current: DatabaseEntityState{
					Type:            "wordpress_user",
					Key:             "wordpress_user:abc",
					Label:           "wordpress_user:admin@example.com",
					Privileged:      true,
					SourceCreatedAt: sourceCreatedAt,
					Signature:       "sig",
				},
			},
		},
	}

	events := BuildDatabaseSnapshotDiffEvents(result, diff, nil)
	if len(events) != 1 {
		t.Fatalf("events = %d, want one entity event", len(events))
	}
	event := events[0]
	if !event.EventTime.Equal(observedAt) {
		t.Fatalf("event time = %s, want observed scan time %s", event.EventTime, observedAt)
	}
	if event.Payload["event_time_source"] != "observed_at" ||
		event.Payload["timestamp_suspicious"] != true {
		t.Fatalf("payload = %#v, want suspicious backdated source timestamp", event.Payload)
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
		Entities: []DatabaseEntityObservation{
			{
				Type:       "wordpress_user",
				Key:        "wordpress_user:admin",
				Label:      "wordpress_user:admin",
				Privileged: true,
				Attributes: map[string]any{
					"administrator":       true,
					"capabilities_sha256": pluginsHash,
				},
				Signature: pluginsHash,
			},
		},
	}
}
