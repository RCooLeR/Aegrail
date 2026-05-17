package collector

import (
	"fmt"
	"strings"
	"time"
)

type DatabaseSnapshotEvent struct {
	EventTime time.Time
	Type      string
	Target    string
	Severity  string
	Message   string
	Labels    map[string]string
	Payload   map[string]any
}

func BuildDatabaseSnapshotEvents(result DatabaseCollectResult, baseLabels map[string]string) []DatabaseSnapshotEvent {
	eventTime := result.FinishedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	labels := databaseEventLabels(baseLabels, result, nil)
	warningCount := len(result.Warnings)
	events := []DatabaseSnapshotEvent{
		{
			EventTime: eventTime,
			Type:      "db.snapshot.completed",
			Target:    result.Name,
			Severity:  databaseSnapshotSeverity(warningCount),
			Message:   fmt.Sprintf("Database snapshot completed for %s with %d check(s)", result.Name, len(result.Checks)),
			Labels:    labels,
			Payload: map[string]any{
				"database":        result.Name,
				"engine":          result.Engine,
				"profile":         result.Profile,
				"check_count":     len(result.Checks),
				"entity_count":    len(result.Entities),
				"warning_count":   warningCount,
				"run_started_at":  result.StartedAt.Format(time.RFC3339Nano),
				"run_finished_at": result.FinishedAt.Format(time.RFC3339Nano),
			},
		},
	}

	for _, check := range result.Checks {
		checkLabels := databaseEventLabels(baseLabels, result, map[string]string{
			"db_check":  check.Name,
			"db_metric": check.Metric,
			"db_status": check.Status,
			"db_table":  check.Table,
		})
		payload := map[string]any{
			"database": result.Name,
			"engine":   result.Engine,
			"profile":  result.Profile,
			"check":    check.Name,
			"status":   check.Status,
			"metric":   check.Metric,
			"table":    check.Table,
		}
		if check.CountValid {
			payload["count"] = check.Count
		}
		if check.OptionName != "" {
			payload["option_name"] = check.OptionName
		}
		if check.ValueSHA256 != "" {
			payload["value_sha256"] = check.ValueSHA256
			payload["value_bytes"] = check.ValueBytes
		}
		if check.Message != "" {
			payload["message"] = check.Message
		}
		events = append(events, DatabaseSnapshotEvent{
			EventTime: eventTime,
			Type:      "db.snapshot.check",
			Target:    databaseCheckTarget(result, check),
			Severity:  databaseCheckSeverity(check),
			Message:   databaseCheckMessage(result, check),
			Labels:    checkLabels,
			Payload:   payload,
		})
	}

	for _, warning := range result.Warnings {
		warning = strings.TrimSpace(warning)
		if warning == "" {
			continue
		}
		events = append(events, DatabaseSnapshotEvent{
			EventTime: eventTime,
			Type:      "db.coverage.warning",
			Target:    result.Name,
			Severity:  "medium",
			Message:   warning,
			Labels:    labels,
			Payload: map[string]any{
				"database": result.Name,
				"engine":   result.Engine,
				"profile":  result.Profile,
				"warning":  warning,
			},
		})
	}
	return events
}

func BuildDatabaseSnapshotDiffEvents(result DatabaseCollectResult, diff DatabaseSnapshotDiffResult, baseLabels map[string]string) []DatabaseSnapshotEvent {
	if diff.Skipped {
		return nil
	}
	eventTime := result.FinishedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	labels := databaseEventLabels(baseLabels, result, nil)
	if diff.Baselined {
		return []DatabaseSnapshotEvent{
			{
				EventTime: eventTime,
				Type:      "db.snapshot.baseline_created",
				Target:    result.Name,
				Severity:  "info",
				Message:   fmt.Sprintf("Database snapshot baseline created for %s", result.Name),
				Labels:    labels,
				Payload: map[string]any{
					"database":     result.Name,
					"engine":       result.Engine,
					"profile":      result.Profile,
					"check_count":  len(BuildDatabaseSnapshotState(result).Checks),
					"entity_count": len(BuildDatabaseSnapshotState(result).Entities),
				},
			},
		}
	}
	events := make([]DatabaseSnapshotEvent, 0, len(diff.Changes))
	for _, change := range diff.Changes {
		current := change.Current
		checkLabels := databaseEventLabels(baseLabels, result, map[string]string{
			"db_check":       current.Name,
			"db_metric":      current.Metric,
			"db_status":      current.Status,
			"db_table":       current.Table,
			"db_change_type": change.Type,
		})
		payload := map[string]any{
			"database":    result.Name,
			"engine":      result.Engine,
			"profile":     result.Profile,
			"change_type": change.Type,
			"check":       current.Name,
			"metric":      current.Metric,
			"table":       current.Table,
			"current":     databaseCheckStatePayload(current),
		}
		if change.Previous.Name != "" {
			payload["previous"] = databaseCheckStatePayload(change.Previous)
		}
		if current.OptionName != "" {
			payload["option_name"] = current.OptionName
		}
		events = append(events, DatabaseSnapshotEvent{
			EventTime: eventTime,
			Type:      "db.snapshot.check_" + databaseChangeEventSuffix(change.Type),
			Target:    databaseStateTarget(result, current),
			Severity:  databaseDiffSeverity(current),
			Message:   databaseDiffMessage(result, change),
			Labels:    checkLabels,
			Payload:   payload,
		})
	}
	for _, change := range diff.EntityChanges {
		entity := change.Current
		if entity.Key == "" {
			entity = change.Previous
		}
		timing := databaseEntityEventTiming(change, diff.PreviousUpdatedAt, result.FinishedAt)
		entityLabels := databaseEventLabels(baseLabels, result, map[string]string{
			"db_entity_type": entity.Type,
			"db_entity_key":  entity.Key,
			"db_change_type": change.Type,
			"db_privileged":  boolLabel(entity.Privileged),
		})
		payload := map[string]any{
			"database":              result.Name,
			"engine":                result.Engine,
			"profile":               result.Profile,
			"change_type":           change.Type,
			"entity_type":           entity.Type,
			"entity_key":            entity.Key,
			"observed_at":           databaseFormatTime(result.FinishedAt),
			"event_time_source":     timing.Source,
			"event_time_confidence": timing.Confidence,
		}
		if timing.Suspicious {
			payload["timestamp_suspicious"] = true
			payload["timestamp_note"] = timing.Note
		}
		if change.Current.Key != "" {
			payload["current"] = databaseEntityStatePayload(change.Current)
		}
		if change.Previous.Key != "" {
			payload["previous"] = databaseEntityStatePayload(change.Previous)
		}
		events = append(events, DatabaseSnapshotEvent{
			EventTime: timing.EventTime,
			Type:      "db.entity." + databaseChangeEventSuffix(change.Type),
			Target:    databaseEntityTarget(result, entity),
			Severity:  databaseEntityDiffSeverity(entity),
			Message:   databaseEntityDiffMessage(result, change),
			Labels:    entityLabels,
			Payload:   payload,
		})
	}
	return events
}

func databaseEventLabels(base map[string]string, result DatabaseCollectResult, extra map[string]string) map[string]string {
	labels := make(map[string]string, len(base)+len(extra)+4)
	for key, value := range base {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			labels[key] = value
		}
	}
	labels["collector"] = "database"
	if result.Name != "" {
		labels["db_name"] = result.Name
	}
	if result.Engine != "" {
		labels["db_engine"] = result.Engine
	}
	if result.Profile != "" {
		labels["db_profile"] = result.Profile
	}
	for key, value := range extra {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			labels[key] = value
		}
	}
	return labels
}

func databaseSnapshotSeverity(warningCount int) string {
	if warningCount > 0 {
		return "medium"
	}
	return "info"
}

func databaseCheckSeverity(check DatabaseCheckResult) string {
	switch check.Status {
	case "warning":
		return "medium"
	case "missing":
		return "low"
	default:
		return "info"
	}
}

func databaseCheckTarget(result DatabaseCollectResult, check DatabaseCheckResult) string {
	if check.Table != "" && check.Metric != "" {
		return result.Name + ":" + check.Table + ":" + check.Metric
	}
	if check.Table != "" {
		return result.Name + ":" + check.Table
	}
	return result.Name + ":" + check.Name
}

func databaseCheckMessage(result DatabaseCollectResult, check DatabaseCheckResult) string {
	if check.Message != "" {
		return check.Message
	}
	switch {
	case check.ValueSHA256 != "":
		return fmt.Sprintf("Database check %s captured a redacted value digest", check.Name)
	case check.Status == "missing":
		return fmt.Sprintf("Database check %s did not find a value", check.Name)
	default:
		return fmt.Sprintf("Database check %s observed count %d", check.Name, check.Count)
	}
}

func databaseCheckStatePayload(state DatabaseSnapshotCheckState) map[string]any {
	payload := map[string]any{
		"name":      state.Name,
		"status":    state.Status,
		"metric":    state.Metric,
		"table":     state.Table,
		"signature": state.Signature,
	}
	if state.CountValid {
		payload["count"] = state.Count
	}
	if state.ValueSHA256 != "" {
		payload["value_sha256"] = state.ValueSHA256
		payload["value_bytes"] = state.ValueBytes
	}
	if state.OptionName != "" {
		payload["option_name"] = state.OptionName
	}
	return payload
}

func databaseEntityStatePayload(state DatabaseEntityState) map[string]any {
	payload := map[string]any{
		"type":       state.Type,
		"key":        state.Key,
		"label":      state.Label,
		"privileged": state.Privileged,
		"signature":  state.Signature,
	}
	if !state.SourceCreatedAt.IsZero() {
		payload["source_created_at"] = databaseFormatTime(state.SourceCreatedAt)
	}
	if !state.SourceUpdatedAt.IsZero() {
		payload["source_updated_at"] = databaseFormatTime(state.SourceUpdatedAt)
	}
	if len(state.Attributes) > 0 {
		payload["attributes"] = state.Attributes
	}
	return payload
}

func databaseStateTarget(result DatabaseCollectResult, state DatabaseSnapshotCheckState) string {
	if state.Table != "" && state.Metric != "" {
		return result.Name + ":" + state.Table + ":" + state.Metric
	}
	if state.Table != "" {
		return result.Name + ":" + state.Table
	}
	return result.Name + ":" + state.Name
}

func databaseEntityTarget(result DatabaseCollectResult, entity DatabaseEntityState) string {
	if entity.Label != "" {
		return result.Name + ":" + entity.Type + ":" + entity.Label
	}
	return result.Name + ":" + entity.Type + ":" + entity.Key
}

func databaseEntityDiffSeverity(entity DatabaseEntityState) string {
	if entity.Privileged {
		return "high"
	}
	switch entity.Type {
	case "wordpress_user", "wordpress_plugin", "wordpress_theme", "wordpress_option", "wordpress_cron", "wordpress_content_script", "prestashop_employee", "prestashop_module", "prestashop_configuration", "mautic_user", "mautic_role", "mautic_plugin", "mautic_integration", "mautic_oauth_client", "mautic_webhook", "yii2_rbac_user", "yii2_rbac_role_assignment", "yii2_rbac_item", "yii2_rbac_assignment", "laravel_user", "laravel_role", "laravel_permission", "laravel_role_assignment", "laravel_role_permission", "laravel_permission_assignment":
		return "medium"
	default:
		return "low"
	}
}

func databaseDiffSeverity(state DatabaseSnapshotCheckState) string {
	name := strings.ToLower(state.Name + " " + state.Metric)
	switch {
	case strings.Contains(name, "admin") ||
		strings.Contains(name, "capabilities") ||
		strings.Contains(name, "active_plugins") ||
		strings.Contains(name, "theme") ||
		strings.Contains(name, "cron") ||
		strings.Contains(name, "employee") ||
		strings.Contains(name, "active_modules") ||
		strings.Contains(name, "oauth") ||
		strings.Contains(name, "webhook") ||
		strings.Contains(name, "integration"):
		return "medium"
	default:
		return "low"
	}
}

func databaseDiffMessage(result DatabaseCollectResult, change DatabaseSnapshotChange) string {
	current := change.Current
	switch change.Type {
	case "added":
		return fmt.Sprintf("Database check %s was added to snapshot state for %s", current.Name, result.Name)
	default:
		return fmt.Sprintf("Database check %s changed for %s", current.Name, result.Name)
	}
}

func databaseEntityDiffMessage(result DatabaseCollectResult, change DatabaseEntityChange) string {
	entity := change.Current
	if entity.Key == "" {
		entity = change.Previous
	}
	if entity.Privileged {
		return fmt.Sprintf("Privileged database entity %s %s for %s", entity.Type, change.Type, result.Name)
	}
	return fmt.Sprintf("Database entity %s %s for %s", entity.Type, change.Type, result.Name)
}

func databaseChangeEventSuffix(value string) string {
	switch strings.TrimSpace(value) {
	case "added":
		return "added"
	case "removed":
		return "removed"
	default:
		return "changed"
	}
}

type databaseEventTiming struct {
	EventTime  time.Time
	Source     string
	Confidence string
	Suspicious bool
	Note       string
}

func databaseEntityEventTiming(change DatabaseEntityChange, previousSnapshotAt time.Time, observedAt time.Time) databaseEventTiming {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedAt = observedAt.UTC()
	if change.Type == "removed" {
		return databaseObservedTiming(observedAt, "removed records only have an observed disappearance time")
	}
	current := change.Current
	candidate, source := databaseEntityCandidateTime(change.Type, current)
	if candidate.IsZero() {
		return databaseObservedTiming(observedAt, "record has no usable source timestamp")
	}
	candidate = candidate.UTC()
	timing := databaseEventTiming{
		EventTime:  candidate,
		Source:     source,
		Confidence: "source",
	}
	if candidate.After(observedAt.Add(2 * time.Minute)) {
		timing.EventTime = observedAt
		timing.Source = "observed_at"
		timing.Confidence = "observed"
		timing.Suspicious = true
		timing.Note = "source database timestamp is in the future relative to scan time"
		return timing
	}
	if !previousSnapshotAt.IsZero() && candidate.Before(previousSnapshotAt.Add(-2*time.Minute)) {
		timing.EventTime = observedAt
		timing.Source = "observed_at"
		timing.Confidence = "observed"
		timing.Suspicious = true
		timing.Note = "record appeared or changed after the previous snapshot but source timestamp predates that snapshot"
	}
	return timing
}

func databaseEntityCandidateTime(changeType string, state DatabaseEntityState) (time.Time, string) {
	switch changeType {
	case "added":
		if !state.SourceCreatedAt.IsZero() {
			return state.SourceCreatedAt, "source_created_at"
		}
		if !state.SourceUpdatedAt.IsZero() {
			return state.SourceUpdatedAt, "source_updated_at"
		}
	case "changed":
		if !state.SourceUpdatedAt.IsZero() {
			return state.SourceUpdatedAt, "source_updated_at"
		}
		if !state.SourceCreatedAt.IsZero() {
			return state.SourceCreatedAt, "source_created_at"
		}
	}
	return time.Time{}, ""
}

func databaseObservedTiming(observedAt time.Time, note string) databaseEventTiming {
	return databaseEventTiming{
		EventTime:  observedAt,
		Source:     "observed_at",
		Confidence: "observed",
		Note:       note,
	}
}

func databaseFormatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
