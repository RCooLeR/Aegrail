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
