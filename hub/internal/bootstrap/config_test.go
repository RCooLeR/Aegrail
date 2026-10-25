package bootstrap

import (
	"strings"
	"testing"
	"time"
)

func TestEnvDurationExtendedParsesDaySuffix(t *testing.T) {
	t.Setenv("AEGRAIL_TEST_RETENTION", "180d")

	got := envDurationExtended("AEGRAIL_TEST_RETENTION", time.Hour)
	want := 180 * 24 * time.Hour
	if got != want {
		t.Fatalf("envDurationExtended = %s, want %s", got, want)
	}
}

func TestLoadConfigDefaultsRetentionToSixMonthsAndKeepsResolvedFindings(t *testing.T) {
	t.Setenv("AEGRAIL_RETENTION_EVENTS", "")
	t.Setenv("AEGRAIL_RETENTION_RESOLVED_FINDINGS", "")
	t.Setenv("AEGRAIL_RETENTION_MODEL_REPORTS", "")
	t.Setenv("AEGRAIL_RETENTION_AUTH_EVENTS", "")

	config := LoadConfig()
	want := 180 * 24 * time.Hour
	if config.Hub.RetentionEvents != want ||
		config.Hub.RetentionModelReports != want ||
		config.Hub.RetentionAuthEvents != want ||
		config.Hub.RetentionResolvedFindings != 0 {
		t.Fatalf("retention defaults = events %s, resolved %s, reports %s, auth %s; want events/reports/auth %s and resolved 0",
			config.Hub.RetentionEvents,
			config.Hub.RetentionResolvedFindings,
			config.Hub.RetentionModelReports,
			config.Hub.RetentionAuthEvents,
			want,
		)
	}
}

func TestLoadConfigDefaultsEmailNotificationsToHighSeverity(t *testing.T) {
	t.Setenv("AEGRAIL_NOTIFICATION_EMAIL_MIN_SEVERITY", "")

	config := LoadConfig()
	if config.Notifications.Email.MinSeverity != "high" {
		t.Fatalf("email min severity = %q, want high", config.Notifications.Email.MinSeverity)
	}
}

func TestLoadConfigChecksPendingMigrationsByDefault(t *testing.T) {
	t.Setenv("AEGRAIL_ALLOW_PENDING_MIGRATIONS", "")

	config := LoadConfig()
	if config.Hub.AllowPendingMigrations {
		t.Fatal("AllowPendingMigrations = true, want false by default")
	}
}

func TestLoadConfigCanAllowPendingMigrationsForEmergency(t *testing.T) {
	t.Setenv("AEGRAIL_ALLOW_PENDING_MIGRATIONS", "true")

	config := LoadConfig()
	if !config.Hub.AllowPendingMigrations {
		t.Fatal("AllowPendingMigrations = false, want true when explicitly enabled")
	}
}

func TestLoadConfigCanMigrateOnStart(t *testing.T) {
	t.Setenv("AEGRAIL_MIGRATE_ON_START", "true")

	config := LoadConfig()
	if !config.Hub.MigrateOnStart {
		t.Fatal("MigrateOnStart = false, want true when explicitly enabled")
	}
}

func TestLoadConfigRecordsInvalidEnvironmentValues(t *testing.T) {
	t.Setenv("AEGRAIL_OLLAMA_OFFLINE", "ture")
	t.Setenv("AEGRAIL_MODEL_ANALYSIS_LIMIT", "many")
	t.Setenv("AEGRAIL_OLLAMA_TIMEOUT", "forever")

	config := LoadConfig()
	err := Config{
		Database:    DatabaseConfig{URL: "postgres://example"},
		Hub:         HubConfig{WirePrivateKey: "wire-key", UserSecretKey: "user-secret"},
		ParseErrors: config.ParseErrors,
	}.ValidateServe()
	if err == nil {
		t.Fatal("ValidateServe returned nil error for invalid environment values")
	}
	for _, want := range []string{"AEGRAIL_OLLAMA_OFFLINE", "AEGRAIL_MODEL_ANALYSIS_LIMIT", "AEGRAIL_OLLAMA_TIMEOUT"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("ValidateServe error = %q, want %s", err.Error(), want)
		}
	}
}

func TestEnvDurationAcceptsBareZero(t *testing.T) {
	t.Setenv("AEGRAIL_TEST_ZERO_DURATION", "0")

	if got := envDuration("AEGRAIL_TEST_ZERO_DURATION", time.Minute); got != 0 {
		t.Fatalf("envDuration bare zero = %s, want 0", got)
	}
	if got := envDurationExtended("AEGRAIL_TEST_ZERO_DURATION", time.Minute); got != 0 {
		t.Fatalf("envDurationExtended bare zero = %s, want 0", got)
	}
}
