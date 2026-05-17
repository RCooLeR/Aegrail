package agent

import (
	"strings"
	"testing"
	"time"
)

func TestParseNginxCombinedAccessLog(t *testing.T) {
	event, ok := parseStructuredLogEvent("/var/log/nginx/access.log", `203.0.113.10 - admin [12/May/2026:09:10:11 +0000] "GET /wp-login.php?token=super-secret&ok=1 HTTP/1.1" 500 42 "https://example.test/start?session=abc" "curl/8.0"`)
	if !ok {
		t.Fatal("expected structured access event")
	}
	if event.Type != "log.access" || event.Parser != "nginx_access" || event.Severity != "medium" {
		t.Fatalf("event = %+v", event)
	}
	if !event.EventTime.Equal(time.Date(2026, 5, 12, 9, 10, 11, 0, time.UTC)) {
		t.Fatalf("event time = %s", event.EventTime)
	}
	if event.Payload["method"] != "GET" || event.Payload["path"] != "/wp-login.php" || event.Payload["status_code"] != 500 {
		t.Fatalf("payload = %#v", event.Payload)
	}
	query, _ := event.Payload["query_redacted"].(string)
	if strings.Contains(query, "super-secret") || !strings.Contains(query, "%5BREDACTED%5D") {
		t.Fatalf("query was not redacted: %q", query)
	}
	referer, _ := event.Payload["referer_redacted"].(string)
	if strings.Contains(referer, "abc") || !strings.Contains(referer, "[REDACTED]") {
		t.Fatalf("referer was not redacted: %q", referer)
	}
}

func TestParseApacheCombinedAccessLog(t *testing.T) {
	event, ok := parseStructuredLogEvent("/var/log/apache2/access.log", `198.51.100.9 - - [12/May/2026:09:11:12 +0000] "POST /admin123/index.php HTTP/2.0" 403 512 "-" "Mozilla/5.0"`)
	if !ok {
		t.Fatal("expected structured access event")
	}
	if event.Type != "log.access" || event.Parser != "apache_access" || event.Severity != "low" {
		t.Fatalf("event = %+v", event)
	}
	if event.Payload["method"] != "POST" || event.Payload["path"] != "/admin123/index.php" || event.Payload["protocol"] != "HTTP/2.0" {
		t.Fatalf("payload = %#v", event.Payload)
	}
}

func TestParsePHPErrorLog(t *testing.T) {
	event, ok := parseStructuredLogEvent("/var/log/php-fpm/error.log", `[12-May-2026 09:12:13 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function eval_shell() in /var/www/html/wp-content/uploads/avatar.php:14`)
	if !ok {
		t.Fatal("expected structured PHP error event")
	}
	if event.Type != "log.php_error" || event.Parser != "php_error" || event.Severity != "high" {
		t.Fatalf("event = %+v", event)
	}
	if event.Payload["level"] != "fatal_error" || event.Payload["file"] != "/var/www/html/wp-content/uploads/avatar.php" || event.Payload["line_number"] != 14 {
		t.Fatalf("payload = %#v", event.Payload)
	}
	if !event.EventTime.Equal(time.Date(2026, 5, 12, 9, 12, 13, 0, time.UTC)) {
		t.Fatalf("event time = %s", event.EventTime)
	}
}

func TestParseApachePHPFPMErrorLog(t *testing.T) {
	event, ok := parseStructuredLogEvent("/var/log/apache2/error.log", `[Tue May 12 09:13:14.123456 2026] [proxy_fcgi:error] [pid 1234] [client 203.0.113.20:52310] AH01071: Got error 'PHP message: PHP Warning: Undefined array key "token" in /var/www/html/index.php on line 22'`)
	if !ok {
		t.Fatal("expected structured Apache PHP error event")
	}
	if event.Type != "log.php_error" || event.Severity != "low" {
		t.Fatalf("event = %+v", event)
	}
	if event.Payload["apache_module"] != "proxy_fcgi" || event.Payload["apache_level"] != "error" || event.Payload["remote_addr"] != "203.0.113.20" {
		t.Fatalf("payload = %#v", event.Payload)
	}
	if event.Payload["file"] != "/var/www/html/index.php" || event.Payload["line_number"] != 22 {
		t.Fatalf("payload = %#v", event.Payload)
	}
}

func TestParseTorExitListSupportsBulkAndExitAddressFormats(t *testing.T) {
	ips, err := parseTorExitList(strings.NewReader(`
# Tor bulk list
203.0.113.10
ExitAddress 2001:db8::1 2026-05-12 09:00:00
not-an-ip
`))
	if err != nil {
		t.Fatalf("parseTorExitList returned error: %v", err)
	}
	if _, ok := ips["203.0.113.10"]; !ok {
		t.Fatalf("ips = %#v, want IPv4 address", ips)
	}
	if _, ok := ips["2001:db8::1"]; !ok {
		t.Fatalf("ips = %#v, want IPv6 address from ExitAddress line", ips)
	}
	if _, ok := ips["not-an-ip"]; ok {
		t.Fatalf("ips = %#v, did not expect invalid address", ips)
	}
}

func TestEnrichAccessLogEventWithTorExitRaisesAdminSeverity(t *testing.T) {
	line := logLine{
		Text: `203.0.113.10 - - [12/May/2026:09:10:11 +0000] "GET /wp-admin/ HTTP/1.1" 200 42 "-" "Mozilla/5.0"`,
	}
	event := logLineEvent("/var/log/nginx/access.log", line)
	matcher := &torExitSet{
		ips:       map[string]struct{}{"203.0.113.10": {}},
		source:    "test://tor-exits",
		checkedAt: time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC),
	}

	enrichAccessLogEventWithTor(&event, matcher)

	if event.Severity != "medium" {
		t.Fatalf("severity = %q, want medium for Tor admin request", event.Severity)
	}
	if event.Payload["remote_is_tor"] != true || event.Payload["remote_network"] != "tor_exit" {
		t.Fatalf("payload = %#v, want Tor metadata", event.Payload)
	}
	tags, ok := event.Payload["remote_tags"].([]string)
	if !ok || len(tags) != 1 || tags[0] != "tor_exit" {
		t.Fatalf("remote_tags = %#v, want tor_exit tag", event.Payload["remote_tags"])
	}
	if event.Payload["tor_exit_list_source"] != "test://tor-exits" || event.Payload["tor_exit_list_size"] != 1 {
		t.Fatalf("payload = %#v, want Tor source metadata", event.Payload)
	}
	if !strings.Contains(strings.ToLower(event.Message), "tor exit") {
		t.Fatalf("message = %q, want Tor context", event.Message)
	}
}

func TestMauticAccessLogFilterDropsRoutineTrackingNoise(t *testing.T) {
	event := logLineEvent("/var/log/nginx/access.log", logLine{
		Text: `203.0.113.10 - - [12/May/2026:09:10:11 +0000] "GET /index.php/r/abc123 HTTP/1.1" 302 42 "-" "Mozilla/5.0"`,
	})
	event.Labels = mergeStringMaps(event.Labels, map[string]string{"site_kind": "mautic"})
	if !shouldDropNoisyLogEvent(event) {
		t.Fatalf("event = %#v, want routine Mautic redirect dropped", event)
	}

	serverError := logLineEvent("/var/log/nginx/access.log", logLine{
		Text: `203.0.113.10 - - [12/May/2026:09:10:11 +0000] "GET /r/abc123 HTTP/1.1" 500 42 "-" "Mozilla/5.0"`,
	})
	serverError.Labels = mergeStringMaps(serverError.Labels, map[string]string{"site_kind": "mautic"})
	if shouldDropNoisyLogEvent(serverError) {
		t.Fatalf("event = %#v, want Mautic tracking server error kept", serverError)
	}

	admin := logLineEvent("/var/log/nginx/access.log", logLine{
		Text: `203.0.113.10 - - [12/May/2026:09:10:12 +0000] "GET /s/login HTTP/1.1" 200 42 "-" "Mozilla/5.0"`,
	})
	admin.Labels = mergeStringMaps(admin.Labels, map[string]string{"site_kind": "mautic"})
	if shouldDropNoisyLogEvent(admin) {
		t.Fatalf("event = %#v, want Mautic admin/login path kept", admin)
	}
}

func TestMauticAccessLogFilterDropsStaticClientNoiseButKeepsServerErrors(t *testing.T) {
	static404 := logLineEvent("/var/log/nginx/access.log", logLine{
		Text: `203.0.113.10 - - [12/May/2026:09:10:11 +0000] "GET /media/css/app.css HTTP/1.1" 404 42 "-" "Mozilla/5.0"`,
	})
	static404.Labels = mergeStringMaps(static404.Labels, map[string]string{"site_kind": "mautic"})
	if !shouldDropNoisyLogEvent(static404) {
		t.Fatalf("event = %#v, want static Mautic 404 dropped", static404)
	}

	static500 := logLineEvent("/var/log/nginx/access.log", logLine{
		Text: `203.0.113.10 - - [12/May/2026:09:10:12 +0000] "GET /media/css/app.css HTTP/1.1" 500 42 "-" "Mozilla/5.0"`,
	})
	static500.Labels = mergeStringMaps(static500.Labels, map[string]string{"site_kind": "mautic"})
	if shouldDropNoisyLogEvent(static500) {
		t.Fatalf("event = %#v, want static Mautic server error kept", static500)
	}
}
