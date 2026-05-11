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
