package agent

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/redaction"
)

type structuredLogEvent struct {
	Type      string
	Parser    string
	EventTime time.Time
	Severity  string
	Message   string
	Payload   map[string]any
}

var accessLogPattern = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?.*$`)
var phpFileLinePattern = regexp.MustCompile(`(?i)\bin\s+(.+?)\s+on\s+line\s+(\d+)`)
var phpColonFileLinePattern = regexp.MustCompile(`(?i)\bin\s+([^'"\s]+):(\d+)(?:\s|$)`)

func parseStructuredLogEvent(path string, line string) (event structuredLogEvent, ok bool) {
	defer func() {
		if recover() != nil {
			event = structuredLogEvent{}
			ok = false
		}
	}()
	if event, ok := parseAccessLogEvent(path, line); ok {
		return event, true
	}
	if event, ok := parsePHPErrorLogEvent(path, line); ok {
		return event, true
	}
	return structuredLogEvent{}, false
}

func parseAccessLogEvent(path string, line string) (structuredLogEvent, bool) {
	match := accessLogPattern.FindStringSubmatch(line)
	if match == nil {
		return structuredLogEvent{}, false
	}

	status, err := strconv.Atoi(match[6])
	if err != nil {
		return structuredLogEvent{}, false
	}
	method, requestTarget, protocol := parseHTTPLogRequest(match[5])
	requestPath, redactedQuery, redactedTarget := splitRequestTarget(requestTarget)
	eventTime, _ := time.Parse("02/Jan/2006:15:04:05 -0700", match[4])
	parser := accessLogParser(path)
	payload := map[string]any{
		"parser":                  parser,
		"log_kind":                "access",
		"remote_addr":             match[1],
		"remote_ident":            emptyDash(match[2]),
		"remote_user":             emptyDash(match[3]),
		"method":                  method,
		"path":                    requestPath,
		"query_redacted":          redactedQuery,
		"request_target_redacted": redactedTarget,
		"protocol":                protocol,
		"status_code":             status,
	}
	if !eventTime.IsZero() {
		payload["event_time"] = eventTime.UTC().Format(time.RFC3339)
	}
	if bytes, ok := parseLogBytes(match[7]); ok {
		payload["response_bytes"] = bytes
	}
	if len(match) > 8 && match[8] != "" && match[8] != "-" {
		payload["referer_redacted"] = redaction.RedactURL(match[8])
	}
	if len(match) > 9 && match[9] != "" && match[9] != "-" {
		payload["user_agent"] = redaction.RedactText(match[9])
	}

	messagePath := requestPath
	if messagePath == "" {
		messagePath = redactedTarget
	}
	message := fmt.Sprintf("HTTP %d %s %s", status, method, messagePath)
	remoteAddr := strings.TrimSpace(match[1])
	if remoteAddr != "" && remoteAddr != "-" {
		message += " from " + remoteAddr
	}
	return structuredLogEvent{
		Type:      "log.access",
		Parser:    parser,
		EventTime: eventTime,
		Severity:  accessLogSeverity(status),
		Message:   message,
		Payload:   payload,
	}, true
}

func parsePHPErrorLogEvent(path string, line string) (structuredLogEvent, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "php") && !looksLikePHPLogPath(path) {
		return structuredLogEvent{}, false
	}

	brackets, remainder := leadingBracketValues(line)
	message := normalizePHPLogMessage(remainder)
	if message == "" {
		message = normalizePHPLogMessage(line)
	}
	level := detectPHPLevel(message)
	if level == "" && !strings.Contains(strings.ToLower(message), "php") {
		return structuredLogEvent{}, false
	}

	payload := map[string]any{
		"parser":              "php_error",
		"log_kind":            "php_error",
		"level":               level,
		"message_redacted":    redaction.RedactText(message),
		"source_log_redacted": redaction.RedactText(line),
	}
	eventTime := parseLogTimestamp(firstString(brackets))
	if !eventTime.IsZero() {
		payload["event_time"] = eventTime.UTC().Format(time.RFC3339)
	}
	addApacheErrorContext(payload, brackets)
	if file, lineNumber, ok := extractPHPFileLine(message); ok {
		payload["file"] = file
		payload["line_number"] = lineNumber
	}

	return structuredLogEvent{
		Type:      "log.php_error",
		Parser:    "php_error",
		EventTime: eventTime,
		Severity:  phpLogSeverity(level, message),
		Message:   phpLogSummary(level, message),
		Payload:   payload,
	}, true
}

func parseHTTPLogRequest(request string) (string, string, string) {
	parts := strings.Fields(request)
	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	if len(parts) == 2 {
		return parts[0], parts[1], ""
	}
	if len(parts) == 1 {
		return "", parts[0], ""
	}
	return "", "", ""
}

func splitRequestTarget(target string) (string, string, string) {
	if strings.TrimSpace(target) == "" || target == "-" {
		return "", "", ""
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return target, "", redaction.RedactURL(target)
	}
	path := parsed.Path
	if path == "" && parsed.Opaque != "" {
		path = parsed.Opaque
	}
	query := ""
	if parsed.RawQuery != "" {
		query = redaction.RedactQuery(parsed.RawQuery)
	}
	return path, query, redaction.RedactURL(target)
}

func accessLogParser(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(lower, "nginx"):
		return "nginx_access"
	case strings.Contains(lower, "apache"), strings.Contains(lower, "httpd"):
		return "apache_access"
	default:
		return "web_access"
	}
}

func accessLogSeverity(status int) string {
	switch {
	case status >= 500:
		return string(domain.SeverityMedium)
	case status >= 400:
		return string(domain.SeverityLow)
	default:
		return string(domain.SeverityInfo)
	}
}

func parseLogBytes(value string) (int64, bool) {
	if value == "-" || strings.TrimSpace(value) == "" {
		return 0, false
	}
	bytes, err := strconv.ParseInt(value, 10, 64)
	return bytes, err == nil
}

func commonLogStatus(line string) int {
	if event, ok := parseAccessLogEvent("", line); ok {
		status, _ := event.Payload["status_code"].(int)
		return status
	}
	return 0
}

func leadingBracketValues(line string) ([]string, string) {
	rest := strings.TrimSpace(line)
	var values []string
	for strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			break
		}
		values = append(values, rest[1:end])
		rest = strings.TrimSpace(rest[end+1:])
	}
	return values, rest
}

func parseLogTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	layouts := []string{
		"02-Jan-2006 15:04:05 MST",
		"02-Jan-2006 15:04:05 -0700",
		"02-Jan-2006 15:04:05",
		"Mon Jan _2 15:04:05.000000 2006",
		"Mon Jan _2 15:04:05 2006",
	}
	for _, layout := range layouts {
		if strings.Contains(layout, "MST") || strings.Contains(layout, "-0700") {
			parsed, err := time.Parse(layout, value)
			if err == nil {
				return parsed.UTC()
			}
			continue
		}
		parsed, err := time.ParseInLocation(layout, value, time.UTC)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func normalizePHPLogMessage(value string) string {
	message := strings.TrimSpace(strings.Trim(value, `"'`))
	lower := strings.ToLower(message)
	if index := strings.Index(lower, "php message:"); index >= 0 {
		message = strings.TrimSpace(message[index+len("php message:"):])
	}
	message = strings.TrimSpace(strings.Trim(message, `"'`))
	if strings.HasPrefix(strings.ToLower(message), "got error") {
		if index := strings.Index(message, "'"); index >= 0 {
			message = strings.TrimSpace(strings.Trim(message[index+1:], `"'`))
		}
	}
	return message
}

func detectPHPLevel(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "fatal error"), strings.Contains(lower, "uncaught"):
		return "fatal_error"
	case strings.Contains(lower, "parse error"):
		return "parse_error"
	case strings.Contains(lower, "php warning"), strings.Contains(lower, "warning"):
		return "warning"
	case strings.Contains(lower, "deprecated"):
		return "deprecated"
	case strings.Contains(lower, "php notice"), strings.Contains(lower, "notice"):
		return "notice"
	case strings.Contains(lower, "php error"), strings.Contains(lower, " error"):
		return "error"
	case strings.Contains(lower, "php"):
		return "php"
	default:
		return ""
	}
}

func phpLogSeverity(level string, message string) string {
	lower := strings.ToLower(message)
	switch {
	case level == "fatal_error",
		level == "parse_error",
		strings.Contains(lower, "segmentation fault"),
		strings.Contains(lower, "uncaught"):
		return string(domain.SeverityHigh)
	case level == "error":
		return string(domain.SeverityMedium)
	case level == "warning", level == "deprecated", level == "notice":
		return string(domain.SeverityLow)
	default:
		return string(domain.SeverityInfo)
	}
}

func phpLogSummary(level string, message string) string {
	if level == "" {
		level = "php"
	}
	if file, lineNumber, ok := extractPHPFileLine(message); ok {
		return fmt.Sprintf("PHP %s in %s:%d", strings.ReplaceAll(level, "_", " "), file, lineNumber)
	}
	return "PHP " + strings.ReplaceAll(level, "_", " ")
}

func extractPHPFileLine(message string) (string, int, bool) {
	if match := phpFileLinePattern.FindStringSubmatch(message); match != nil {
		lineNumber, err := strconv.Atoi(match[2])
		if err == nil {
			return strings.Trim(strings.TrimSpace(match[1]), `"'`), lineNumber, true
		}
	}
	if match := phpColonFileLinePattern.FindStringSubmatch(message); match != nil {
		lineNumber, err := strconv.Atoi(match[2])
		if err == nil {
			return strings.Trim(strings.TrimSpace(match[1]), `"'`), lineNumber, true
		}
	}
	return "", 0, false
}

func addApacheErrorContext(payload map[string]any, brackets []string) {
	if len(brackets) <= 1 {
		return
	}
	for _, value := range brackets[1:] {
		lower := strings.ToLower(value)
		switch {
		case strings.HasPrefix(lower, "pid "):
			payload["process_id"] = strings.TrimSpace(strings.TrimPrefix(value, "pid"))
		case strings.HasPrefix(lower, "client "):
			client := strings.TrimSpace(value[len("client "):])
			payload["remote_addr"] = stripPort(client)
		case strings.Contains(value, ":"):
			module, level, ok := strings.Cut(value, ":")
			if ok && module != "" && level != "" {
				payload["apache_module"] = module
				payload["apache_level"] = level
			}
		}
	}
}

func stripPort(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	if index := strings.LastIndex(value, ":"); index > 0 && strings.Count(value, ":") == 1 {
		return value[:index]
	}
	return value
}

func looksLikePHPLogPath(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(lower, "php") || strings.Contains(lower, "fpm")
}

func emptyDash(value string) string {
	if value == "-" {
		return ""
	}
	return value
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
