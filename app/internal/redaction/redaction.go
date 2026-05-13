package redaction

import (
	"net/url"
	"regexp"
	"strings"
)

const marker = "[REDACTED]"

var sensitiveKeys = map[string]struct{}{
	"api_key":       {},
	"apikey":        {},
	"auth":          {},
	"authorization": {},
	"access_token":  {},
	"password":      {},
	"passwd":        {},
	"pwd":           {},
	"secret":        {},
	"session":       {},
	"sessionid":     {},
	"sid":           {},
	"token":         {},
}

var assignmentPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|authorization|access[_-]?token|password|passwd|pwd|secret|session[_-]?id|session|token)\s*[:=]\s*[^&\s,;]+`)
var authorizationPattern = regexp.MustCompile(`(?i)\b(auth|authorization)\s*[:=]\s*(bearer|basic)\s+[^&\s,;]+`)
var cookiePattern = regexp.MustCompile(`(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+`)

func RedactText(value string) string {
	redacted := authorizationPattern.ReplaceAllStringFunc(value, func(match string) string {
		separator := strings.IndexAny(match, ":=")
		if separator < 0 {
			return marker
		}
		return strings.TrimSpace(match[:separator+1]) + marker
	})
	redacted = assignmentPattern.ReplaceAllStringFunc(redacted, func(match string) string {
		separator := strings.IndexAny(match, ":=")
		if separator < 0 {
			return marker
		}
		return strings.TrimSpace(match[:separator+1]) + marker
	})
	return cookiePattern.ReplaceAllString(redacted, "${1}: "+marker)
}

func RedactURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return RedactText(value)
	}

	query := parsed.Query()
	changed := false
	for key := range query {
		if isSensitiveKey(key) {
			query.Set(key, marker)
			changed = true
		}
	}
	if changed {
		parsed.RawQuery = query.Encode()
	}
	return RedactText(parsed.String())
}

func RedactQuery(value string) string {
	query, err := url.ParseQuery(value)
	if err != nil {
		return RedactText(value)
	}

	for key := range query {
		if isSensitiveKey(key) {
			query.Set(key, marker)
		}
	}
	return query.Encode()
}

func RedactAny(value any) any {
	return redactAny("", value)
}

func redactAny(key string, value any) any {
	if isSensitiveKey(key) {
		return marker
	}
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for itemKey, itemValue := range typed {
			redacted[itemKey] = redactAny(itemKey, itemValue)
		}
		return redacted
	case map[string]string:
		redacted := make(map[string]any, len(typed))
		for itemKey, itemValue := range typed {
			redacted[itemKey] = redactAny(itemKey, itemValue)
		}
		return redacted
	case []any:
		redacted := make([]any, 0, len(typed))
		for _, item := range typed {
			redacted = append(redacted, redactAny("", item))
		}
		return redacted
	case []string:
		redacted := make([]any, 0, len(typed))
		for _, item := range typed {
			redacted = append(redacted, redactAny("", item))
		}
		return redacted
	case string:
		if looksLikeURL(typed) {
			return RedactURL(typed)
		}
		return RedactText(typed)
	default:
		return value
	}
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	_, ok := sensitiveKeys[normalized]
	if ok {
		return true
	}
	for _, marker := range []string{"api_key", "authorization", "access_token", "password", "passwd", "secret", "session", "token"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func looksLikeURL(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}
