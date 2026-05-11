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
var cookiePattern = regexp.MustCompile(`(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+`)

func RedactText(value string) string {
	redacted := assignmentPattern.ReplaceAllStringFunc(value, func(match string) string {
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

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
	_, ok := sensitiveKeys[normalized]
	return ok
}
