package domain

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$`)
var sourceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,62}$`)

func NormalizeSlug(kind string, value string) (string, error) {
	slug := strings.ToLower(strings.TrimSpace(value))
	if slug == "" {
		return "", fmt.Errorf("%s slug is required", kind)
	}
	if !slugPattern.MatchString(slug) {
		return "", fmt.Errorf("%s slug %q must use lowercase letters, numbers, and hyphens", kind, value)
	}
	return slug, nil
}

func NormalizeSourceType(value string) (string, error) {
	sourceType := strings.ToLower(strings.TrimSpace(value))
	if sourceType == "" {
		return "", errors.New("source type is required")
	}
	if !sourceTypePattern.MatchString(sourceType) {
		return "", fmt.Errorf("source type %q must use lowercase letters, numbers, underscores, and hyphens", value)
	}
	return sourceType, nil
}

func NormalizeBaseURL(value string) (string, error) {
	baseURL := strings.TrimSpace(value)
	if baseURL == "" {
		return "", nil
	}

	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return "", fmt.Errorf("site url %q is not valid: %w", value, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("site url %q must use http or https", value)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("site url %q must include a host", value)
	}
	return baseURL, nil
}
