package redaction

import (
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	value := RedactURL("https://example.test/admin?token=abc123&controller=AdminOrders")

	if strings.Contains(value, "abc123") {
		t.Fatalf("redacted URL still contains token: %s", value)
	}
	if !strings.Contains(value, "controller=AdminOrders") {
		t.Fatalf("redacted URL removed safe query value: %s", value)
	}
}

func TestRedactText(t *testing.T) {
	value := RedactText("password=super-secret api_key:abc authorization=Bearer auth-token Cookie: PHPSESSID=123")

	for _, secret := range []string{"super-secret", "abc", "auth-token", "PHPSESSID=123"} {
		if strings.Contains(value, secret) {
			t.Fatalf("redacted text still contains %q: %s", secret, value)
		}
	}
}

func TestRedactAnyRedactsNestedSensitiveFields(t *testing.T) {
	value := RedactAny(map[string]any{
		"url":          "https://example.test/admin?token=abc123&safe=yes",
		"access_token": "secret-token",
		"payload": map[string]any{
			"Authorization": "Bearer abc",
			"message":       "password=hunter2 safe text",
		},
	})

	encoded := value.(map[string]any)
	if encoded["access_token"] != marker {
		t.Fatalf("access token = %#v, want redacted marker", encoded["access_token"])
	}
	payload := encoded["payload"].(map[string]any)
	if payload["Authorization"] != marker {
		t.Fatalf("authorization = %#v, want redacted marker", payload["Authorization"])
	}
	text := encoded["url"].(string) + " " + payload["message"].(string)
	for _, secret := range []string{"abc123", "Bearer abc", "hunter2"} {
		if strings.Contains(text, secret) {
			t.Fatalf("redacted value still contains %q: %#v", secret, value)
		}
	}
	if !strings.Contains(encoded["url"].(string), "safe=yes") {
		t.Fatalf("redacted URL removed safe query value: %s", encoded["url"])
	}
}
