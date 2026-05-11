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
	value := RedactText("password=super-secret api_key:abc Cookie: PHPSESSID=123")

	for _, secret := range []string{"super-secret", "abc", "PHPSESSID=123"} {
		if strings.Contains(value, secret) {
			t.Fatalf("redacted text still contains %q: %s", secret, value)
		}
	}
}
