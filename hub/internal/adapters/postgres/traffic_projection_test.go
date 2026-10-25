package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestBuildTrafficRequestProjectionSupportsTrafficAndAccessEvents(t *testing.T) {
	userAgent := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	event := domain.IngestEvent{
		EventType: "traffic.request",
		Payload: map[string]any{
			"remote_addr":             "[2001:db8::1]:443",
			"method":                  "get",
			"scheme":                  "HTTPS",
			"host":                    "example.test",
			"path":                    "/catalog",
			"query_redacted":          "page=2",
			"request_target_redacted": "/catalog?page=2",
			"status_code":             float64(200),
			"response_bytes":          float64(512),
			"request_time":            "0.125",
			"upstream_response_time":  "0.040, 0.050",
			"user_agent":              userAgent,
			"remote_is_tor":           "true",
		},
	}

	projection, ok := buildTrafficRequestProjection(event)
	if !ok {
		t.Fatal("traffic.request was not projected")
	}
	if projection.ClientIP != "2001:db8::1" || projection.Method != "GET" || projection.Scheme != "https" {
		t.Fatalf("projection scope fields = %#v", projection)
	}
	if projection.StatusCode != 200 || projection.ResponseBytes != int64(512) {
		t.Fatalf("status/bytes = (%#v, %#v), want (200, 512)", projection.StatusCode, projection.ResponseBytes)
	}
	if projection.RequestDurationMS != float64(125) || projection.UpstreamDurationMS != float64(40) {
		t.Fatalf("durations = (%#v, %#v), want (125, 40)", projection.RequestDurationMS, projection.UpstreamDurationMS)
	}
	wantHashBytes := sha256.Sum256([]byte(userAgent))
	wantHash := hex.EncodeToString(wantHashBytes[:])
	if projection.UserAgentHash != wantHash || !projection.Analysis.IsBot || projection.Analysis.Family != "googlebot" {
		t.Fatalf("user-agent projection = hash %q analysis %#v", projection.UserAgentHash, projection.Analysis)
	}
	if !projection.RemoteIsTor {
		t.Fatal("string Tor marker was not normalized")
	}

	event.EventType = "log.access"
	if _, ok := buildTrafficRequestProjection(event); !ok {
		t.Fatal("log.access was not projected")
	}
}

func TestBuildTrafficRequestProjectionRejectsInvalidTypedValues(t *testing.T) {
	projection, ok := buildTrafficRequestProjection(domain.IngestEvent{
		EventType: "log.access",
		Payload: map[string]any{
			"remote_addr":    "not-an-ip",
			"status_code":    999,
			"response_bytes": -1,
			"request_time":   "NaN",
		},
	})
	if !ok {
		t.Fatal("log.access should still project valid fields")
	}
	if projection.ClientIP != nil || projection.StatusCode != nil || projection.ResponseBytes != nil || projection.RequestDurationMS != nil {
		t.Fatalf("invalid typed values were retained: %#v", projection)
	}
	if _, ok := buildTrafficRequestProjection(domain.IngestEvent{EventType: "log.php_error"}); ok {
		t.Fatal("non-traffic event was projected")
	}
}

func TestNormalizedTrafficIPStripsIPv6ScopeZoneBeforeInetBinding(t *testing.T) {
	tests := map[string]string{
		"fe80::1%eth0":           "fe80::1",
		"[fe80::2%ethernet]:443": "fe80::2",
		"81.250.241.21/32":       "81.250.241.21",
		"2001:db8::21/128":       "2001:db8::21",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := normalizedTrafficIP(input); got != want {
				t.Fatalf("normalizedTrafficIP(%q) = %#v, want %q", input, got, want)
			}
		})
	}
	if got := normalizedTrafficIP("81.250.241.0/24"); got != nil {
		t.Fatalf("normalizedTrafficIP(non-host prefix) = %#v, want nil", got)
	}
}
