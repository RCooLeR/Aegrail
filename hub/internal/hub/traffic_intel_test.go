package hub

import (
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestRecognizeTrafficProviderRequiresMatchedHostnameToBeVerified(t *testing.T) {
	names := []string{"crawl.googlebot.com", "confirmed.attacker.example"}
	match, recognized, verified := recognizeTrafficProvider(names, map[string]struct{}{
		"confirmed.attacker.example": {},
	})
	if !recognized || match.KnownActor != "Google" {
		t.Fatalf("recognition = (%#v, %v), want unverified Google recognition", match, recognized)
	}
	if verified {
		t.Fatal("provider was verified by a different forward-confirmed hostname")
	}

	match, recognized, verified = recognizeTrafficProvider(names, map[string]struct{}{
		"crawl.googlebot.com": {},
	})
	if !recognized || !verified || match.KnownActor != "Google" {
		t.Fatalf("recognition = (%#v, %v, %v), want verified Google", match, recognized, verified)
	}
}

func TestRecognizeTrafficProviderDoesNotVerifyContainsOnlyFingerprint(t *testing.T) {
	name := "confirmed-ahrefs.evil.example"
	match, recognized, verified := recognizeTrafficProvider([]string{name}, map[string]struct{}{name: {}})
	if !recognized || match.KnownActor != "Ahrefs" {
		t.Fatalf("recognition = (%#v, %v), want Ahrefs hint", match, recognized)
	}
	if verified {
		t.Fatal("contains-only reverse-DNS fingerprint became provider-verified")
	}
}

func TestLookupTrafficIPIntelDoesNotTrustRecognizedProvider(t *testing.T) {
	// Trust lives only in TrafficIPPolicy. The technical intel record has no
	// trusted field, so even verified provider evidence cannot grant trust.
	intel := lookupTrafficIPIntel(t.Context(), "127.0.0.1", testTrafficTime())
	if intel.ProviderVerified {
		t.Fatalf("loopback intel = %#v, want no provider verification", intel)
	}
}

func TestTrafficIPIntelRefreshErrorKeepsHintsButClearsVerification(t *testing.T) {
	cached := domain.TrafficIPIntel{
		IP:                 "203.0.113.9",
		ReverseDNS:         []string{"crawl.googlebot.com"},
		DNSVerified:        true,
		ProviderFamily:     "googlebot",
		RecognizedProvider: "Google",
		ProviderActorType:  "crawler",
		ProviderVerified:   true,
		LookupStatus:       "fresh",
	}
	refreshed := domain.TrafficIPIntel{
		IP:           "203.0.113.9",
		LookupStatus: "error",
		LastError:    "lookup timed out",
	}
	merged := trafficIPIntelWithStaleHints(cached, refreshed)
	if merged.RecognizedProvider != "Google" || len(merged.ReverseDNS) != 1 {
		t.Fatalf("merged hints = %#v, want last-known Google hints", merged)
	}
	if merged.LookupStatus != "error" || merged.DNSVerified || merged.ProviderVerified {
		t.Fatalf("merged verification = %#v, want error state with no current verification", merged)
	}
}

func testTrafficTime() time.Time {
	return time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
}
