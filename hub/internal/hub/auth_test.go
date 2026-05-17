package hub

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

func TestHubTOTPCodeCannotBeReplayedInSameWindow(t *testing.T) {
	h := New(Dependencies{})
	secret := "JBSWY3DPEHPK3PXP"
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("DecodeString returned error: %v", err)
	}
	at := time.Unix(1710000000, 0).UTC()
	code := generateTOTPCode(secretBytes, uint64(at.Unix()/30))
	userID := domain.ID("user-1")

	if !h.verifyAndConsumeTOTPCode(userID, secret, code, at) {
		t.Fatalf("first TOTP verification was rejected")
	}
	if h.verifyAndConsumeTOTPCode(userID, secret, code, at.Add(10*time.Second)) {
		t.Fatalf("replayed TOTP code was accepted inside the same 90-second window")
	}
}
