package hub

import (
	"encoding/base32"
	"strings"
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

func TestHubUserSecretEncryptionUsesHKDFV2(t *testing.T) {
	ciphertext, err := encryptHubUserSecret("strong local test secret", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("encryptHubUserSecret returned error: %v", err)
	}
	if !strings.HasPrefix(ciphertext, "v2:") {
		t.Fatalf("ciphertext version = %q, want v2", ciphertext)
	}
	plaintext, err := decryptHubUserSecret("strong local test secret", ciphertext)
	if err != nil {
		t.Fatalf("decryptHubUserSecret returned error: %v", err)
	}
	if plaintext != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	// Any non-v2 version tag must be rejected.
	if _, err := decryptHubUserSecret("strong local test secret", "v1:abc:def"); err == nil {
		t.Fatalf("non-v2 ciphertext was accepted without error")
	}
	if _, err := decryptHubUserSecret("strong local test secret", "v2:abc:def"); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("short nonce error = %v, want nonce error", err)
	}
}
