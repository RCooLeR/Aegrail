package wire

import (
	"testing"
	"time"
)

func TestEncryptBuildsWireEnvelope(t *testing.T) {
	nodePrivate, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	hubPrivate, hubPublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	if derived, err := PublicKeyFromPrivate(hubPrivate); err != nil || derived != hubPublic {
		t.Fatalf("PublicKeyFromPrivate = %q, %v; want %q", derived, err, hubPublic)
	}
	envelope, err := Encrypt([]byte(`{"hello":"hub"}`), "node-web-01", nodePrivate, hubPublic, time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if envelope.Schema != EnvelopeSchema || envelope.NodeID != "node-web-01" || envelope.Ciphertext == "" || envelope.Nonce == "" {
		t.Fatalf("envelope = %#v, want populated wire envelope", envelope)
	}
}
