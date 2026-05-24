package wire

import (
	"bytes"
	"testing"
	"time"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	hubPrivate, hubPublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	nodePrivate, nodePublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	plaintext := []byte(`{"hello":"wire"}`)
	envelope, err := Encrypt(plaintext, "node-web-01", nodePrivate, hubPublic, now)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	decrypted, err := Decrypt(envelope, nodePublic, hubPrivate, now, time.Minute)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %s, want %s", decrypted, plaintext)
	}
}

func TestDecryptRejectsWrongNodeKey(t *testing.T) {
	hubPrivate, hubPublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	nodePrivate, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	_, wrongNodePublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair wrong node returned error: %v", err)
	}
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	envelope, err := Encrypt([]byte(`{"hello":"wire"}`), "node-web-01", nodePrivate, hubPublic, now)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if _, err := Decrypt(envelope, wrongNodePublic, hubPrivate, now, time.Minute); err == nil {
		t.Fatal("Decrypt returned nil error for wrong node public key")
	}
}

func TestDecryptRejectsExpiredEnvelope(t *testing.T) {
	hubPrivate, hubPublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	nodePrivate, nodePublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	envelope, err := Encrypt([]byte(`{"hello":"wire"}`), "node-web-01", nodePrivate, hubPublic, now)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if _, err := Decrypt(envelope, nodePublic, hubPrivate, now.Add(10*time.Minute), time.Minute); err == nil {
		t.Fatal("Decrypt returned nil error for expired envelope")
	}
}

func TestDecryptRejectsTamperedEnvelope(t *testing.T) {
	hubPrivate, hubPublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	nodePrivate, nodePublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	envelope, err := Encrypt([]byte(`{"hello":"wire"}`), "node-web-01", nodePrivate, hubPublic, now)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	ciphertext, err := decode(envelope.Ciphertext)
	if err != nil {
		t.Fatalf("ciphertext decode returned error: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x01
	envelope.Ciphertext = encode(ciphertext)
	if _, err := Decrypt(envelope, nodePublic, hubPrivate, now, time.Minute); err == nil {
		t.Fatal("Decrypt returned nil error for tampered ciphertext")
	}
}

func TestDecryptRejectsMismatchedNodeID(t *testing.T) {
	hubPrivate, hubPublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair hub returned error: %v", err)
	}
	nodePrivate, nodePublic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair node returned error: %v", err)
	}
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	envelope, err := Encrypt([]byte(`{"hello":"wire"}`), "node-web-01", nodePrivate, hubPublic, now)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	envelope.NodeID = "node-web-02"
	if _, err := Decrypt(envelope, nodePublic, hubPrivate, now, time.Minute); err == nil {
		t.Fatal("Decrypt returned nil error for mismatched node id")
	}
}
