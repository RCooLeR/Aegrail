package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const EnvelopeSchema = "aegrail.agent.wire.v1"

type Envelope struct {
	Schema     string `json:"schema"`
	NodeID     string `json:"node_id"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func GenerateKeyPair() (privateKey string, publicKey string, err error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return "", "", err
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", "", err
	}
	return encode(private.Bytes()), encode(private.PublicKey().Bytes()), nil
}

func PublicKeyFromPrivate(privateKey string) (string, error) {
	private, err := parsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return encode(private.PublicKey().Bytes()), nil
}

func PublicKeyFingerprint(publicKey string) (string, error) {
	raw, err := decode(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "X25519-SHA256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func Encrypt(plaintext []byte, nodeID string, nodeSecret string, hubPublicKey string, now time.Time) (Envelope, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return Envelope{}, errors.New("node id is required")
	}
	private, err := parsePrivateKey(nodeSecret)
	if err != nil {
		return Envelope{}, fmt.Errorf("node secret: %w", err)
	}
	public, err := parsePublicKey(hubPublicKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("hub public key: %w", err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return Envelope{}, err
	}
	key := deriveKey(shared, nodeID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	timestamp := now.UTC().Format(time.RFC3339)
	ad := associatedData(EnvelopeSchema, nodeID, timestamp)
	ciphertext := aead.Seal(nil, nonce, plaintext, ad)
	return Envelope{
		Schema:     EnvelopeSchema,
		NodeID:     nodeID,
		Timestamp:  timestamp,
		Nonce:      encode(nonce),
		Ciphertext: encode(ciphertext),
	}, nil
}

func Decrypt(envelope Envelope, nodePublicKey string, hubPrivateKey string, now time.Time, skew time.Duration) ([]byte, error) {
	if envelope.Schema != EnvelopeSchema {
		return nil, fmt.Errorf("unsupported envelope schema %q", envelope.Schema)
	}
	nodeID := strings.TrimSpace(envelope.NodeID)
	if nodeID == "" {
		return nil, errors.New("node id is required")
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(envelope.Timestamp))
	if err != nil {
		return nil, errors.New("invalid envelope timestamp")
	}
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	now = now.UTC()
	if parsed.Before(now.Add(-skew)) || parsed.After(now.Add(skew)) {
		return nil, errors.New("envelope timestamp is outside the accepted window")
	}
	private, err := parsePrivateKey(hubPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("hub private key: %w", err)
	}
	public, err := parsePublicKey(nodePublicKey)
	if err != nil {
		return nil, fmt.Errorf("node public key: %w", err)
	}
	nonce, err := decode(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext, err := decode(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	key := deriveKey(shared, nodeID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("nonce size %d is invalid", len(nonce))
	}
	ad := associatedData(envelope.Schema, nodeID, envelope.Timestamp)
	return aead.Open(nil, nonce, ciphertext, ad)
}

func parsePrivateKey(value string) (*ecdh.PrivateKey, error) {
	raw, err := decode(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

func parsePublicKey(value string) (*ecdh.PublicKey, error) {
	raw, err := decode(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return ecdh.X25519().NewPublicKey(raw)
}

func deriveKey(shared []byte, nodeID string) []byte {
	salt := sha256.Sum256([]byte("aegrail-wire-v1:" + nodeID))
	prkMAC := hmac.New(sha256.New, salt[:])
	prkMAC.Write(shared)
	prk := prkMAC.Sum(nil)
	outMAC := hmac.New(sha256.New, prk)
	outMAC.Write([]byte("aegrail agent-to-hub aes-256-gcm v1"))
	outMAC.Write([]byte{1})
	return outMAC.Sum(nil)[:32]
}

func associatedData(schema string, nodeID string, timestamp string) []byte {
	return []byte(schema + "\n" + nodeID + "\n" + timestamp)
}

func encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decode(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty value")
	}
	return base64.RawURLEncoding.DecodeString(value)
}
