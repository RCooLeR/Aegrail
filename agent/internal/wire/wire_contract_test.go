package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

const contractNodeID = "agt_contract_01"
const contractNodePrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
const contractHubPublicKey = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns"
const contractTimestamp = "2026-05-17T01:02:03Z"
const contractNonce = "WllYV1ZVVFNSUVBP"
const contractPlaintext = `{"schema":"aegrail.agent.queue.v1","batch_id":"contract-batch","events":[{"type":"file.changed","target":"/var/www/site/index.php"}]}`
const contractCiphertext = "C3YpQZ6N31ny-sdsWL1zkfkfU2YDc4CF6FrK6yvhEfKrhauC2QgyJ-h425WtdGlsh3RhWlFgd_vUuTO6u73BjkZaPkt3T2p125GWI1b1tBCH2ECRZz7331ysBkAOMAJ2_hj78vc-YANi9RjSV-nyQPST_bpULO4MBs6DdZ4XByumM0HavUJ1tqcOIJOZmN-h-_5wuDw"

func TestAgentWireContractMatchesHubFixture(t *testing.T) {
	envelope, err := encryptContractFixture([]byte(contractPlaintext))
	if err != nil {
		t.Fatalf("encryptContractFixture returned error: %v", err)
	}
	if envelope.Schema != EnvelopeSchema ||
		envelope.NodeID != contractNodeID ||
		envelope.Timestamp != contractTimestamp ||
		envelope.Nonce != contractNonce ||
		envelope.Ciphertext != contractCiphertext {
		t.Fatalf("contract envelope = %#v, want ciphertext fixture %q", envelope, contractCiphertext)
	}
}

func encryptContractFixture(plaintext []byte) (Envelope, error) {
	private, err := parsePrivateKey(contractNodePrivateKey)
	if err != nil {
		return Envelope{}, err
	}
	public, err := parsePublicKey(contractHubPublicKey)
	if err != nil {
		return Envelope{}, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return Envelope{}, err
	}
	block, err := aes.NewCipher(deriveKey(shared, contractNodeID))
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce, err := decode(contractNonce)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Schema:     EnvelopeSchema,
		NodeID:     contractNodeID,
		Timestamp:  contractTimestamp,
		Nonce:      contractNonce,
		Ciphertext: encode(aead.Seal(nil, nonce, plaintext, associatedData(EnvelopeSchema, contractNodeID, contractTimestamp))),
	}, nil
}
