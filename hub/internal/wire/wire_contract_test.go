package wire

import (
	"bytes"
	"testing"
	"time"
)

const contractNodeID = "agt_contract_01"
const contractNodePublicKey = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw"
const contractHubPrivateKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A"
const contractTimestamp = "2026-05-17T01:02:03Z"
const contractNonce = "WllYV1ZVVFNSUVBP"
const contractPlaintext = `{"schema":"aegrail.agent.queue.v1","batch_id":"contract-batch","events":[{"type":"file.changed","target":"/var/www/site/index.php"}]}`
const contractCiphertext = "C3YpQZ6N31ny-sdsWL1zkfkfU2YDc4CF6FrK6yvhEfKrhauC2QgyJ-h425WtdGlsh3RhWlFgd_vUuTO6u73BjkZaPkt3T2p125GWI1b1tBCH2ECRZz7331ysBkAOMAJ2_hj78vc-YANi9RjSV-nyQPST_bpULO4MBs6DdZ4XByumM0HavUJ1tqcOIJOZmN-h-_5wuDw"

func TestHubWireContractDecryptsAgentFixture(t *testing.T) {
	now := time.Date(2026, 5, 17, 1, 2, 3, 0, time.UTC)
	decrypted, err := Decrypt(Envelope{
		Schema:     EnvelopeSchema,
		NodeID:     contractNodeID,
		Timestamp:  contractTimestamp,
		Nonce:      contractNonce,
		Ciphertext: contractCiphertext,
	}, contractNodePublicKey, contractHubPrivateKey, now, time.Minute)
	if err != nil {
		t.Fatalf("Decrypt returned error for agent fixture: %v", err)
	}
	if !bytes.Equal(decrypted, []byte(contractPlaintext)) {
		t.Fatalf("decrypted = %s, want %s", decrypted, contractPlaintext)
	}
}
