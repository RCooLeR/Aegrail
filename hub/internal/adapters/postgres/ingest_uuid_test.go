package postgres

import (
	"testing"
	"uuid"
)

func TestNewUUIDStringUsesVersion7(t *testing.T) {
	generated := newUUIDString()
	parsed, err := uuid.Parse(generated)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", generated, err)
	}
	if got := parsed[6] >> 4; got != 7 {
		t.Fatalf("version bits = %d, want 7", got)
	}
	if got := parsed[8] >> 6; got != 2 {
		t.Fatalf("variant bits = %d, want RFC 9562 variant 2", got)
	}

	next := uuid.MustParse(newUUIDString())
	if parsed.Compare(next) >= 0 {
		t.Fatalf("generated UUIDv7 values are not increasing: %s then %s", parsed, next)
	}
}
