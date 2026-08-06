package protocol

import (
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

func TestValidateTimestampRequiresCanonicalUTCSeconds(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	if err := ValidateTimestamp("2026-08-06T12:00:00Z", now); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"2026-08-06T08:00:00-04:00",
		"2026-08-06T12:00:00.000Z",
		"2026-08-06T12:00:00+00:00",
		"2026-08-06T11:54:59Z",
	} {
		if err := ValidateTimestamp(value, now); err == nil {
			t.Errorf("accepted noncanonical or stale timestamp %q", value)
		}
	}
}

func TestValidateNonceRequiresCanonicalEighteenBytes(t *testing.T) {
	valid := secure.Encode([]byte("0123456789abcdefgh"))
	if err := ValidateNonce(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", valid + "=", secure.Encode([]byte("too short")),
		strings.Repeat("!", 24)} {
		if err := ValidateNonce(value); err == nil {
			t.Errorf("accepted invalid nonce %q", value)
		}
	}
}
