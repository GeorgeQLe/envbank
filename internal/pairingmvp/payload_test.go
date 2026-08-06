package pairingmvp

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validPayload() Payload {
	return Payload{Server: "http://127.0.0.1:7337", VaultID: strings.Repeat("A", 24),
		DeviceID: strings.Repeat("b", 24), Fingerprint: "0123456789abcdef",
		CreatedAt: "2026-08-05T12:00:00Z"}
}

func TestPayloadRoundTrip(t *testing.T) {
	want := validPayload()
	encoded, err := EncodePayload(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestPayloadRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Payload)
	}{
		{"remote HTTP", func(p *Payload) { p.Server = "http://example.com" }},
		{"path", func(p *Payload) { p.Server += "/v1" }},
		{"query", func(p *Payload) { p.Server += "?x=1" }},
		{"empty query", func(p *Payload) { p.Server += "?" }},
		{"fragment", func(p *Payload) { p.Server += "#x" }},
		{"bad ID", func(p *Payload) { p.DeviceID = "../device" }},
		{"bad fingerprint", func(p *Payload) { p.Fingerprint = "0123" }},
		{"bad time", func(p *Payload) { p.CreatedAt = "yesterday" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPayload()
			tt.mutate(&p)
			if _, err := EncodePayload(p); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := DecodePayload("envbank-pairing:v2:e30"); err == nil {
		t.Fatal("accepted unsupported version")
	}
	if _, err := DecodePayload(PayloadPrefix + strings.Repeat("A", MaxPayloadSize)); err == nil {
		t.Fatal("accepted oversized payload")
	}
	raw := `{"device_id":"` + strings.Repeat("b", 24) + `","server":"http://127.0.0.1:7337","vault_id":"` + strings.Repeat("A", 24) + `","fingerprint":"0123456789abcdef","created_at":"2026-08-05T12:00:00Z"}`
	if _, err := DecodePayload(PayloadPrefix + base64.RawURLEncoding.EncodeToString([]byte(raw))); err == nil {
		t.Fatal("accepted non-canonical JSON")
	}
}

func FuzzDecodePayload(f *testing.F) {
	seed, _ := EncodePayload(validPayload())
	f.Add(seed)
	f.Add("envbank-pairing:v9:e30")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > MaxPayloadSize {
			input = input[:MaxPayloadSize]
		}
		_, _ = DecodePayload(input)
	})
}
