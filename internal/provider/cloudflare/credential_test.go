package cloudflare

import (
	"strings"
	"testing"
)

func TestCredentialAccountIsStableScopedAndOpaque(t *testing.T) {
	first, err := CredentialAccount("vault-id", "example/siftcut/staging")
	if err != nil {
		t.Fatal(err)
	}
	repeated, _ := CredentialAccount("vault-id", "example/siftcut/staging")
	other, _ := CredentialAccount("other-vault", "example/siftcut/staging")
	if first != repeated || first == other || !strings.HasPrefix(first, "v1:") ||
		strings.Contains(first, "vault-id") || strings.Contains(first, "siftcut") {
		t.Fatalf("credential account derivation is not stable, scoped, and opaque")
	}
}
