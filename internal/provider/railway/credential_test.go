package railway

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
	if first != repeated || first == other || strings.Contains(first, "siftcut") || strings.Contains(first, "vault-id") {
		t.Fatalf("credential account was not stable, scoped, and opaque: %q %q %q", first, repeated, other)
	}
}
