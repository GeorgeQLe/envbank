package secure

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealRoundTripAndAAD(t *testing.T) {
	key, _ := RandomBytes(32)
	blob, err := Seal(key, []byte("secret"), []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, blob, []byte("context"))
	if err != nil || string(got) != "secret" {
		t.Fatalf("round trip failed: %q, %v", got, err)
	}
	if _, err := Open(key, blob, []byte("wrong")); err == nil {
		t.Fatal("expected authentication failure for wrong AAD")
	}
}

func TestOpenRejectsInvalidNonceLength(t *testing.T) {
	key, _ := RandomBytes(32)
	blob, err := Seal(key, []byte("secret"), []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	blob.Nonce = Encode([]byte("short"))
	if _, err := Open(key, blob, []byte("context")); err == nil {
		t.Fatal("expected invalid nonce length to be rejected")
	}
}

func TestWrapVaultKeyRoundTrip(t *testing.T) {
	device, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	vaultKey, _ := RandomBytes(32)
	envelope, err := WrapVaultKey(vaultKey, device.WrappingPublic, "vault", "device")
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapVaultKey(envelope, device.Secrets.WrappingPrivate, "vault", "device")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, vaultKey) {
		t.Fatal("unwrapped key differs")
	}
}

func TestPBKDF2Vector(t *testing.T) {
	got := DeriveKey([]byte("password"), []byte("salt"), 1)
	const want = "Eg-2z_z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs"
	if Encode(got) != want {
		t.Fatalf("unexpected vector %s", Encode(got))
	}
}

func TestValidatePublicDeviceKeysRejectsMalformedAndNoncanonicalKeys(t *testing.T) {
	keys, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicDeviceKeys(keys.SigningPublic, keys.WrappingPublic); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		signing  string
		wrapping string
	}{
		{"padded signing", keys.SigningPublic + "=", keys.WrappingPublic},
		{"short signing", Encode(make([]byte, 31)), keys.WrappingPublic},
		{"padded wrapping", keys.SigningPublic, keys.WrappingPublic + "="},
		{"short wrapping", keys.SigningPublic, Encode(make([]byte, 31))},
		{"low-order wrapping point", keys.SigningPublic, Encode(make([]byte, 32))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidatePublicDeviceKeys(test.signing, test.wrapping); err == nil {
				t.Fatal("invalid keys were accepted")
			}
		})
	}
}

func TestPublicKeysFromSecrets(t *testing.T) {
	keys, err := NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	signing, wrapping, err := PublicKeysFromSecrets(keys.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	if signing != keys.SigningPublic || wrapping != keys.WrappingPublic {
		t.Fatal("derived public keys do not match generated identity")
	}
	keys.Secrets.SigningPrivate += "="
	if _, _, err := PublicKeysFromSecrets(keys.Secrets); err == nil ||
		!strings.Contains(err.Error(), "signing") {
		t.Fatalf("noncanonical private key error = %v", err)
	}
}
