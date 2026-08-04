package secure

import (
	"bytes"
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
