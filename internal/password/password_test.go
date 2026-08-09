package password

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDefaultsAndRequiredClasses(t *testing.T) {
	p := DefaultPolicy()
	value, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != DefaultLength {
		t.Fatalf("length = %d", len(value))
	}
	for _, class := range []string{Lowercase, Uppercase, Digits, Symbols} {
		if !strings.ContainsAny(value, class) {
			t.Fatalf("password lacks class %q", class)
		}
	}
	if strings.Trim(value, Lowercase+Uppercase+Digits+Symbols) != "" {
		t.Fatal("password contains a disallowed character")
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, length := range []int{7, 257} {
		p := DefaultPolicy()
		p.Length = length
		if _, err := Generate(p); err == nil {
			t.Fatalf("accepted length %d", length)
		}
	}
	p := Policy{Length: 24}
	if _, err := Generate(p); err == nil {
		t.Fatal("accepted no character classes")
	}
	for _, length := range []int{8, 256} {
		p := Policy{Length: length, Digits: true}
		value, err := Generate(p)
		if err != nil || len(value) != length || strings.Trim(value, Digits) != "" {
			t.Fatalf("boundary %d: %q, %v", length, value, err)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random failed") }

func TestReaderErrorsAreReturned(t *testing.T) {
	if _, err := generate(failingReader{}, Policy{Length: 8, Lowercase: true}); err == nil || err.Error() != "random failed" {
		t.Fatalf("error = %v", err)
	}
}

func TestRandomIndexRejectsBiasedTail(t *testing.T) {
	reader := bytes.NewReader([]byte{255, 254, 253, 252, 251, 250, 249})
	index, err := randomIndex(reader, 10)
	if err != nil {
		t.Fatal(err)
	}
	if index != 9 {
		t.Fatalf("index = %d, want 9 after rejecting 255..250", index)
	}
	if reader.Len() != 0 {
		t.Fatalf("reader has %d bytes left", reader.Len())
	}
}
