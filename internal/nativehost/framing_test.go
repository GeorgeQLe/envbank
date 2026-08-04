package nativehost

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMessageRoundTripAndStrictJSON(t *testing.T) {
	var framed bytes.Buffer
	want := Request{Version: 1, ID: "abc", Action: "lock"}
	if err := WriteMessage(&framed, want); err != nil {
		t.Fatal(err)
	}
	var got Request
	if err := ReadMessage(&framed, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}

	payload := []byte(`{"version":1,"id":"x","action":"lock","extra":true}`)
	framed.Reset()
	binary.Write(&framed, binary.LittleEndian, uint32(len(payload)))
	framed.Write(payload)
	if err := ReadMessage(&framed, &got); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestMessageLimit(t *testing.T) {
	var framed bytes.Buffer
	binary.Write(&framed, binary.LittleEndian, uint32(MaxRequestBytes+1))
	if err := ReadMessage(&framed, &Request{}); err == nil {
		t.Fatal("oversize message was accepted")
	}
	if err := WriteMessage(&framed, map[string]string{"x": strings.Repeat("x", MaxRequestBytes)}); err == nil {
		t.Fatal("oversize response was accepted")
	}
}

func TestLockDoesNotUnlock(t *testing.T) {
	host := New("missing", nil)
	response, terminate := host.Handle(Request{Version: 1, ID: "1", Action: "lock"})
	if !terminate || !response.OK {
		t.Fatalf("response=%#v terminate=%v", response, terminate)
	}
}
