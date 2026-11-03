package nativehost

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

type protectedDriver struct {
	fill   func([]byte) (bool, error)
	closed bool
}

func (d *protectedDriver) Validate(context.Context, protectedfill.Target) error { return nil }
func (d *protectedDriver) FillAndSubmit(_ context.Context, _ protectedfill.Target, v []byte) (bool, error) {
	return d.fill(v)
}
func (d *protectedDriver) Destroy(context.Context, protectedfill.Target) error {
	d.closed = true
	return nil
}
func (d *protectedDriver) DestroyOrphans(context.Context) error { return nil }

func TestUnavailableProtectionNeverUnlocksOrReleases(t *testing.T) {
	store := &mockKeychain{}
	h := NewForComputerUse("must-not-read-this-config", store, nil)
	for _, action := range []string{"get_for_fill", "generate_password", "allow_origin", "deny_origin"} {
		r, _ := h.Handle(Request{Version: 1, ID: "attempt", Action: action, Name: "TOKEN", Origin: "https://example.com"})
		if r.OK || r.Result != nil {
			t.Fatalf("legacy release accepted: %s", action)
		}
	}
	r, _ := h.Handle(Request{Version: 1, ID: "capabilities", Action: "protected_status"})
	raw, _ := json.Marshal(r)
	if !r.OK || !strings.Contains(string(raw), `"available":false`) || !strings.Contains(string(raw), `"computer_use":true`) {
		t.Fatal("missing host reported protected mode ready")
	}
	r, _ = h.Handle(Request{Version: 1, ID: "execute", Action: "protected_execute", Name: "TOKEN", Origin: "https://example.com"})
	if !r.OK || r.Result.(protectedfill.Receipt).Status != "HOST_PROTECTION_UNAVAILABLE" || len(store.accounts) != 0 {
		t.Fatal("missing host attempted a credential read")
	}
}

func TestProtectedNativeExchangeNeverReturnsValue(t *testing.T) {
	marker := "DISPOSABLE_NATIVE_PROTECTED_MARKER"
	h, calls := testHost(t, nil, []protocol.SecretRecord{{Name: "TOKEN", Value: marker, AllowedOrigins: []string{"https://example.com"}, Revision: 1}})
	g, err := protectedfill.OpenGate(filepath.Join(t.TempDir(), "gate"))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	d := &protectedDriver{fill: func(value []byte) (bool, error) {
		if !g.Blocked() || string(value) != marker {
			t.Fatal("value escaped protected phase")
		}
		return false, errors.New(marker)
	}}
	h.ComputerUse = true
	h.Protection = &protectedfill.Coordinator{Gate: g, Driver: d}
	target := &protectedfill.Target{Record: "TOKEN", Origin: "https://example.com", Context: "tab_5", Document: "doc_1", Field: "field_1", Submit: "submit_1"}
	r, _ := h.Handle(Request{Version: 1, ID: "execute", Action: "protected_execute", Name: "TOKEN", Origin: target.Origin, Target: target})
	raw, _ := json.Marshal(r)
	if !r.OK || strings.Contains(string(raw), marker) || strings.Contains(string(raw), `"value"`) || *calls != 1 || !d.closed || g.Blocked() {
		t.Fatal("protected response, binding or cleanup failed")
	}
	if r.Result.(protectedfill.Receipt).Status != "FAILED_CONTEXT_CLOSED" {
		t.Fatal("driver error not reduced to fixed status")
	}
	target.Record = "OTHER"
	_, _ = h.Handle(Request{Version: 1, ID: "wrong-record", Action: "protected_execute", Name: "TOKEN", Origin: target.Origin, Target: target})
	if *calls != 1 {
		t.Fatal("mismatched record read vault")
	}
	target.Record = "TOKEN"
	target.Origin = "https://evil.example"
	_, _ = h.Handle(Request{Version: 1, ID: "wrong-origin", Action: "protected_execute", Name: "TOKEN", Origin: "https://example.com", Target: target})
	if *calls != 1 {
		t.Fatal("mismatched origin read vault")
	}
}
