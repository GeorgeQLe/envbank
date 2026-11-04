package computeruse_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/nativehost"
	"github.com/GeorgeQLe/envbank/pkg/computeruse"
	"github.com/GeorgeQLe/envbank/pkg/protectedfill"
)

type countingKeychain struct{ reads int }

func (k *countingKeychain) Get(string, string, string) ([]byte, error) {
	k.reads++
	return nil, nil
}

// Without a qualified observation-controlling host (Gate shared by every
// observation/input route AND a trusted Driver), the public embedding point
// must refuse every value-releasing or mutating action before touching the
// config or Keychain. This is the fail-closed state the external controller
// checklist (docs/computer-use-host-acceptance.md) must replace.
func TestEmbeddingRefusesWithoutQualifiedHost(t *testing.T) {
	gate, err := protectedfill.OpenGate(filepath.Join(t.TempDir(), "gate"))
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	for name, protection := range map[string]*protectedfill.Coordinator{
		"no-coordinator": nil,
		"gate-no-driver": {Gate: gate},
		"driver-no-gate": {Driver: refusingDriver{t}},
	} {
		t.Run(name, func(t *testing.T) {
			store := &countingKeychain{}
			host := computeruse.NewNativeHost("/nonexistent/must-not-read.json", store, protection)
			for _, action := range []string{"get_for_fill", "generate_password", "allow_origin", "deny_origin"} {
				r, _ := host.Handle(nativehost.Request{Version: 1, ID: "attempt", Action: action, Name: "TOKEN", Origin: "https://example.com"})
				if r.OK || r.Result != nil {
					t.Fatalf("%s accepted without a qualified host", action)
				}
			}
			target := &protectedfill.Target{Record: "TOKEN", Origin: "https://example.com", Context: "tab_1", Document: "doc_1", Field: "field_1", Submit: "submit_1"}
			r, _ := host.Handle(nativehost.Request{Version: 1, ID: "execute", Action: "protected_execute", Name: "TOKEN", Origin: target.Origin, Target: target})
			receipt, ok := r.Result.(protectedfill.Receipt)
			if !ok || receipt.Status != "HOST_PROTECTION_UNAVAILABLE" || store.reads != 0 {
				t.Fatalf("protected execute without a qualified host: %+v reads=%d", r.Result, store.reads)
			}
		})
	}
	// Refusal comes from the missing Driver/host, not a broken barrier: the
	// gate still wraps observations normally while no protected phase runs.
	if _, err := gate.Observe(context.Background(), func(context.Context) ([]byte, error) { return []byte("x"), nil }); err != nil {
		t.Fatal("fresh gate should allow observation through the barrier wrapper")
	}
}

type refusingDriver struct{ t *testing.T }

func (d refusingDriver) Validate(context.Context, protectedfill.Target) error {
	d.t.Error("driver used without a gate")
	return context.Canceled
}
func (d refusingDriver) FillAndSubmit(context.Context, protectedfill.Target, []byte) (bool, error) {
	d.t.Error("driver received a value without a gate")
	return false, context.Canceled
}

func (d refusingDriver) Destroy(context.Context, protectedfill.Target) error { return nil }

func (d refusingDriver) DestroyOrphans(context.Context) error { return nil }
