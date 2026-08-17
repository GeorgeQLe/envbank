package cloudflare

import (
	"context"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

type bindingNamesAPI struct{ names []string }

func (*bindingNamesAPI) Identity(context.Context, string) error { return nil }
func (*bindingNamesAPI) Inspect(context.Context, Target) (Snapshot, error) {
	return Snapshot{}, nil
}
func (*bindingNamesAPI) Stage(context.Context, StageRequest) (string, error) { return "", nil }
func (api *bindingNamesAPI) VersionBindingNames(context.Context, Target, string) ([]string, error) {
	return append([]string(nil), api.names...), nil
}
func (*bindingNamesAPI) Deploy(context.Context, Target, string, bool) (string, error) {
	return "", nil
}

func TestVerifyTreatsExpectedAbsenceAsVerified(t *testing.T) {
	target := Target{AccountID: "account", ZoneID: "zone", ScriptName: "worker"}
	adapter := &Adapter{API: &bindingNamesAPI{}, Target: target}
	evidence, err := adapter.Verify(context.Background(), provider.VerifyRequest{
		Target: provider.Target{ProjectID: "account", EnvironmentID: "zone",
			ServiceIDs: map[string]string{"worker": "worker"}},
		Service: "worker", ServiceID: "worker", Name: "REMOVED_SECRET",
		ProviderOperationID: "version", ExpectedPresence: provider.PresenceAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Result != provider.VerificationVerified || evidence.Presence != provider.PresenceAbsent {
		t.Fatalf("expected absence evidence = %#v", evidence)
	}
}

func TestVerifyReportsPresenceMismatch(t *testing.T) {
	target := Target{AccountID: "account", ZoneID: "zone", ScriptName: "worker"}
	adapter := &Adapter{API: &bindingNamesAPI{names: []string{"SECRET"}}, Target: target}
	evidence, err := adapter.Verify(context.Background(), provider.VerifyRequest{
		Target: provider.Target{ProjectID: "account", EnvironmentID: "zone",
			ServiceIDs: map[string]string{"worker": "worker"}},
		Service: "worker", ServiceID: "worker", Name: "SECRET",
		ProviderOperationID: "version", ExpectedPresence: provider.PresenceAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Result != provider.VerificationLimited || evidence.Presence != provider.PresencePresent {
		t.Fatalf("presence mismatch evidence = %#v", evidence)
	}
}
