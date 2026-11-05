package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

// Bindings are encrypted vault objects: a broker restart (a new client,
// unlocked again, and a new provider service) reads them back from the
// server, and they never appear as records.
func TestProviderBindingsPersistInTheVault(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	ctx := context.Background()
	api, key := unlockedFixtureAPI(t, fixture.firstConfigPath, fixture.passphrasePath)
	first := &brokerVault{api: api, vaultKey: key}
	value := provideractiontest.Sentinel("postgresql://app_a:")
	rev, err := first.StoreSecret(ctx, "DATABASE_URL", func(consume func([]byte) error) error { return consume([]byte(value)) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.StoreSecret(ctx, provideraction.ControlVercel, func(consume func([]byte) error) error {
		return consume([]byte(provideractiontest.Sentinel("vcp_")))
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.LoadBinding(ctx, "DATABASE_URL"); !errors.Is(err, provideraction.ErrMissing) {
		t.Fatalf("absent binding: %v", err)
	}
	b := provideraction.Binding{V: provideraction.BindingVersion, Record: "DATABASE_URL", Provider: provideraction.ProviderNeon, Kind: provideraction.KindNeonPooled,
		Resource: provideraction.BindingResource{ProjectID: "calm-sky-123456", BranchID: "br-main-1"}, RecordRevision: rev,
		AllowedDestinations: []provideraction.Destination{{TeamID: "team_abc123", ProjectID: "prj_abc123"}}}
	if _, err := first.SaveBinding(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SaveBinding(ctx, b, 0); err == nil {
		t.Fatal("stale binding write accepted")
	}
	if err := first.SaveVercelProject(ctx, provideraction.VercelProject{V: 1, TeamID: "team_abc123", ProjectID: "prj_abc123", Name: "throwaway"}); err != nil {
		t.Fatal(err)
	}
	first.wipe()

	// Restart: a fresh unlock and a fresh service.
	api2, key2 := unlockedFixtureAPI(t, fixture.firstConfigPath, fixture.passphrasePath)
	second := &brokerVault{api: api2, vaultKey: key2}
	got, objRev, err := second.LoadBinding(ctx, "DATABASE_URL")
	if err != nil || objRev != 1 || got.RecordRevision != rev || len(got.AllowedDestinations) != 1 || got.Kind != provideraction.KindNeonPooled {
		t.Fatalf("reloaded binding %+v rev %d: %v", got, objRev, err)
	}
	if all, err := second.ListBindings(ctx); err != nil || len(all) != 1 || all[0].Binding.Record != "DATABASE_URL" {
		t.Fatalf("list %+v: %v", all, err)
	}
	if _, err := second.LoadVercelProject(ctx, "team_abc123", "prj_abc123"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.LoadVercelProject(ctx, "team_abc123", "prj_other"); !errors.Is(err, provideraction.ErrMissing) {
		t.Fatalf("absent provenance: %v", err)
	}
	names, err := second.Names(ctx)
	if err != nil || strings.Join(names, ",") != "CONTROL_VERCEL_TOKEN,DATABASE_URL" {
		t.Fatalf("records: %v %v", names, err)
	}
	// The objects are encrypted on the server: no plaintext in the listing.
	encrypted, err := api2.ListVaultObjects()
	if err != nil || len(encrypted) != 2 {
		t.Fatalf("objects %d: %v", len(encrypted), err)
	}
	rawObjects, _ := json.Marshal(encrypted)
	for _, plain := range []string{"DATABASE_URL", "calm-sky-123456", "prj_abc123", vaultobject.KindProviderBinding} {
		if strings.Contains(string(rawObjects), plain) {
			t.Fatalf("object listing exposes %q", plain)
		}
	}

	svc := newProviderService(second, provideractiontest.NewProviders(&provideractiontest.Log{}))
	defer svc.Close()
	push := func(project string) string {
		params, _ := json.Marshal(map[string]any{"team_id": "team_abc123", "project_id": project, "target": "preview", "variables": map[string]string{"DATABASE_URL": "DATABASE_URL"}})
		prep, code := svc.Prepare(ctx, provideraction.ActionVercelEnvPush, params)
		prep.Release()
		return code
	}
	if code := push("prj_abc123"); code != "" {
		t.Fatalf("allowed push after restart: %q", code)
	}
	if code := push("prj_other"); code != provideraction.CodeDestinationNotAllowed {
		t.Fatalf("not allowed push after restart: %q", code)
	}
	// A value written outside the broker unbinds the record.
	if err := second.Store(ctx, "DATABASE_URL", "replaced by owner"); err != nil {
		t.Fatal(err)
	}
	if code := push("prj_abc123"); code != provideraction.CodeRecordNotBound {
		t.Fatalf("push of a replaced value: %q", code)
	}
}
