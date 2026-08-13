package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type memoryWriter struct {
	stored   []byte
	revision int64
	fail     bool
}

func (writer *memoryWriter) StoreSecret(_ context.Context, record string, provide func(func([]byte) error) error) (int64, error) {
	if writer.fail {
		return 0, errors.New("sentinel provider response")
	}
	err := provide(func(value []byte) error { writer.stored = append([]byte(nil), value...); return nil })
	if err != nil {
		return 0, err
	}
	writer.revision++
	return writer.revision, nil
}

func TestSecretSinkStoresBeforeReceiptAndIsSingleUse(t *testing.T) {
	writer := &memoryWriter{}
	sink, err := NewSecretSink(writer, "STRIPE_WEBHOOK_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := sink.Store(context.Background(), strings.NewReader("whsec_unique-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Record != "STRIPE_WEBHOOK_SECRET" || receipt.Revision != 1 || string(writer.stored) != "whsec_unique-sentinel" {
		t.Fatalf("unexpected receipt %#v", receipt)
	}
	if _, err := sink.StoreBytes(context.Background(), []byte("second")); err == nil {
		t.Fatal("sink allowed a second credential")
	}
	raw, _ := json.Marshal(struct {
		Sink    *SecretSink   `json:"sink"`
		Receipt SecretReceipt `json:"receipt"`
	}{sink, receipt})
	if bytes.Contains(raw, []byte("whsec_")) {
		t.Fatal("serialized result leaked credential")
	}
}

func TestSecretSinkReturnsFixedError(t *testing.T) {
	sink, _ := NewSecretSink(&memoryWriter{fail: true}, "TOKEN")
	_, err := sink.StoreBytes(context.Background(), []byte("unique-sentinel"))
	if err == nil || err.Error() != "provider credential could not be stored" || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("error=%v", err)
	}
}

type memoryReader struct {
	value    []byte
	revision int64
}

func (reader memoryReader) ReadSecret(_ context.Context, _ string, revision int64, consume func([]byte) error) error {
	if revision != reader.revision {
		return errors.New("revision changed")
	}
	return consume(reader.value)
}

func TestSecretSourceIsCallbackScopedAndRevisionBound(t *testing.T) {
	reader := memoryReader{value: []byte("source-sentinel"), revision: 7}
	source, err := NewSecretSource(reader, "TOKEN", 7)
	if err != nil {
		t.Fatal(err)
	}
	var observed bool
	if err := source.WithSecret(context.Background(), func(value []byte) error { observed = string(value) == "source-sentinel"; return nil }); err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("callback did not receive exact revision")
	}
	raw, _ := json.Marshal(source)
	if bytes.Contains(raw, reader.value) {
		t.Fatal("secret source serialized its value")
	}
	stale, _ := NewSecretSource(reader, "TOKEN", 6)
	if err := stale.WithSecret(context.Background(), func([]byte) error { return nil }); err == nil {
		t.Fatal("stale revision accepted")
	}
}

func testPolicy(t *testing.T, now time.Time) (AutomationPolicy, ed25519.PublicKey) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := AutomationPolicy{Version: 1, ID: "policy-1", VaultID: "vault", Bundle: "bundle", ManifestDigest: strings.Repeat("a", 64), Environment: "production", ProviderIdentities: map[string]string{"stripe": "acct_1"}, CredentialClasses: []string{"webhook-signing-secret"}, Operations: []string{"create", "stage", "activate", "verify", "rollback", "revoke"}, Targets: []TargetPolicy{{Provider: "vercel", ProjectID: "prj", EnvironmentID: "production"}}, Schedule: "0 3 * * *", HealthChecks: []string{"https://example.test/health"}, GracePeriod: "24h", Rollback: "restore-last-known-good", RetryBudget: 3, ExpiresAt: now.Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339), ApprovingDevice: "device-fingerprint"}
	if err := policy.Sign(private); err != nil {
		t.Fatal(err)
	}
	return policy, public
}

func TestPolicySignatureAuthorizationAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	policy, _ := testPolicy(t, now)
	binding := AuthorizationBinding{VaultID: "vault", Bundle: "bundle", ManifestDigest: strings.Repeat("a", 64), Environment: "production", Provider: "stripe", ProviderIdentity: "acct_1", CredentialClass: "webhook-signing-secret", Operation: "revoke", Target: TargetPolicy{Provider: "vercel", ProjectID: "prj", EnvironmentID: "production"}}
	if err := policy.Authorizes(binding, now); err != nil {
		t.Fatal(err)
	}
	tampered := policy
	tampered.Bundle = "other"
	if err := tampered.Validate(now); err == nil {
		t.Fatal("tampered signed policy accepted")
	}
	if err := policy.Validate(now.Add(91 * 24 * time.Hour)); err == nil {
		t.Fatal("expired policy accepted")
	}
}

func TestEvidenceChainDetectsTampering(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	first, err := NewEvidence(nil, "operation", "stored", "OK", "device", now, private)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEvidence(&first, "operation", "staged", "OK", "device", now.Add(time.Second), private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceChain([]Evidence{first, second}, public); err != nil {
		t.Fatal(err)
	}
	second.Stage = "complete"
	if err := VerifyEvidenceChain([]Evidence{first, second}, public); err == nil {
		t.Fatal("tampered chain accepted")
	}
}

func TestRollbackAndQuarantineTransitions(t *testing.T) {
	for _, pair := range [][2]State{{StateActivating, StateRollingBack}, {StateRollingBack, StateRolledBack}, {StateRolledBack, StateQuarantined}} {
		if err := Transition(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := Transition(StateHealthy, StateComplete); err == nil {
		t.Fatal("skipped grace and revocation")
	}
}

func TestRevocationRechecksPolicyRecordTargetAndHealth(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	policy, _ := testPolicy(t, now)
	policyDigest, _ := policy.Digest()
	binding := AuthorizationBinding{VaultID: "vault", Bundle: "bundle", ManifestDigest: strings.Repeat("a", 64), Environment: "production", Provider: "stripe", ProviderIdentity: "acct_1", CredentialClass: "webhook-signing-secret", Operation: "revoke", Target: TargetPolicy{Provider: "vercel", ProjectID: "prj", EnvironmentID: "production"}}
	operation := Operation{Version: 1, ID: "operation", PolicyID: policy.ID, PolicyDigest: policyDigest, VaultID: "vault", Bundle: "bundle", ManifestDigest: binding.ManifestDigest, Provider: "stripe", ProviderIdentity: "acct_1", Target: binding.Target, CredentialClass: "webhook-signing-secret", DestinationRecord: "STRIPE_WEBHOOK_SECRET", PreviousRecordRevision: 1, NewRecordRevision: 2, PreviousCredentialID: "we_old", NewCredentialID: "we_new", HealthEvidenceDigest: strings.Repeat("b", 64), State: StateRevoking, GraceEndsAt: now.Add(-time.Hour).Format(time.RFC3339), CreatedAt: now.Add(-25 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339)}
	if err := operation.RevocationAllowed(binding, 2, strings.Repeat("b", 64), now, policy); err != nil {
		t.Fatal(err)
	}
	if err := operation.RevocationAllowed(binding, 3, strings.Repeat("b", 64), now, policy); err == nil {
		t.Fatal("changed record revision accepted")
	}
	if err := operation.RevocationAllowed(binding, 2, strings.Repeat("c", 64), now, policy); err == nil {
		t.Fatal("changed health evidence accepted")
	}
}
