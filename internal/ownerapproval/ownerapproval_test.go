package ownerapproval_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval/ownerapprovaltest"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func device(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("device\x00" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func policy() lifecycle.AutomationPolicy {
	return lifecycle.AutomationPolicy{Version: 1, ID: "vercel-" + strings.Repeat("b", 64), VaultID: "vault", Bundle: "acceptance", ManifestDigest: strings.Repeat("a", 64), Environment: "staging", ProviderIdentities: map[string]string{"vercel": "team_x:prj_y"}, CredentialClasses: []string{"vercel-environment-secret"}, Operations: []string{"stage", "activate", "verify", "rollback"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: "prj_y", EnvironmentID: "preview"}}, Schedule: "manual", HealthChecks: []string{"/api/health"}, GracePeriod: "15m", Rollback: "previous-deployment", RetryBudget: 1, ExpiresAt: testNow.Add(time.Hour).Format(time.RFC3339), ApprovingDevice: "device", DeploymentPlanID: strings.Repeat("b", 64), DeploymentSourceID: "dpl_source", DeploymentScopeFingerprint: strings.Repeat("c", 64), DeploymentHealthPath: "/api/health"}
}

func approved(t *testing.T, signer *ownerapprovaltest.Signer) lifecycle.AutomationPolicy {
	t.Helper()
	p := policy()
	if err := ownerapproval.Approve(context.Background(), &p, device("a"), signer, signer.PublicKey(), testNow, "approve plan"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApproveProducesCanonicalVerifiableDeviceSignedProof(t *testing.T) {
	signer := ownerapprovaltest.New("owner")
	signer.HighS = true
	p := approved(t, signer)
	if signer.Calls != 1 || signer.Reasons[0] != "approve plan" {
		t.Fatal("signer not invoked exactly once with reason")
	}
	if err := ownerapproval.Verify(p, signer.PublicKey(), testNow); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
	if err := p.Validate(testNow); err != nil {
		t.Fatalf("device signature does not cover owner approval: %v", err)
	}
	normalized, err := ownerapproval.CanonicalSignature(p.OwnerApproval.Signature)
	if err != nil || !bytes.Equal(normalized, p.OwnerApproval.Signature) {
		t.Fatal("stored owner signature is not canonical low-S")
	}
	if p.OwnerApproval.KeyID != ownerapproval.KeyID(signer.PublicKey()) || p.OwnerApproval.Presence != lifecycle.OwnerApprovalPresence {
		t.Fatal("owner identity/attributes missing")
	}
}

func TestDeviceOnlyAndSoftwareSubstitutesNeverVerify(t *testing.T) {
	owner := ownerapprovaltest.New("owner")
	p := policy()
	if err := p.Sign(device("a")); err != nil {
		t.Fatal(err)
	}
	if ownerapproval.Verify(p, owner.PublicKey(), testNow) == nil {
		t.Fatal("device-only (TTY/software) approval accepted as hardware approval")
	}
	// A different key (e.g. a software key minted by an agent holding the
	// device key) is refused before any prompt and at verification.
	other := ownerapprovaltest.New("agent-software-key")
	q := policy()
	if err := ownerapproval.Approve(context.Background(), &q, device("a"), other, owner.PublicKey(), testNow, "x"); !errors.Is(err, ownerapproval.ErrKeyMismatch) || other.Calls != 0 {
		t.Fatal("signer with unpinned key was asked to sign")
	}
	q = approved(t, other)
	if !errors.Is(ownerapproval.Verify(q, owner.PublicKey(), testNow), ownerapproval.ErrKeyMismatch) {
		t.Fatal("approval from unpinned key accepted")
	}
	// Relabeling the foreign signature with the pinned identity still fails.
	q.OwnerApproval.PublicKey = owner.PublicKey()
	q.OwnerApproval.KeyID = ownerapproval.KeyID(owner.PublicKey())
	_ = q.Sign(device("a"))
	if ownerapproval.Verify(q, owner.PublicKey(), testNow) == nil {
		t.Fatal("relabeled foreign signature accepted")
	}
	if ownerapproval.Verify(approved(t, owner), nil, testNow) == nil {
		t.Fatal("approval verified without an owner pin")
	}
}

func TestTamperingAfterOwnerSignatureFailsEvenWhenDeviceResigns(t *testing.T) {
	owner := ownerapprovaltest.New("owner")
	mutations := map[string]func(*lifecycle.AutomationPolicy){
		"expiry":     func(p *lifecycle.AutomationPolicy) { p.ExpiresAt = testNow.Add(2 * time.Hour).Format(time.RFC3339) },
		"source":     func(p *lifecycle.AutomationPolicy) { p.DeploymentSourceID = "dpl_other" },
		"plan":       func(p *lifecycle.AutomationPolicy) { p.DeploymentPlanID = strings.Repeat("d", 64) },
		"operations": func(p *lifecycle.AutomationPolicy) { p.Operations = append(p.Operations, "revoke") },
		"identity":   func(p *lifecycle.AutomationPolicy) { p.ProviderIdentities["vercel"] = "team_x:prj_z" },
		"health":     func(p *lifecycle.AutomationPolicy) { p.DeploymentHealthPath = "/other" },
		"signed-at": func(p *lifecycle.AutomationPolicy) {
			p.OwnerApproval.SignedAt = testNow.Add(-time.Minute).Format(time.RFC3339)
		},
		"presence":  func(p *lifecycle.AutomationPolicy) { p.OwnerApproval.Presence = "software" },
		"signature": func(p *lifecycle.AutomationPolicy) { p.OwnerApproval.Signature[len(p.OwnerApproval.Signature)-1] ^= 1 },
		"trailing":  func(p *lifecycle.AutomationPolicy) { p.OwnerApproval.Signature = append(p.OwnerApproval.Signature, 0) },
		"high-s": func(p *lifecycle.AutomationPolicy) {
			p.OwnerApproval.Signature, _ = ownerapprovaltest.FlipS(p.OwnerApproval.Signature)
		},
		"device-swap": nil,
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := approved(t, owner)
			if mutate == nil {
				// A different device key cannot silently re-sign the owner proof...
				if p.Sign(device("other")) == nil {
					t.Fatal("owner approval re-signed by different device")
				}
				// ...and forcing the new device key into the statement breaks it.
				p.PublicKey = append([]byte(nil), device("other").Public().(ed25519.PublicKey)...)
				if err := p.Sign(device("other")); err != nil {
					t.Fatal(err)
				}
				if ownerapproval.Verify(p, owner.PublicKey(), testNow) == nil {
					t.Fatal("owner approval transferred to a different device")
				}
				return
			}
			mutate(&p)
			_ = p.Sign(device("a"))
			if ownerapproval.Verify(p, owner.PublicKey(), testNow) == nil {
				t.Fatal("tampered approval verified")
			}
		})
	}
}

func TestOwnerSigningTimeBoundsExpiry(t *testing.T) {
	owner := ownerapprovaltest.New("owner")
	p := policy()
	p.ExpiresAt = testNow.Add(25 * time.Hour).Format(time.RFC3339)
	if ownerapproval.Approve(context.Background(), &p, device("a"), owner, owner.PublicKey(), testNow, "x") == nil {
		t.Fatal("approval longer than 24h after owner signature accepted")
	}
	p = approved(t, owner)
	if ownerapproval.Verify(p, owner.PublicKey(), testNow.Add(-10*time.Minute)) == nil {
		t.Fatal("future-dated owner signature accepted")
	}
}

func TestRenewalMayChangeOnlyExpiryAndFreshSignature(t *testing.T) {
	owner := ownerapprovaltest.New("owner")
	first := approved(t, owner)
	renewed := policy()
	renewed.ExpiresAt = testNow.Add(3 * time.Hour).Format(time.RFC3339)
	if err := ownerapproval.Approve(context.Background(), &renewed, device("a"), owner, owner.PublicKey(), testNow.Add(time.Hour), "renew"); err != nil {
		t.Fatal(err)
	}
	if !ownerapproval.SameAuthority(first, renewed) {
		t.Fatal("expiry-only renewal rejected")
	}
	changed := policy()
	changed.RetryBudget = 2
	_ = ownerapproval.Approve(context.Background(), &changed, device("a"), owner, owner.PublicKey(), testNow, "x")
	if ownerapproval.SameAuthority(first, changed) {
		t.Fatal("renewal changed signed authority")
	}
	swapped := approved(t, ownerapprovaltest.New("second-key"))
	if ownerapproval.SameAuthority(first, swapped) {
		t.Fatal("renewal swapped owner key")
	}
	dropped := policy()
	_ = dropped.Sign(device("a"))
	if ownerapproval.SameAuthority(first, dropped) || ownerapproval.SameAuthority(dropped, first) {
		t.Fatal("renewal dropped or added hardware proof")
	}
}

func TestSecureEnclaveSignerRequiresPinWithoutTouchingKeychain(t *testing.T) {
	if _, err := ownerapproval.OpenSecureEnclave(nil); err == nil {
		t.Fatal("hardware signer opened without an owner pin")
	}
	if _, err := ownerapproval.OpenSecureEnclave([]byte{4, 1, 2}); err == nil {
		t.Fatal("hardware signer opened with an invalid pin")
	}
	if ownerapproval.ValidPublicKey(make([]byte, ownerapproval.PublicKeySize)) {
		t.Fatal("off-curve pin accepted")
	}
}

// TestNoProductionImport keeps the software signer out of shipped code.
func TestNoProductionImport(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const forbidden = "github.com/GeorgeQLe/envbank/internal/ownerapproval/ownerapprovaltest"
	checked := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, filepath.Join("ownerapproval", "ownerapprovaltest")) {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, spec := range file.Imports {
			if value, _ := strconv.Unquote(spec.Path.Value); value == forbidden {
				t.Errorf("production file imports software owner signer: %s", path)
			}
		}
		return nil
	})
	if err != nil || checked < 20 {
		t.Fatalf("import scan incomplete: %v (%d files)", err, checked)
	}
}

func TestOwnerVerifierRejectsExpiredProofItself(t *testing.T) {
	signer := ownerapprovaltest.New("expired-owner")
	p := approved(t, signer)
	expires, e := time.Parse(time.RFC3339, p.ExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	if ownerapproval.Verify(p, signer.PublicKey(), expires) == nil {
		t.Fatal("owner verifier accepted an expired approval")
	}
}

type cancelledOwnerSigner struct {
	ownerapproval.Signer
	cancel context.CancelFunc
}

func (s cancelledOwnerSigner) Sign(ctx context.Context, message []byte, reason string) ([]byte, error) {
	signature, e := s.Signer.Sign(ctx, message, reason)
	s.cancel()
	return signature, e
}
func TestCancellationDuringOwnerPromptDoesNotCreateApproval(t *testing.T) {
	signer := ownerapprovaltest.New("cancel-owner")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := policy()
	e := ownerapproval.Approve(ctx, &p, device("a"), cancelledOwnerSigner{Signer: signer, cancel: cancel}, signer.PublicKey(), testNow, "approve test")
	if !errors.Is(e, ownerapproval.ErrCancelled) || p.OwnerApproval != nil || len(p.Signature) != 0 {
		t.Fatal("cancelled authentication minted an approval")
	}
}
