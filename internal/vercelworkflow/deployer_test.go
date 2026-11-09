package vercelworkflow

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

// standingFixture replaces the fixture's per-plan approval with a standing
// rotation approval for the same manifest and scope.
func standingFixture(t *testing.T, environment string, mutate func(*lifecycle.AutomationPolicy)) (*Backend, *memoryStore, *fakeAdapter, ed25519.PrivateKey) {
	t.Helper()
	b, s, a, _, private := fixture(t, environment)
	policy := s.policy
	policy.ID = "rotation-fixture"
	policy.DeploymentPlanID = ""
	policy.DeploymentSourceID = ""
	policy.Schedule = "on-demand"
	policy.Operations = []string{"create", "stage", "activate", "verify", "rollback", "revoke"}
	policy.OwnerApproval = nil
	policy.Signature = nil
	if mutate != nil {
		mutate(&policy)
	}
	if err := ownerSign(&policy, private); err != nil {
		t.Fatal(err)
	}
	s.policy = policy
	b.StandingPolicyID = policy.ID
	return b, s, a, private
}

func deployerFor(b *Backend) *RotationDeployer {
	return &RotationDeployer{Backend: b, SourceDeploymentID: "dpl_source", MaxCalls: 30}
}

func rotationRequest() lifecycle.DeploymentRequest {
	return lifecycle.DeploymentRequest{OperationID: "op-1", RecordRevisions: map[string]int64{"api": 1}, PreviousRecordRevisions: map[string]int64{"api": 0}}
}

func TestRotationDeployerStagesActivatesAndRollsBackProduction(t *testing.T) {
	b, s, a, _ := standingFixture(t, "production", nil)
	d := deployerFor(b)
	d.SourceDeploymentID = "" // production resolves the current deployment itself
	evidence, err := d.Stage(context.Background(), rotationRequest())
	if err != nil || evidence.Status != "promote-pending" || !strings.HasPrefix(evidence.DeploymentID, "vd-") || a.writes != 1 || a.creates != 1 || a.promotes != 0 {
		t.Fatalf("evidence=%+v err=%v writes=%d creates=%d promotes=%d", evidence, err, a.writes, a.creates, a.promotes)
	}
	if s.states[evidence.DeploymentID].SourceDeploymentID != "dpl_source" {
		t.Fatalf("source not resolved from current deployment: %+v", s.states[evidence.DeploymentID])
	}
	health, err := d.Activate(context.Background(), rotationRequest(), evidence.DeploymentID)
	if err != nil || health.Validate() != nil || a.promotes != 1 || a.current != "dpl_new" || s.states[evidence.DeploymentID].Stage != "complete" {
		t.Fatalf("health=%+v err=%v promotes=%d current=%s", health, err, a.promotes, a.current)
	}
	if err := d.Rollback(context.Background(), rotationRequest(), evidence.DeploymentID); err != nil || a.rollbacks != 1 || a.current != "dpl_source" || s.states[evidence.DeploymentID].Stage != "rolled-back" {
		t.Fatalf("err=%v rollbacks=%d current=%s stage=%s", err, a.rollbacks, a.current, s.states[evidence.DeploymentID].Stage)
	}
}

func TestRotationDeployerPreviewCompletesOnStage(t *testing.T) {
	b, _, a, _ := standingFixture(t, "preview", nil)
	d := deployerFor(b)
	evidence, err := d.Stage(context.Background(), rotationRequest())
	if err != nil || evidence.Status != "complete" || a.writes != 1 || a.creates != 1 {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	health, err := d.Activate(context.Background(), rotationRequest(), evidence.DeploymentID)
	if err != nil || health.Validate() != nil || a.promotes != 0 {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	if err := d.Rollback(context.Background(), rotationRequest(), evidence.DeploymentID); err != nil || a.rollbacks != 0 {
		t.Fatalf("preview rollback err=%v rollbacks=%d", err, a.rollbacks)
	}
}

func TestPreviewStandingApprovalRequiresNamedSource(t *testing.T) {
	b, _, a, _ := standingFixture(t, "preview", nil)
	d := deployerFor(b)
	d.SourceDeploymentID = ""
	_, err := d.Stage(context.Background(), rotationRequest())
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "SOURCE_DEPLOYMENT_REQUIRED" || a.writes != 0 {
		t.Fatalf("err=%v writes=%d", err, a.writes)
	}
}

func TestStandingApprovalMustDeclareItself(t *testing.T) {
	for name, mutate := range map[string]func(*lifecycle.AutomationPolicy){
		"manual schedule": func(p *lifecycle.AutomationPolicy) { p.Schedule = "manual" },
		"plan pinned":     func(p *lifecycle.AutomationPolicy) { p.DeploymentPlanID = "some-plan" },
		"source pinned":   func(p *lifecycle.AutomationPolicy) { p.DeploymentSourceID = "dpl_source" },
		"other manifest":  func(p *lifecycle.AutomationPolicy) { p.ManifestDigest = strings.Repeat("b", 64) },
		"other bundle":    func(p *lifecycle.AutomationPolicy) { p.Bundle = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			b, _, a, _ := standingFixture(t, "preview", mutate)
			_, err := deployerFor(b).Stage(context.Background(), rotationRequest())
			var typed provider.Error
			if !errors.As(err, &typed) || typed.Code != "VERCEL_APPROVAL_REQUIRED" || a.writes != 0 {
				t.Fatalf("err=%v writes=%d", err, a.writes)
			}
		})
	}
}

func TestStandingApprovalStillNeedsOwnerSignature(t *testing.T) {
	b, s, a, private := standingFixture(t, "preview", nil)
	s.policy.OwnerApproval = nil
	if err := s.policy.Sign(private); err != nil {
		t.Fatal(err)
	}
	_, err := deployerFor(b).Stage(context.Background(), rotationRequest())
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "VERCEL_APPROVAL_REQUIRED" || a.writes != 0 {
		t.Fatalf("err=%v writes=%d", err, a.writes)
	}
}

func TestStageRefusesStaleSnapshot(t *testing.T) {
	b, _, a, _ := standingFixture(t, "preview", nil)
	request := rotationRequest()
	request.RecordRevisions["api"] = 2
	_, err := deployerFor(b).Stage(context.Background(), request)
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "SNAPSHOT_STALE" || typed.Retry != provider.RetryNever || a.writes != 0 {
		t.Fatalf("err=%v writes=%d", err, a.writes)
	}
}

func TestPerPlanApprovalIgnoresStandingRules(t *testing.T) {
	// Without StandingPolicyID the backend behaves exactly as before.
	b, _, a, p, _ := fixture(t, "preview")
	runTo(t, b, p, "complete")
	if a.writes != 1 {
		t.Fatalf("writes=%d", a.writes)
	}
}

func TestActivateUnknownDeploymentIsAmbiguous(t *testing.T) {
	b, _, _, _ := standingFixture(t, "production", nil)
	_, err := deployerFor(b).Activate(context.Background(), rotationRequest(), "vd-missing")
	var typed provider.Error
	if !errors.As(err, &typed) || typed.Code != "DEPLOYMENT_UNKNOWN" || typed.Retry != provider.RetryAmbiguous {
		t.Fatalf("err=%v", err)
	}
}

func TestBlockerRetryClasses(t *testing.T) {
	for code, want := range map[string]provider.RetryClass{"VERCEL_OPERATION_BUSY": provider.RetrySafe, "PROMOTION_REQUEST_NOT_SENT": provider.RetrySafe, "ALIAS_RECONCILIATION_REQUIRED": provider.RetryAmbiguous, "UNEXPECTED_PROMOTION_ROLLBACK_REQUIRED": provider.RetryAmbiguous, "PRODUCTION_DEPLOYMENT_DRIFT": provider.RetryNever, "DEPLOYMENT_HEALTH_FAILED": provider.RetryNever} {
		if got := blockerRetry(code); got != want {
			t.Fatalf("%s: got %s want %s", code, got, want)
		}
	}
}
