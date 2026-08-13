package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

type fakeDeployment struct {
	name  string
	calls *[]string
	fail  string
}

func (*fakeDeployment) Inspect(context.Context, provider.Target) (provider.MetadataState, error) {
	return provider.MetadataState{}, nil
}
func (fake *fakeDeployment) Stage(context.Context, DeploymentRequest) (DeploymentEvidence, error) {
	*fake.calls = append(*fake.calls, "stage:"+fake.name)
	if fake.fail == "stage" {
		return DeploymentEvidence{}, errors.New("secret provider body")
	}
	return DeploymentEvidence{DeploymentID: fake.name, Status: "staged"}, nil
}
func (fake *fakeDeployment) Activate(_ context.Context, evidence DeploymentEvidence) (DeploymentEvidence, error) {
	*fake.calls = append(*fake.calls, "activate:"+fake.name)
	if fake.fail == "activate" {
		return evidence, errors.New("secret provider body")
	}
	evidence.Status = "active"
	return evidence, nil
}
func (fake *fakeDeployment) Verify(context.Context, DeploymentEvidence) (HealthEvidence, error) {
	*fake.calls = append(*fake.calls, "verify:"+fake.name)
	if fake.fail == "verify" {
		return HealthEvidence{}, errors.New("secret provider body")
	}
	first := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	return HealthEvidence{SuccessfulChecks: 3, FirstSuccessAt: first.Format(time.RFC3339), LastSuccessAt: first.Add(30 * time.Second).Format(time.RFC3339), Healthy: true}, nil
}
func (fake *fakeDeployment) Rollback(_ context.Context, evidence DeploymentEvidence) (DeploymentEvidence, error) {
	*fake.calls = append(*fake.calls, "rollback:"+fake.name)
	evidence.Status = "rolled-back"
	return evidence, nil
}

func TestDeployInOrderRollsBackInReverse(t *testing.T) {
	calls := []string{}
	targets := []NamedDeployment{{"vercel", &fakeDeployment{"vercel", &calls, ""}}, {"railway", &fakeDeployment{"railway", &calls, "verify"}}}
	requests := map[string]DeploymentRequest{"vercel": {OperationID: "op"}, "railway": {OperationID: "op"}}
	_, err := DeployInOrder(context.Background(), targets, requests)
	if err == nil {
		t.Fatal("verification failure accepted")
	}
	want := []string{"stage:vercel", "stage:railway", "activate:vercel", "verify:vercel", "activate:railway", "verify:railway", "rollback:railway", "rollback:vercel"}
	if len(calls) != len(want) {
		t.Fatalf("calls=%v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls=%v", calls)
		}
	}
}

func TestHealthEvidenceRequiresThreeChecksOverThirtySeconds(t *testing.T) {
	first := time.Now().UTC()
	for _, evidence := range []HealthEvidence{{Healthy: true, SuccessfulChecks: 2, FirstSuccessAt: first.Format(time.RFC3339), LastSuccessAt: first.Add(time.Minute).Format(time.RFC3339)}, {Healthy: true, SuccessfulChecks: 3, FirstSuccessAt: first.Format(time.RFC3339), LastSuccessAt: first.Add(29 * time.Second).Format(time.RFC3339)}} {
		if evidence.Validate() == nil {
			t.Fatal("weak health evidence accepted")
		}
	}
}
