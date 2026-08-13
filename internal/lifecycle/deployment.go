package lifecycle

import (
	"context"
	"errors"
)

type NamedDeployment struct {
	Name    string
	Adapter DeploymentAdapter
}

type DeploymentResult struct {
	Name     string             `json:"name"`
	Evidence DeploymentEvidence `json:"evidence"`
	Health   HealthEvidence     `json:"health"`
}

type DeploymentFailure struct {
	Stage      string
	Target     string
	RolledBack []string
}

func (DeploymentFailure) Error() string {
	return "deployment workflow failed; rollback evidence recorded"
}

// DeployInOrder stages every destination before activation, activates in the
// manifest-provided order, and rolls affected destinations back in reverse.
// No provider error text crosses this boundary.
func DeployInOrder(ctx context.Context, targets []NamedDeployment, requests map[string]DeploymentRequest) ([]DeploymentResult, error) {
	if ctx == nil || len(targets) == 0 {
		return nil, errors.New("deployment workflow is invalid")
	}
	staged := make([]DeploymentEvidence, len(targets))
	results := make([]DeploymentResult, 0, len(targets))
	for index, target := range targets {
		request, ok := requests[target.Name]
		if target.Name == "" || target.Adapter == nil || !ok {
			return nil, errors.New("deployment workflow is invalid")
		}
		evidence, err := target.Adapter.Stage(ctx, request)
		if err != nil {
			rolled := rollback(ctx, targets[:index], staged[:index])
			return nil, DeploymentFailure{Stage: "staging", Target: target.Name, RolledBack: rolled}
		}
		staged[index] = evidence
	}
	for index, target := range targets {
		activated, err := target.Adapter.Activate(ctx, staged[index])
		if err != nil {
			rolled := rollback(ctx, targets[:index+1], staged[:index+1])
			return nil, DeploymentFailure{Stage: "activating", Target: target.Name, RolledBack: rolled}
		}
		health, err := target.Adapter.Verify(ctx, activated)
		if err != nil || health.Validate() != nil {
			staged[index] = activated
			rolled := rollback(ctx, targets[:index+1], staged[:index+1])
			return nil, DeploymentFailure{Stage: "verifying", Target: target.Name, RolledBack: rolled}
		}
		staged[index] = activated
		results = append(results, DeploymentResult{Name: target.Name, Evidence: activated, Health: health})
	}
	return results, nil
}

func rollback(ctx context.Context, targets []NamedDeployment, evidence []DeploymentEvidence) []string {
	rolled := []string{}
	for index := len(targets) - 1; index >= 0; index-- {
		if _, err := targets[index].Adapter.Rollback(ctx, evidence[index]); err == nil {
			rolled = append(rolled, targets[index].Name)
		}
	}
	return rolled
}
