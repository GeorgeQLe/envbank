package rotationrun

import (
	"context"
	"errors"

	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/rotation"
)

// MCPBackend answers the rotation tools and forwards everything else to the
// configured deployment backend. An agent starts a rotation by credential
// name and resumes it by operation ID; both are identifiers. The result
// carries the lifecycle state and never a value. Runners are keyed by
// manifest provider name, one engine per provider control credential.
type MCPBackend struct {
	Inner    mcpserver.Backend
	Runners  map[string]*Runner
	PolicyID string
}

func (backend *MCPBackend) Call(ctx context.Context, name string, request mcpserver.Request) (mcpserver.Result, error) {
	switch name {
	case "envbank_rotation_run":
		return backend.run(ctx, request)
	case "envbank_rotation_due":
		// Scheduled rotation is not implemented; the owner or an agent
		// triggers runs explicitly.
		return mcpserver.Result{BlockerCode: "ROTATION_SCHEDULE_NOT_IMPLEMENTED"}, nil
	}
	if backend.Inner == nil {
		return mcpserver.Result{BlockerCode: "PROVIDER_ROTATION_UNAVAILABLE"}, nil
	}
	return backend.Inner.Call(ctx, name, request)
}

func (backend *MCPBackend) run(ctx context.Context, request mcpserver.Request) (mcpserver.Result, error) {
	if len(backend.Runners) == 0 || backend.PolicyID == "" {
		return mcpserver.Result{BlockerCode: "ROTATION_NOT_CONFIGURED"}, nil
	}
	operationID := request.OperationID
	var runner *Runner
	if operationID == "" {
		if request.Credential == "" {
			return mcpserver.Result{BlockerCode: "ROTATION_CREDENTIAL_REQUIRED"}, nil
		}
		var credential contract.Credential
		for _, candidate := range backend.Runners {
			if resolved, err := candidate.Credential(request.Credential); err == nil {
				credential = resolved
				runner = backend.Runners[resolved.Provider]
			}
			break
		}
		if runner == nil {
			return mcpserver.Result{BlockerCode: "ROTATION_CREDENTIAL_UNKNOWN"}, nil
		}
		if request.Provider != "" && request.Provider != credential.Provider {
			return mcpserver.Result{BlockerCode: "POLICY_BINDING_MISMATCH"}, nil
		}
		operation, err := runner.Plan(ctx, request.Credential, backend.PolicyID)
		if err != nil {
			return mcpserver.Result{BlockerCode: planBlocker(err)}, nil
		}
		operationID = operation.ID
	} else {
		runner = backend.runnerFor(ctx, operationID, request.Provider)
		if runner == nil {
			return mcpserver.Result{OperationID: operationID, BlockerCode: "ROTATION_OPERATION_UNKNOWN"}, nil
		}
	}
	operation, err := runner.Run(ctx, operationID)
	switch {
	case errors.Is(err, rotation.ErrBusy):
		return result(operation, "ROTATION_BUSY"), nil
	case errors.Is(err, rotation.ErrNotApproved):
		return result(operation, "ROTATION_APPROVAL_REQUIRED"), nil
	case errors.Is(err, rotation.ErrLeaseExpired):
		return result(operation, "ROTATION_LEASE_EXPIRED"), nil
	case err != nil:
		return mcpserver.Result{OperationID: operationID, BlockerCode: "ROTATION_ERROR"}, nil
	}
	return result(operation, ""), nil
}

// runnerFor finds the runner whose provider owns a stored operation.
func (backend *MCPBackend) runnerFor(ctx context.Context, operationID, providerHint string) *Runner {
	for name, runner := range backend.Runners {
		if providerHint != "" && providerHint != name {
			continue
		}
		operation, _, err := runner.Engine.Store.LoadOperation(ctx, operationID)
		if err == nil && operation.Provider == name {
			return runner
		}
	}
	return nil
}

func planBlocker(err error) string {
	switch {
	case errors.Is(err, ErrUnbound):
		return "ROTATION_CREDENTIAL_UNBOUND"
	case errors.Is(err, rotation.ErrNotApproved):
		return "ROTATION_APPROVAL_REQUIRED"
	}
	return "ROTATION_PLAN_FAILED"
}

func result(operation lifecycle.Operation, blocker string) mcpserver.Result {
	ids := []string{}
	if operation.DeploymentID != "" {
		ids = append(ids, operation.DeploymentID)
	}
	return mcpserver.Result{OperationID: operation.ID, Stage: string(operation.State), Provider: operation.Provider, ResourceIDs: ids, BlockerCode: blocker}
}
