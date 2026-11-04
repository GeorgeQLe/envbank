package vercelworkflow

import (
	"context"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
)

// Revalidate approval immediately before each private write, not just at the
// beginning of a potentially long multi-variable operation.
type approvedAdapter struct {
	provider.Adapter
	backend  *Backend
	state    *State
	revision *int64
}

func (a approvedAdapter) Inspect(ctx context.Context, target provider.Target) (provider.MetadataState, error) {
	metadata, e := a.Adapter.Inspect(ctx, target)
	if e != nil {
		return metadata, e
	}
	if metadata.Revision != a.state.ProviderRevision {
		return provider.MetadataState{}, provider.Error{Operation: "inspect", Code: "METADATA_DRIFT", Retry: provider.RetryNever}
	}
	plan, _, e := a.backend.Store.LoadPlan(ctx, a.state.PlanID)
	if e != nil {
		return provider.MetadataState{}, e
	}
	// The generic engine pins the original plan revision. The workflow pins
	// the latest successfully journaled write checkpoint instead, so its own
	// confirmed changes do not look like external drift on Resume. Never mask
	// a mismatch against that checkpoint and never bypass action reconciliation.
	metadata.Revision = plan.ProviderRevision
	return metadata, nil
}

func (a approvedAdapter) Write(ctx context.Context, request provider.WriteRequest) (provider.WriteEvidence, error) {
	if a.backend.authorizeState(ctx, *a.state, "stage") != nil {
		return provider.WriteEvidence{}, provider.Error{Operation: "write", Code: "AUTOMATION_POLICY_DENIED", Retry: provider.RetrySafe}
	}
	before, e := a.Adapter.Inspect(ctx, request.Target)
	if e != nil {
		return provider.WriteEvidence{}, provider.Error{Operation: "write", Code: "METADATA_INSPECTION_FAILED", Retry: provider.RetrySafe}
	}
	if before.Revision != a.state.ProviderRevision {
		return provider.WriteEvidence{}, provider.Error{Operation: "write", Code: "METADATA_DRIFT", Retry: provider.RetryNever}
	}
	request.ExpectedMetadataRevision = a.state.ProviderRevision
	ctx = vercel.WithMutationAuthorization(ctx, func(c context.Context) error { return a.backend.authorizeState(c, *a.state, "stage") })
	evidence, e := a.Adapter.Write(ctx, request)
	if e != nil {
		return evidence, e
	}
	if !digestID.MatchString(evidence.MetadataRevision) {
		return provider.WriteEvidence{}, provider.Error{Operation: "write", Code: "WRITE_CHECKPOINT_UNAVAILABLE", Retry: provider.RetryAmbiguous}
	}
	a.state.ProviderRevision = evidence.MetadataRevision
	checkpoint, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if e = a.backend.save(checkpoint, a.state, a.revision, "writing"); e != nil {
		return provider.WriteEvidence{}, provider.Error{Operation: "write", Code: "WRITE_CHECKPOINT_UNAVAILABLE", Retry: provider.RetryAmbiguous}
	}
	return evidence, nil
}
func (a approvedAdapter) Verify(ctx context.Context, request provider.VerifyRequest) (provider.VerifyEvidence, error) {
	if a.backend.authorizeState(ctx, *a.state, "verify") != nil {
		return provider.VerifyEvidence{}, provider.Error{Operation: "verify", Code: "AUTOMATION_POLICY_DENIED", Retry: provider.RetrySafe}
	}
	return a.Adapter.Verify(ctx, request)
}
func (b *Backend) approvedEngine(state *State, revision *int64) *rollout.Engine {
	return &rollout.Engine{Adapter: approvedAdapter{Adapter: b.Adapter, backend: b, state: state, revision: revision}, Store: approvedStore{Store: b.Store, backend: b, state: state}, Now: b.now}
}

type approvedStore struct {
	Store
	backend *Backend
	state   *State
}

func (s approvedStore) LoadRecord(ctx context.Context, bundleID, record string, revision int64) ([]byte, error) {
	if s.backend.authorizeState(ctx, *s.state, "stage") != nil || bundleID != s.backend.Document.Manifest.Bundle {
		return nil, provider.Error{Operation: "write", Code: "AUTOMATION_POLICY_DENIED", Retry: provider.RetrySafe}
	}
	return s.Store.LoadRecord(ctx, bundleID, record, revision)
}
