package provideraction

import "time"

// Production releases.
//
// Vercel creates a production redeploy STAGED (autoAssignCustomDomains is
// false), so production traffic stays on the old deployment, and keeps using
// the old credential, until the new deployment is promoted. A production
// target therefore runs: read the deployment serving production (the
// rollback target) → push env → staged redeploy → wait ready → health on the
// staged deployment → promote → prove production serves it (alias-proven
// CurrentDeployment) → health again → prove it once more → only then does the
// caller invalidate or delete the old credential.
//
// A failure before the promote leaves production untouched. A failure at or
// after the promote rolls production back to the previous deployment (which
// still uses the old credential), and the old credential is not
// invalidated. Env vars already pushed to production stay updated either
// way: a Vercel rollback never restores variable values.

const (
	// DefaultPromotionInterval is the wait between production alias reads
	// after a promote or rollback.
	DefaultPromotionInterval = 5 * time.Second
	// maxPromotionPolls bounds those reads (with the default interval, 5
	// minutes).
	maxPromotionPolls = 60
	maxRollbackTries  = 3
)

// release is a production release's state.
type release struct {
	ref      VercelRef
	previous string // served production when the operation started
	created  string // the staged deployment, once created
	// promoting is set immediately before the promote request is sent (or
	// when production is found already serving the new deployment): from
	// then on a failure rolls back.
	promoting bool
}

// productionEnv is ref's production scope.
func productionEnv(ref VercelRef) VercelEnv {
	return VercelEnv{TeamID: ref.TeamID, ProjectID: ref.ProjectID, Target: TargetProduction}
}

// productionBaseline reads, for a production target, the deployment serving
// production now. It runs before the operation changes anything, so a
// project whose production cannot be proven (no verified domain, split
// aliases, alias job running) fails with no side effects. No-op for preview.
func (r *run) productionBaseline(ref VercelRef) error {
	if ref.Target != TargetProduction {
		return nil
	}
	return r.step(StepVercelCurrent, CodeProviderFailed, func() error {
		id, err := r.vercel.CurrentDeployment(r.ctx, productionEnv(ref))
		if err != nil {
			return err
		}
		if !vercelDeploymentRe.MatchString(id) {
			return fail(CodeProviderResponse)
		}
		r.prod = &release{ref: ref, previous: id}
		r.res.PreviousDeploymentID = id
		return nil
	})
}

// promoteAndVerify promotes the healthy staged deployment and proves
// production serves it and is healthy. Any failure from the promote on rolls
// production back and is returned unchanged (its step and code).
func (r *run) promoteAndVerify(ref VercelRef, deployment, deploymentURL, healthPath string) error {
	rel := r.prod
	rel.created = deployment
	err := r.promoteSteps(rel, deploymentURL, healthPath)
	if err != nil && rel.promoting {
		r.rollBack(rel)
	}
	return err
}

func (r *run) promoteSteps(rel *release, deploymentURL, healthPath string) error {
	ref := rel.ref
	if err := r.step(StepVercelPromote, CodeProviderFailed, func() error {
		// Production must still be on the deployment read at the start:
		// otherwise the rollback target would be stale.
		cur, err := r.vercel.CurrentDeployment(r.ctx, productionEnv(ref))
		if err != nil {
			return err
		}
		if cur == rel.created {
			rel.promoting = true // promoted by someone else: treat as ours
			return fail(CodeProductionDrift)
		}
		if cur != rel.previous {
			return fail(CodeProductionDrift)
		}
		rel.promoting = true
		if err := r.vercel.Promote(r.ctx, ref.TeamID, ref.ProjectID, rel.created); err != nil {
			return err
		}
		r.res.Promoted = true
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(StepVercelVerifyProduction, CodeProductionNotServing, func() error {
		if err := r.awaitProduction(rel, rel.created); err != nil {
			return err
		}
		r.res.ProductionVerified = true
		return nil
	}); err != nil {
		return err
	}
	// The promoted deployment is checked at its own URL: the aliases were
	// just proven to point at it, and custom domains are never contacted.
	if err := r.step(StepHealthProduction, CodeHealthFailed, func() error {
		return r.checkHealth(deploymentURL, healthPath, &r.res.ProductionHealth)
	}); err != nil {
		return err
	}
	// Once more, immediately before the caller invalidates the old
	// credential: production must not have moved during the health window.
	return r.step(StepVercelConfirmProduction, CodeProviderFailed, func() error {
		cur, err := r.vercel.CurrentDeployment(r.ctx, productionEnv(ref))
		if err != nil {
			return err
		}
		if cur != rel.created {
			return fail(CodeProductionDrift)
		}
		return nil
	})
}

// awaitProduction reads production until it is proven to serve want. A read
// that fails (alias job running) or still shows the other deployment of this
// release is retried; a third deployment is drift.
func (r *run) awaitProduction(rel *release, want string) error {
	ref := rel.ref
	for i := 0; i < maxPromotionPolls; i++ {
		if i > 0 {
			if err := r.svc.clock.Sleep(r.ctx, r.svc.promoteIn); err != nil {
				return fail(CodeProductionNotServing)
			}
		}
		cur, err := r.vercel.CurrentDeployment(r.ctx, productionEnv(ref))
		if err != nil {
			continue
		}
		switch cur {
		case want:
			return nil
		case rel.previous, rel.created:
		default:
			return fail(CodeProductionDrift)
		}
	}
	return fail(CodeProductionNotServing)
}

// rollBack returns production to rel.previous after a failure at or after
// the promote. It never fails the operation itself: the original failure is
// reported, and the outcome is Result.Rollback (and RolledBack).
func (r *run) rollBack(rel *release) {
	ref := rel.ref
	r.res.Rollback = RollbackFailed
	_ = r.step(StepVercelRollback, CodeProviderFailed, func() error {
		tries, accepted := 0, false
		for i := 0; i < maxPromotionPolls; i++ {
			if i > 0 {
				if err := r.svc.clock.Sleep(r.ctx, r.svc.promoteIn); err != nil {
					return err
				}
			}
			cur, err := r.vercel.CurrentDeployment(r.ctx, productionEnv(ref))
			if err != nil {
				continue // alias job running: read again
			}
			switch cur {
			case rel.previous:
				if tries > 0 {
					r.res.Rollback, r.res.RolledBack = RollbackDone, true
				} else {
					r.res.Rollback = RollbackNotNeeded
				}
				return nil
			case rel.created:
				// Resent only after an error (at most maxRollbackTries); an
				// accepted or ambiguous request is settled by the reads.
				if !accepted && tries < maxRollbackTries {
					tries++
					accepted = r.vercel.Rollback(r.ctx, ref.TeamID, ref.ProjectID, rel.previous) == nil
				}
			default:
				r.res.Rollback = RollbackDrift
				return fail(CodeProductionDrift)
			}
		}
		return fail(CodeProductionNotServing)
	})
}
