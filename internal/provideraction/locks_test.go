package provideraction_test

import (
	"context"
	"encoding/json"
	"testing"

	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

func redeployParams(t *testing.T, project string) json.RawMessage {
	return js(t, map[string]any{"team_id": "team_abc123", "project_id": project, "target": "preview"})
}

// Two operations on one resource never interleave: while the first holds
// its resources (approved and running, or only prepared and waiting for its
// owner's Touch ID) the second is refused RESOURCE_BUSY before any prompt
// and without a provider call. Other resources are unaffected, and the lock
// ends with the first operation.
func TestResourceLockRefusesSecondOperationBeforeItsPrompt(t *testing.T) {
	ctx := context.Background()
	whsec := provideractiontest.Sentinel("whsec_")
	cases := []struct {
		name           string
		first, second  func(t *testing.T) (string, json.RawMessage)
		other          func(t *testing.T) (string, json.RawMessage)
		secondAfterRun bool // the second still succeeds once the first finished
	}{
		{"neon project: rotate then delete",
			func(t *testing.T) (string, json.RawMessage) { return pa.ActionNeonRotate, rotateParams(t) },
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "calm-sky-123456"})
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "other-project-1"})
			}, true},
		{"vercel project: push then redeploy",
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionVercelEnvPush, js(t, map[string]any{"team_id": "team_abc123", "project_id": "prj_abc123", "target": "preview", "variables": map[string]string{"DATABASE_URL": "DATABASE_URL"}})
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionVercelRedeploy, redeployParams(t, "prj_abc123")
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionVercelRedeploy, redeployParams(t, "prj_other1")
			}, true},
		{"vercel project: neon rotate then redeploy",
			func(t *testing.T) (string, json.RawMessage) { return pa.ActionNeonRotate, rotateParams(t) },
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionVercelRedeploy, redeployParams(t, "prj_abc123")
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionVercelRedeploy, redeployParams(t, "prj_other1")
			}, true},
		{"stripe lineage: rotate then delete",
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionStripeWebhookRotate, stripeRotateParams(t)
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": "we_old1"})
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionStripeWebhookDelete, js(t, map[string]any{"endpoint_id": "we_unrelated"})
			}, false}, // after the rotation, we_old1 is deleted by it; the delete still runs (and fails at Stripe)
		{"records: two creates of one record",
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://app.example.com/api/stripe", "events": []string{"checkout.session.completed"}, "record": "NEW_WHSEC"})
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://app.example.com/api/other", "events": []string{"checkout.session.completed"}, "record": "NEW_WHSEC"})
			},
			func(t *testing.T) (string, json.RawMessage) {
				return pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://app.example.com/api/stripe", "events": []string{"checkout.session.completed"}, "record": "OTHER_WHSEC"})
			}, false}, // the record exists afterwards: RECORD_EXISTS
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": whsec}, func(o *pa.Options) { o.MaxRunning = 4 })
			a1, p1 := c.first(t)
			a2, p2 := c.second(t)
			ao, po := c.other(t)

			// Prepared only (the owner is being asked): already locked.
			prep, code := e.svc.Prepare(ctx, a1, p1)
			if code != "" {
				t.Fatalf("first: %s", code)
			}
			if _, code := e.svc.Prepare(ctx, a2, p2); code != pa.CodeResourceBusy {
				t.Fatalf("second while the first awaits approval: %q", code)
			}
			// Declined: the lock is released with the preparation.
			prep.Release()
			p, code := e.svc.Prepare(ctx, a2, p2)
			if code != "" {
				t.Fatalf("second after the first was declined: %q", code)
			}
			p.Release()

			// Running: still locked; an unrelated resource is not.
			e.fake.Block = make(chan struct{})
			prep, code = e.svc.Prepare(ctx, a1, p1)
			if code != "" {
				t.Fatalf("first: %s", code)
			}
			id, code := e.svc.Start(prep, owner, scope, nil)
			if code != "" {
				t.Fatal(code)
			}
			prep.Release() // as the gate does after Start: must not unlock a started operation
			before := len(e.log.Calls())
			if _, code := e.svc.Prepare(ctx, a2, p2); code != pa.CodeResourceBusy {
				t.Fatalf("second while the first runs: %q", code)
			}
			other, code := e.svc.Prepare(ctx, ao, po)
			if code != "" {
				t.Fatalf("unrelated resource: %q", code)
			}
			other.Release()
			if len(e.log.Calls()) > before+1 { // the first may have logged its blocked call
				t.Fatalf("a refused preparation called a provider: %v", e.log.Calls()[before:])
			}
			close(e.fake.Block)
			if st := e.wait(t, id); st.State != pa.StateSucceeded {
				t.Fatalf("first: %+v", st)
			}
			e.fake.Block = nil
			// Finished: the lock is gone.
			p, code = e.svc.Prepare(ctx, a2, p2)
			if c.secondAfterRun && code != "" {
				t.Fatalf("second after the first finished: %q", code)
			}
			if code == pa.CodeResourceBusy {
				t.Fatal("lock kept after the operation finished")
			}
			p.Release()
		})
	}
}

// A failed operation releases its lock too.
func TestResourceLockReleasedOnFailure(t *testing.T) {
	e := newEnv(t, nil)
	e.fake.Fail = "neon.delete_project abc"
	params := js(t, map[string]any{"project_id": "abc"})
	if st := e.run(t, pa.ActionNeonProjectDelete, params); st.State != pa.StateFailed {
		t.Fatalf("status %+v", st)
	}
	e.fake.Fail = ""
	if st := e.run(t, pa.ActionNeonProjectDelete, params); st.State != pa.StateSucceeded {
		t.Fatalf("status %+v", st)
	}
}

// Every port is closed once when its operation ends, before the service
// wipes the credential buffers.
func TestPortsClosedWhenOperationEnds(t *testing.T) {
	e := newEnv(t, nil)
	if st := e.run(t, pa.ActionNeonRotate, rotateParams(t)); st.State != pa.StateSucceeded {
		t.Fatalf("status %+v", st)
	}
	if n := e.fake.Closes(); n != 2 {
		t.Fatalf("closed %d ports, want 2 (Neon and Vercel)", n)
	}
	e.fake.Fail = "neon.delete_project abc"
	e.run(t, pa.ActionNeonProjectDelete, js(t, map[string]any{"project_id": "abc"}))
	if n := e.fake.Closes(); n != 3 {
		t.Fatalf("failed operation's port not closed: %d", n)
	}
}
