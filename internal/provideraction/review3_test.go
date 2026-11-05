package provideraction_test

import (
	"context"
	"strings"
	"testing"

	pa "github.com/GeorgeQLe/envbank/internal/provideraction"
	"github.com/GeorgeQLe/envbank/internal/provideraction/provideractiontest"
)

// Tests for the third security review of provider actions (November 5,
// 2026).

func claimants(e *env, env string, records ...string) []string {
	var out []string
	for _, rec := range records {
		b, _ := e.vault.Binding(rec)
		for _, d := range b.DeployedTo {
			if d.Env == env {
				out = append(out, rec)
				break
			}
		}
	}
	return out
}

// M1: a push whose write fails leaves the env var claimed by both the old
// and the new record. Rotations and env.remove refuse it; an env.push with
// replace_existing takes it over and releases every other claimant.
func TestFailedPushLeavesTwoClaimantsUntilTakenOver(t *testing.T) {
	e := newEnv(t, nil)
	main := branchRef("main")
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	replace := pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, true)
	e.fake.Fail = "vercel.upsert DB_URL preview"
	if st := e.run(t, pa.ActionVercelEnvPush, replace); st.State != pa.StateFailed || st.Step != pa.StepVercelEnvPush || len(st.Result.ReplacedRecords) != 0 {
		t.Fatalf("failed push %+v", st)
	}
	e.fake.Fail = ""
	if got := claimants(e, "DB_URL", "DATABASE_URL", "DATABASE_URL_UNPOOLED"); len(got) != 2 {
		t.Fatalf("claimants after the failed push: %v", got)
	}
	mark := len(e.log.Calls())
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, main)); code != pa.CodeEnvNameTaken {
		t.Fatalf("rotation of a doubly claimed env var: %q", code)
	}
	for _, rec := range []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED"} {
		if code := e.prepareCode(t, pa.ActionVercelEnvRemove, envRemove(t, rec, "DB_URL", main)); code != pa.CodeEnvNameTaken {
			t.Fatalf("remove by %s of a doubly claimed env var: %q", rec, code)
		}
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, false)); code != pa.CodeEnvNameTaken {
		t.Fatalf("push without replace_existing: %q", code)
	}
	e.noCallsSince(t, mark, "refused while doubly claimed")
	st := e.run(t, pa.ActionVercelEnvPush, replace)
	if st.State != pa.StateSucceeded || strings.Join(st.Result.ReplacedRecords, ",") != "DATABASE_URL" {
		t.Fatalf("take over %+v", st)
	}
	if got := claimants(e, "DB_URL", "DATABASE_URL", "DATABASE_URL_UNPOOLED"); strings.Join(got, ",") != "DATABASE_URL_UNPOOLED" {
		t.Fatalf("claimants after the take-over: %v", got)
	}
}

// M1: a push whose release fails part-way leaves the unreleased records
// claiming; replaced_records names only those released. A second
// replace_existing push finishes the job.
func TestPartialReleaseReportsWhatWasReleased(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	main := branchRef("main")
	all := []string{"DATABASE_URL", "DATABASE_URL_UNPOOLED", "STRIPE_WEBHOOK_SECRET"}
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	// The release fails outright: both records claim DB_URL.
	e.vault.FailBinding["DATABASE_URL"] = true
	st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, true))
	if st.State != pa.StateFailed || st.Step != pa.StepBindingRelease || len(st.Result.ReplacedRecords) != 0 {
		t.Fatalf("failed release %+v", st)
	}
	e.vault.FailBinding["DATABASE_URL"] = false
	if got := claimants(e, "DB_URL", all...); strings.Join(got, ",") != "DATABASE_URL,DATABASE_URL_UNPOOLED" {
		t.Fatalf("claimants after the failed release: %v", got)
	}
	// Replacing both, one release fails: only the other is reported.
	take := pushAt(t, main, map[string]string{"DB_URL": "STRIPE_WEBHOOK_SECRET"}, true)
	if s := e.summary(t, pa.ActionVercelEnvPush, take); !strings.Contains(s, "; REPLACES records DATABASE_URL, DATABASE_URL_UNPOOLED' values in DB_URL") {
		t.Fatalf("plural replace text: %s", s)
	}
	e.vault.FailBinding["DATABASE_URL_UNPOOLED"] = true
	st = e.run(t, pa.ActionVercelEnvPush, take)
	if st.State != pa.StateFailed || st.Step != pa.StepBindingRelease || strings.Join(st.Result.ReplacedRecords, ",") != "DATABASE_URL" {
		t.Fatalf("partial release %+v", st)
	}
	e.vault.FailBinding["DATABASE_URL_UNPOOLED"] = false
	if got := claimants(e, "DB_URL", all...); strings.Join(got, ",") != "DATABASE_URL_UNPOOLED,STRIPE_WEBHOOK_SECRET" {
		t.Fatalf("claimants after the partial release: %v", got)
	}
	st = e.run(t, pa.ActionVercelEnvPush, take)
	if st.State != pa.StateSucceeded || strings.Join(st.Result.ReplacedRecords, ",") != "DATABASE_URL_UNPOOLED" {
		t.Fatalf("finish %+v", st)
	}
	if got := claimants(e, "DB_URL", all...); strings.Join(got, ",") != "STRIPE_WEBHOOK_SECRET" {
		t.Fatalf("claimants at the end: %v", got)
	}
}

// M2: a revoked binding's claim still counts. Another record's push needs
// replace_existing; the revoked record may remove its own env var.
func TestRevokedClaimCounts(t *testing.T) {
	e := newEnv(t, nil)
	main := branchRef("main")
	if st := e.run(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL"}, false)); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	b, _ := e.vault.Binding("DATABASE_URL")
	b.Revoked = true
	e.vault.Bind(b)
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, false)); code != pa.CodeEnvNameTaken {
		t.Fatalf("push over a revoked record's env var: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvRemove, envRemove(t, "DATABASE_URL_UNPOOLED", "DB_URL", main)); code != pa.CodeNotDeployed {
		t.Fatalf("remove by a non-claimant: %q", code)
	}
	if st := e.run(t, pa.ActionVercelEnvRemove, envRemove(t, "DATABASE_URL", "DB_URL", main)); st.State != pa.StateSucceeded {
		t.Fatalf("remove by the revoked sole claimant %+v", st)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL_UNPOOLED"}, false)); code != "" {
		t.Fatalf("push after the remove: %q", code)
	}
}

// M3: a Vercel env var no binding claims (set by hand) is never silently
// overwritten: refused before the prompt, or named in the approval with
// replace_existing; one that appears after the approval stops the push.
func TestForeignEnvVarNeedsReplaceExisting(t *testing.T) {
	e := newEnv(t, nil)
	main := branchRef("main")
	e.fake.Foreign = map[string]bool{"DB_URL": true}
	push := pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL"}, false)
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, push); code != pa.CodeEnvNameTaken {
		t.Fatalf("push over a hand-set env var: %q", code)
	}
	if e.log.Index("vercel.upsert DB_URL preview") >= 0 {
		t.Fatal("written")
	}
	replace := pushAt(t, main, map[string]string{"DB_URL": "DATABASE_URL"}, true)
	if s := e.summary(t, pa.ActionVercelEnvPush, replace); !strings.Contains(s, "; REPLACES a value NOT written by this broker in DB_URL") {
		t.Fatalf("foreign replace text: %s", s)
	}
	if st := e.run(t, pa.ActionVercelEnvPush, replace); st.State != pa.StateSucceeded || st.Result.Variables["DB_URL"] != "upserted" {
		t.Fatalf("approved replace %+v", st)
	}
	// Set by hand between the approval and the write.
	other := pushAt(t, main, map[string]string{"PG_URL": "DATABASE_URL"}, false)
	prep, code := e.svc.Prepare(context.Background(), pa.ActionVercelEnvPush, other)
	if code != "" {
		t.Fatal(code)
	}
	e.fake.Foreign["PG_URL"] = true
	id, code := e.svc.Start(prep, owner, scope, nil)
	if code != "" {
		t.Fatal(code)
	}
	if st := e.wait(t, id); st.State != pa.StateFailed || st.Code != pa.CodeEnvNameTaken || e.log.Index("vercel.upsert PG_URL preview") >= 0 {
		t.Fatalf("appeared after the approval %+v", st)
	}
	// A rotation that newly writes a name refuses a hand-set one too.
	e.fake.Foreign["DATABASE_URL"] = true
	if code := e.prepareCode(t, pa.ActionNeonRotate, neonRotate(t, branchRef("feat/z"), main)); code != pa.CodeEnvNameTaken {
		t.Fatalf("rotation over a hand-set env var: %q", code)
	}
}

// L-a: while a sibling Neon binding is mid-rotation, a push of the group
// is refused (only the rotation's retry may proceed).
func TestPushRefusedWhileRotationIncomplete(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.vault.Binding("DATABASE_URL_UNPOOLED")
	b.PendingRole, b.PendingHost = "app_b", strings.Repeat("a", 64)
	e.vault.Bind(b)
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, branchRef("main"), map[string]string{"DATABASE_URL": "DATABASE_URL"}, false)); code != pa.CodeRotationIncomplete {
		t.Fatalf("push during an incomplete rotation: %q", code)
	}
	// A partial binding follow (pooled switched to app_b, direct still
	// pending): the retry, which resets app_b again, is the way out, so no
	// push may deploy the pooled app_b URI before it.
	e = newEnv(t, nil)
	pooled, _ := e.vault.Binding("DATABASE_URL")
	pooled.ActiveRole, pooled.RetiringRole = "app_b", "app_a"
	e.vault.Bind(pooled)
	direct, _ := e.vault.Binding("DATABASE_URL_UNPOOLED")
	direct.PendingRole, direct.PendingHost = "app_b", strings.Repeat("a", 64)
	e.vault.Bind(direct)
	if s := e.summary(t, pa.ActionNeonRotate, rotateParams(t)); !strings.Contains(s, "reset role app_b") {
		t.Fatalf("retry text: %s", s)
	}
	if code := e.prepareCode(t, pa.ActionVercelEnvPush, pushAt(t, branchRef("main"), map[string]string{"DATABASE_URL": "DATABASE_URL"}, false)); code != pa.CodeRotationIncomplete {
		t.Fatalf("push after a partial binding follow: %q", code)
	}
}

// L-b: an interrupted rotation's retry accepts revision R+1 only if it is
// the rotation's own store (pending role as user, same host); an owner
// edit at R+1 is refused before anything is reset.
func TestPendingRetryRefusesOwnerEdit(t *testing.T) {
	for name, uri := range map[string]string{
		"other host": "postgresql://app_b:pw@attacker.example.net/neondb",
		"other user": "postgresql://app_a:pw@ep-x-pooler.neon.tech/neondb",
		"no uri":     "not a uri",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.fake.Fail = "neon.reset app_b"
			if st := e.run(t, pa.ActionNeonRotate, rotateParams(t)); st.State != pa.StateFailed || st.Step != pa.StepNeonResetNewRole {
				t.Fatalf("interrupted %+v", st)
			}
			e.fake.Fail = ""
			if b, _ := e.vault.Binding("DATABASE_URL"); b.PendingRole != "app_b" || len(b.PendingHost) != 64 {
				t.Fatalf("pending binding %+v", b)
			}
			e.vault.Set("DATABASE_URL", uri)
			mark := len(e.log.Calls())
			st := e.run(t, pa.ActionNeonRotate, rotateParams(t))
			if st.State != pa.StateFailed || st.Step != pa.StepBindingPending || st.Code != pa.CodeRecordNotBound {
				t.Fatalf("retry over an owner edit %+v", st)
			}
			for _, c := range e.log.Calls()[mark:] {
				if strings.HasPrefix(c, "neon.reset") || strings.HasPrefix(c, "vercel.upsert") || strings.HasPrefix(c, "neon.invalidate") {
					t.Fatalf("acted after an owner edit: %v", e.log.Calls()[mark:])
				}
			}
			if v, _ := e.vault.Value("DATABASE_URL"); v != uri {
				t.Fatal("owner edit overwritten")
			}
		})
	}
}

// L-c: a push is refused if its records could never be rotated: an
// all-branches preview scope (see TestRotationRefusesUnscopedPreview),
// more scopes than one rotation names (TestPushRefusesMoreScopesThanARotation),
// or a rotation plan too long for the approval prompt.
func TestPushRefusedIfRotationPlanCannotFit(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	var seen []string
	fit := func(ok bool) context.Context {
		return pa.WithPlanFit(context.Background(), func(s string) bool { seen = append(seen, s); return ok })
	}
	for _, rec := range []string{"DATABASE_URL", "STRIPE_WEBHOOK_SECRET"} {
		params := pushAt(t, branchRef("main"), map[string]string{"X_" + rec: rec}, false)
		seen = nil
		prep, code := e.svc.Prepare(fit(false), pa.ActionVercelEnvPush, params)
		prep.Release()
		if code != pa.CodePlanTooLong || len(seen) == 0 || !strings.Contains(seen[0], "ROTATE") {
			t.Fatalf("%s: code %q, checked %q", rec, code, seen)
		}
		prep, code = e.svc.Prepare(fit(true), pa.ActionVercelEnvPush, params)
		prep.Release()
		if code != "" {
			t.Fatalf("%s fits: %q", rec, code)
		}
	}
}

// L-d: env.push and env.remove lock each record's provider resource, so
// they cannot interleave with a delete of the Neon project or Stripe
// endpoint behind it.
func TestEnvOpsLockProviderResources(t *testing.T) {
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	ctx := context.Background()
	main := branchRef("main")
	deleteNeon := js(t, map[string]any{"project_id": "calm-sky-123456"})
	deleteStripe := js(t, map[string]any{"endpoint_id": "we_old1"})
	push, code := e.svc.Prepare(ctx, pa.ActionVercelEnvPush, pushAt(t, main, map[string]string{"DATABASE_URL": "DATABASE_URL", "WH": "STRIPE_WEBHOOK_SECRET"}, false))
	if code != "" {
		t.Fatal(code)
	}
	if code := e.prepareCode(t, pa.ActionNeonProjectDelete, deleteNeon); code != pa.CodeResourceBusy {
		t.Fatalf("neon delete during a push: %q", code)
	}
	if code := e.prepareCode(t, pa.ActionStripeWebhookDelete, deleteStripe); code != pa.CodeResourceBusy {
		t.Fatalf("stripe delete during a push: %q", code)
	}
	id, code := e.svc.Start(push, owner, scope, nil)
	if code != "" {
		t.Fatal(code)
	}
	if st := e.wait(t, id); st.State != pa.StateSucceeded {
		t.Fatalf("push %+v", st)
	}
	rm, code := e.svc.Prepare(ctx, pa.ActionVercelEnvRemove, envRemove(t, "STRIPE_WEBHOOK_SECRET", "WH", main))
	if code != "" {
		t.Fatal(code)
	}
	if code := e.prepareCode(t, pa.ActionStripeWebhookDelete, deleteStripe); code != pa.CodeResourceBusy {
		t.Fatalf("stripe delete during a remove: %q", code)
	}
	rm.Release()
	rm, code = e.svc.Prepare(ctx, pa.ActionVercelEnvRemove, envRemove(t, "DATABASE_URL", "DATABASE_URL", main))
	if code != "" {
		t.Fatal(code)
	}
	if code := e.prepareCode(t, pa.ActionNeonProjectDelete, deleteNeon); code != pa.CodeResourceBusy {
		t.Fatalf("neon delete during a remove: %q", code)
	}
	rm.Release()
}

// L-e: the Stripe drift check covers status and api_version; the copy is
// created with the live endpoint's version, which is recorded.
func TestStripeRotationKeepsStatusAndVersion(t *testing.T) {
	live := func(status, version string) pa.StripeWebhook {
		return pa.StripeWebhook{URL: "https://shop.example.com/api/stripe/webhook", Events: []string{"checkout.session.completed", "invoice.paid"}, Status: status, APIVersion: version}
	}
	e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
	for name, w := range map[string]pa.StripeWebhook{"disabled": live("disabled", "2024-06-20"), "bad version": live("enabled", "latest")} {
		e.fake.Endpoints["we_old1"] = w
		if code := e.prepareCode(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t)); code != pa.CodeStripeEndpointDrift {
			t.Fatalf("%s: %q", name, code)
		}
	}
	e.fake.Endpoints["we_old1"] = live("enabled", "2024-06-20")
	st := e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
	if st.State != pa.StateSucceeded {
		t.Fatalf("rotate %+v", st)
	}
	newID := st.Result.EndpointID
	if got := e.fake.Endpoints[newID]; got.APIVersion != "2024-06-20" {
		t.Fatalf("copy created with version %q", got.APIVersion)
	}
	prov, err := e.vault.LoadStripeEndpoint(context.Background(), newID)
	if err != nil || prov.APIVersion != "2024-06-20" {
		t.Fatalf("recorded version %q (%v)", prov.APIVersion, err)
	}
	// The recorded version must still match at the next rotation.
	w := e.fake.Endpoints[newID]
	w.APIVersion = "2025-03-31.basil"
	e.fake.Endpoints[newID] = w
	if code := e.prepareCode(t, pa.ActionStripeWebhookRotate, stripeRotate(t, newID, vercelRef("preview"))); code != pa.CodeStripeEndpointDrift {
		t.Fatalf("version drift: %q", code)
	}
	// stripe.webhook.create records the account default version it got.
	st = e.run(t, pa.ActionStripeWebhookCreate, js(t, map[string]any{"url": "https://shop.example.com/api/stripe", "events": []string{"invoice.paid"}, "record": "WHSEC_NEW"}))
	if st.State != pa.StateSucceeded {
		t.Fatalf("create %+v", st)
	}
	if prov, _ := e.vault.LoadStripeEndpoint(context.Background(), st.Result.EndpointID); prov.APIVersion != provideractiontest.DefaultStripeAPIVersion {
		t.Fatalf("create recorded version %q", prov.APIVersion)
	}
}

// A bound previous_record (from an earlier rotation) changed meanwhile is
// never overwritten, and nothing is created: changed just before the
// store, the revision-checked write refuses it (RECORD_CHANGED); changed
// after the approval, the run's binding check does (RECORD_NOT_BOUND).
func TestStripePreviousRecordChanged(t *testing.T) {
	for _, c := range []struct {
		name, step, code string
		atStore          bool
	}{
		{"before the store", pa.StepVaultMoveCurrent, pa.CodeRecordChanged, true},
		{"after the approval", pa.StepBindingCheck, pa.CodeRecordNotBound, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, map[string]string{"STRIPE_WEBHOOK_SECRET": provideractiontest.Sentinel("whsec_")})
			st := e.run(t, pa.ActionStripeWebhookRotate, stripeRotateParams(t))
			if st.State != pa.StateSucceeded {
				t.Fatalf("first rotate %+v", st)
			}
			if b, ok := e.vault.Binding("STRIPE_WEBHOOK_SECRET_PREVIOUS"); !ok || b.Revoked {
				t.Fatalf("previous_record not bound: %+v", b)
			}
			prep, code := e.svc.Prepare(context.Background(), pa.ActionStripeWebhookRotate, stripeRotate(t, st.Result.EndpointID, vercelRef("preview")))
			if code != "" {
				t.Fatal(code)
			}
			if c.atStore {
				changed := false
				e.vault.BeforeStore = func(name string) {
					if name == "STRIPE_WEBHOOK_SECRET_PREVIOUS" && !changed {
						changed = true
						e.vault.Set(name, "changed-by-owner")
					}
				}
			} else {
				e.vault.Set("STRIPE_WEBHOOK_SECRET_PREVIOUS", "changed-by-owner")
			}
			mark := len(e.log.Calls())
			id, code := e.svc.Start(prep, owner, scope, nil)
			if code != "" {
				t.Fatal(code)
			}
			st = e.wait(t, id)
			if st.State != pa.StateFailed || st.Code != c.code || st.Step != c.step {
				t.Fatalf("status %+v", st)
			}
			if v, _ := e.vault.Value("STRIPE_WEBHOOK_SECRET_PREVIOUS"); v != "changed-by-owner" {
				t.Fatal("previous_record overwritten")
			}
			for _, call := range e.log.Calls()[mark:] {
				if call == "stripe.create" || strings.HasPrefix(call, "vercel.upsert") || strings.HasPrefix(call, "stripe.delete") {
					t.Fatalf("acted: %v", e.log.Calls()[mark:])
				}
			}
			e.noLeak(t, "status", st)
		})
	}
}
