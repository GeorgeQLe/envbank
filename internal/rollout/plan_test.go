package rollout

import (
	"testing"
	"time"
)

func TestProviderPlanDigestBindsOrderedActionsAndExpiry(t *testing.T) {
	created := time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC)
	plan := ProviderPlan{
		Version: PlanVersion, Bundle: "short-editor/example/staging",
		ManifestDigest:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SnapshotRevision: 3, Provider: "railway", ProviderIdentity: "workspace-identity",
		Target: TargetBinding{ProjectID: "project-id", EnvironmentID: "environment-id",
			ServiceIDs: map[string]string{"api": "service-id"}},
		Actions: []Action{{ID: "action-1", Operation: "upsert", Service: "api",
			ServiceID: "service-id", Name: "DATABASE_URL", Record: "DATABASE_URL",
			ExpectedRecordRevision: 8}},
		CreatedAt: created.Format(time.RFC3339), ExpiresAt: created.Add(PlanTTL).Format(time.RFC3339),
	}
	var err error
	plan.Digest, err = plan.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(created.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Actions = append([]Action(nil), plan.Actions...)
	changed.Actions[0].Name = "OTHER_NAME"
	if err := changed.Validate(created.Add(time.Minute)); err == nil {
		t.Fatal("action substitution did not invalidate plan digest")
	}
	if err := plan.Validate(created.Add(PlanTTL)); err == nil {
		t.Fatal("expired plan was accepted")
	}
	duplicate := plan
	duplicate.Actions = append(append([]Action(nil), plan.Actions...), plan.Actions[0])
	duplicate.Digest, err = duplicate.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Validate(created.Add(time.Minute)); err == nil {
		t.Fatal("duplicate action ID was accepted")
	}
	noncanonical := plan
	noncanonical.CreatedAt = "2026-08-09T16:00:00-04:00"
	noncanonical.ExpiresAt = "2026-08-09T16:15:00-04:00"
	noncanonical.Digest, err = noncanonical.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := noncanonical.Validate(created.Add(time.Minute)); err == nil {
		t.Fatal("noncanonical plan timestamps were accepted")
	}
}
