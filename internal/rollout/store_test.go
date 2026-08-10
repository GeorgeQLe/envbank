package rollout

import (
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/protocol"
)

func TestValidateSnapshotBindingsChecksCurrentRecordBeforeApply(t *testing.T) {
	plan := ProviderPlan{Bundle: "short-editor/example/staging", ManifestDigest: strings.Repeat("a", 64),
		SnapshotRevision: 3, Target: TargetBinding{ServiceIDs: map[string]string{"api": "api-id"}},
		Actions: []Action{{ID: "action-1", Operation: "upsert", Service: "api", ServiceID: "api-id",
			Name: "DATABASE_URL", Record: "database-url", ExpectedRecordRevision: 8}}}
	snapshot := bundle.Snapshot{Bundle: plan.Bundle, ManifestDigest: plan.ManifestDigest,
		RecordRevisions: map[string]int64{"database-url": 8}}
	physical := bundle.PhysicalName(plan.Bundle, "database-url")

	if err := validateSnapshotBindings(plan, 3, snapshot,
		[]protocol.SecretRecord{{Name: physical, Revision: 8}}); err != nil {
		t.Fatal(err)
	}
	for name, records := range map[string][]protocol.SecretRecord{
		"advanced": {{Name: physical, Revision: 9}},
		"missing":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSnapshotBindings(plan, 3, snapshot, records); err == nil {
				t.Fatal("stale current record binding was accepted")
			}
		})
	}
}
