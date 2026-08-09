package bundle

import "testing"

func TestSnapshotSchemaValidation(t *testing.T) {
	snapshot := Snapshot{
		Version: SnapshotVersion, Bundle: "short-editor/example/staging",
		ManifestDigest:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PhysicalToLogical: map[string]string{"ENVBANK_B1_HASH_TOKEN": "TOKEN"},
		Sources:           map[string]SourceStatus{"TOKEN": {Source: "generate", Status: "ready"}},
		RecordRevisions:   map[string]int64{"TOKEN": 4},
		CreatedAt:         "2026-08-09T20:00:00Z",
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	snapshot.RecordRevisions["TOKEN"] = 0
	if err := snapshot.Validate(); err == nil {
		t.Fatal("zero source revision was accepted")
	}
}

func TestSnapshotRequiresCompleteMappingsAndCanonicalTime(t *testing.T) {
	base := Snapshot{
		Version: SnapshotVersion, Bundle: "short-editor/example/staging",
		ManifestDigest:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PhysicalToLogical: map[string]string{"ENVBANK_B1_HASH_TOKEN": "TOKEN"},
		Sources:           map[string]SourceStatus{"TOKEN": {Source: "generate", Status: "ready"}},
		RecordRevisions:   map[string]int64{"TOKEN": 4},
		CreatedAt:         "2026-08-09T20:00:00Z",
	}
	missingSource := base
	missingSource.Sources = map[string]SourceStatus{}
	if err := missingSource.Validate(); err == nil {
		t.Fatal("snapshot with missing source state was accepted")
	}
	missingRevision := base
	missingRevision.RecordRevisions = map[string]int64{}
	if err := missingRevision.Validate(); err == nil {
		t.Fatal("snapshot with missing record revision was accepted")
	}
	noncanonicalTime := base
	noncanonicalTime.CreatedAt = "2026-08-09T16:00:00-04:00"
	if err := noncanonicalTime.Validate(); err == nil {
		t.Fatal("snapshot with noncanonical creation time was accepted")
	}
}
