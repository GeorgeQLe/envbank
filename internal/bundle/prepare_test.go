package bundle

import (
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/protocol"
)

func TestPrepareJournalValidation(t *testing.T) {
	journal := PrepareJournal{
		Version: PrepareJournalVersion, Bundle: "example/bundle",
		ManifestDigest: strings.Repeat("a", 64), UpdatedAt: "2026-08-09T20:00:00Z",
		Records: map[string]JournalRecord{"TOKEN": {Source: "generate", Revision: 1}},
	}
	if err := journal.Validate(); err != nil {
		t.Fatal(err)
	}
	journal.Records["TOKEN"] = JournalRecord{Source: "generate", Revision: 0}
	if err := journal.Validate(); err == nil {
		t.Fatal("journal accepted a zero record revision")
	}
}

func TestPhysicalNameVectorAndIsolation(t *testing.T) {
	const want = "ENVBANK_B1_75XA4EHDJJEMCVR4MTGZQ2OJZMAQGU4KCTJB5AFJDBPCDOBEDX5A_TOKEN"
	if got := PhysicalName("example/siftcut/staging", "TOKEN"); got != want {
		t.Fatalf("PhysicalName vector = %q, want %q", got, want)
	}
	if PhysicalName("example/siftcut/production", "TOKEN") == want {
		t.Fatal("different bundles produced the same physical name")
	}
}

func TestReadImportsRequiresExactBoundedJSONObject(t *testing.T) {
	values, err := readImports(strings.NewReader(`{"ALPHA":"value"}`), []string{"ALPHA"})
	if err != nil || string(values["ALPHA"]) != "value" {
		t.Fatalf("values=%v err=%v", values, err)
	}
	for _, input := range []string{
		`{"ALPHA":"value","EXTRA":"value"}`,
		`{"ALPHA":"first","ALPHA":"second"}`,
		`{"WRONG":"value"}`,
		`["value"]`,
		`{"ALPHA":1}`,
	} {
		if _, err := readImports(strings.NewReader(input), []string{"ALPHA"}); err == nil {
			t.Fatalf("accepted invalid trusted input %q", input)
		}
	}
	if _, err := readImports(strings.NewReader(`{"secret-shaped-key":"value"}`), []string{"ALPHA"}); err == nil || strings.Contains(err.Error(), "secret-shaped-key") {
		t.Fatalf("unexpected input name was exposed: %v", err)
	}
}

func TestExpandIsBounded(t *testing.T) {
	template := contract.Template{Nodes: []contract.TemplateNode{{Reference: "INPUT"}}}
	records := map[string]protocol.SecretRecord{
		PhysicalName("bundle", "INPUT"): {Value: strings.Repeat("x", MaxDerivedBytes+1)},
	}
	if _, err := expand(template, "bundle", records); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized derivation error = %v", err)
	}
}
