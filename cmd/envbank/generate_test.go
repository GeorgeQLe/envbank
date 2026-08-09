package main

import (
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/password"
	"github.com/GeorgeQLe/envbank/internal/protocol"
)

func TestGenerateCreatesAndDoesNotPrintPassword(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	args := append([]string{"generate", "--length", "32", "--symbols=false"}, authArgs(fixture, fixture.firstConfigPath)...)
	stdout, stderr, err := captureRun(t, append(args, "WEB_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	record := findRecord(loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath), "WEB_PASSWORD")
	if record == nil || record.Revision != 1 || len(record.Value) != 32 {
		t.Fatalf("record = %#v", record)
	}
	if strings.ContainsAny(record.Value, password.Symbols) {
		t.Fatalf("generated value contains symbols: %q", record.Value)
	}
	if strings.Contains(stdout+stderr, record.Value) {
		t.Fatal("command output exposed generated password")
	}
	if strings.TrimSpace(stdout) != "WEB_PASSWORD revision 1" || stderr != "" {
		t.Fatalf("output stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestGenerateReplacementAndMetadataPolicy(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	existing := protocol.SecretRecord{Name: "PASSWORD", Value: "old-plaintext", CreatedAt: "2025-01-02T03:04:05Z", RotatedAt: "2025-02-03T04:05:06Z", RotateEveryDays: 45, Revision: 3, AllowedOrigins: []string{"https://example.com"}}
	storeFixtureRecords(t, fixture, []protocol.SecretRecord{existing})
	base := append([]string{"generate"}, authArgs(fixture, fixture.firstConfigPath)...)
	stdout, stderr, err := captureRun(t, append(base, "PASSWORD"))
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("replacement refusal = %v", err)
	}
	if strings.Contains(stdout+stderr+err.Error(), existing.Value) {
		t.Fatal("replacement refusal exposed plaintext")
	}
	args := append(base, "--replace", "PASSWORD")
	stdout, stderr, err = captureRun(t, args)
	if err != nil {
		t.Fatal(err)
	}
	replaced := findRecord(loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath), "PASSWORD")
	if replaced.Revision != 4 || replaced.CreatedAt != existing.CreatedAt || replaced.RotateEveryDays != 45 || len(replaced.AllowedOrigins) != 1 || replaced.AllowedOrigins[0] != existing.AllowedOrigins[0] || replaced.Value == existing.Value {
		t.Fatalf("replacement metadata = %#v", replaced)
	}
	if strings.Contains(stdout+stderr, replaced.Value) {
		t.Fatal("replacement output exposed generated password")
	}
	args = append(base, "--replace", "--rotate-days", "0", "PASSWORD")
	if _, _, err := captureRun(t, args); err != nil {
		t.Fatal(err)
	}
	replaced = findRecord(loadFixtureRecords(t, fixture.firstConfigPath, fixture.passphrasePath), "PASSWORD")
	if replaced.Revision != 5 || replaced.RotateEveryDays != 0 {
		t.Fatalf("explicit rotation policy not applied: %#v", replaced)
	}
}

func TestGenerateRejectsExplicitNegativeRotationPolicy(t *testing.T) {
	fixture := newCLIDeviceFixture(t)
	args := append([]string{"generate", "--rotate-days", "-1"}, authArgs(fixture, fixture.firstConfigPath)...)
	if _, _, err := captureRun(t, append(args, "PASSWORD")); err == nil || !strings.Contains(err.Error(), "zero or greater") {
		t.Fatalf("negative rotation policy error = %v", err)
	}
}
