package contract

import (
	"reflect"
	"strings"
	"testing"
)

const validManifest = `version: 1
bundle: short-editor/siftcut-staging/staging
policies:
  password-32:
    type: password
    length: 32
    lowercase: true
    uppercase: true
    digits: true
    symbols: true
records:
  POSTGRES_PASSWORD:
    source: generate
    policy: password-32
  API_PASSWORD:
    source: generate
    policy: password-32
  DATABASE_URL:
    source: derive
    template: postgresql://siftcut_api:${secret:API_PASSWORD}@postgres.railway.internal:5432/siftcut
  CLERK_SECRET_KEY:
    source: import
    sensitivity: secret
targets:
  railway:
    project: siftcut-staging
    environment: staging
    services:
      postgres:
        order: 1
        variables:
          POSTGRES_DB: {source: constant, value: siftcut}
          POSTGRES_PASSWORD: {source: record, record: POSTGRES_PASSWORD}
      api:
        order: 2
        variables:
          NODE_ENV: {source: constant, value: staging}
          DATABASE_URL: {source: record, record: DATABASE_URL}
          CLERK_ISSUER: {source: import, sensitivity: public}
          CLERK_SECRET_KEY: {source: record, record: CLERK_SECRET_KEY}
      web:
        order: 3
        variables:
          VITE_CLERK_PUBLISHABLE_KEY: {source: import, sensitivity: public}
        absent:
          - VITE_API_URL
`

func TestParseSiftCutManifest(t *testing.T) {
	document, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if document.Manifest.Bundle != "short-editor/siftcut-staging/staging" {
		t.Fatalf("bundle = %q", document.Manifest.Bundle)
	}
	if len(document.Digest) != 64 {
		t.Fatalf("digest = %q", document.Digest)
	}
	if got, want := strings.Join(document.Derived, ","), "DATABASE_URL"; got != want {
		t.Fatalf("derived order = %q, want %q", got, want)
	}
}

func TestCanonicalDigestStableAcrossMapOrderAndFormatting(t *testing.T) {
	first, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	reordered := strings.Replace(validManifest,
		"          NODE_ENV: {source: constant, value: staging}\n          DATABASE_URL: {source: record, record: DATABASE_URL}",
		"          DATABASE_URL:\n            record: DATABASE_URL\n            source: record\n          NODE_ENV:\n            value: staging\n            source: constant", 1)
	second, err := Parse([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || string(first.Canonical) != string(second.Canonical) {
		t.Fatalf("canonical forms differ:\n%s\n%s", first.Canonical, second.Canonical)
	}
}

func TestParseRejectsAmbiguousYAML(t *testing.T) {
	tests := map[string]string{
		"duplicate":          strings.Replace(validManifest, "version: 1", "version: 1\nversion: 1", 1),
		"alias":              strings.Replace(validManifest, "source: generate", "source: &kind generate", 1) + "extra: *kind\n",
		"tag":                strings.Replace(validManifest, "version: 1", "version: !custom 1", 1),
		"merge":              strings.Replace(validManifest, "    source: generate\n    policy: password-32", "    <<: {source: generate}\n    policy: password-32", 1),
		"multiple documents": validManifest + "---\nversion: 1\n",
		"unknown field":      strings.Replace(validManifest, "bundle: short-editor", "unexpected: true\nbundle: short-editor", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse accepted invalid YAML")
			}
		})
	}
}

func TestParseRejectsSemanticErrors(t *testing.T) {
	tests := map[string]string{
		"missing record":          strings.Replace(validManifest, "record: DATABASE_URL", "record: MISSING_RECORD", 1),
		"present and absent":      strings.Replace(validManifest, "          - VITE_API_URL", "          - VITE_CLERK_PUBLISHABLE_KEY", 1),
		"secret constant":         strings.Replace(validManifest, "CLERK_SECRET_KEY: {source: record, record: CLERK_SECRET_KEY}", "CLERK_SECRET_KEY: {source: constant, value: prohibited}", 1),
		"database URL constant":   strings.Replace(validManifest, "DATABASE_URL: {source: record, record: DATABASE_URL}", "DATABASE_URL: {source: constant, value: postgresql://localhost/example}", 1),
		"credential URL constant": strings.Replace(validManifest, "NODE_ENV: {source: constant, value: staging}", "SERVICE_ENDPOINT: {source: constant, value: postgresql://user:password@localhost/example}", 1),
		"bad placeholder":         strings.Replace(validManifest, "${secret:API_PASSWORD}", "${env:API_PASSWORD}", 1),
		"missing policy":          strings.Replace(validManifest, "policy: password-32", "policy: missing", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse accepted invalid manifest")
			}
		})
	}
}

func TestParseRejectsDerivationCycle(t *testing.T) {
	input := strings.Replace(validManifest,
		"    template: postgresql://siftcut_api:${secret:API_PASSWORD}@postgres.railway.internal:5432/siftcut",
		"    template: ${secret:SECOND}\n  SECOND:\n    source: derive\n    template: ${secret:DATABASE_URL}", 1)
	_, err := Parse([]byte(input))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("error = %v, want cycle", err)
	}
}

func TestParseLimitsDocumentSize(t *testing.T) {
	input := make([]byte, MaxManifestBytes+1)
	if _, err := Parse(input); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseTemplate(t *testing.T) {
	parsed, err := ParseTemplate("prefix-${secret:ONE}-${secret:TWO}")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(parsed.References, ","), "ONE,TWO"; got != want {
		t.Fatalf("references = %q, want %q", got, want)
	}
	wantNodes := []TemplateNode{
		{Literal: "prefix-"},
		{Reference: "ONE"},
		{Literal: "-"},
		{Reference: "TWO"},
	}
	if !reflect.DeepEqual(parsed.Nodes, wantNodes) {
		t.Fatalf("nodes = %#v, want %#v", parsed.Nodes, wantNodes)
	}
	for _, invalid := range []string{"${ONE}", "${secret:lower}", "${secret:ONE"} {
		if _, err := ParseTemplate(invalid); err == nil {
			t.Errorf("ParseTemplate(%q) succeeded", invalid)
		}
	}
}

func TestParseInvalidTypeErrorDoesNotEchoValue(t *testing.T) {
	const sentinel = "SENTINEL_PARSE_VALUE_8faa603ea4c64cd9"
	input := strings.Replace(validManifest, "version: 1", "version: "+sentinel, 1)
	_, err := Parse([]byte(input))
	if err == nil {
		t.Fatal("Parse accepted an invalid version type")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error exposed invalid scalar value: %v", err)
	}
}

func TestParseEscapesTerminalControlCharactersInErrors(t *testing.T) {
	input := strings.Replace(validManifest, "POSTGRES_PASSWORD:", `"BAD\u001b]0;owned\nstatus: valid":`, 1)
	_, err := Parse([]byte(input))
	if err == nil {
		t.Fatal("Parse accepted an invalid record name")
	}
	message := err.Error()
	for _, control := range []string{"\x1b", "\n", "\r"} {
		if strings.Contains(message, control) {
			t.Fatalf("error contains terminal control %q: %q", control, message)
		}
	}
	for _, escaped := range []string{`\u001b`, `\u000a`} {
		if !strings.Contains(message, escaped) {
			t.Fatalf("error %q does not contain escaped control %q", message, escaped)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(validManifest))
	f.Add([]byte("version: 1\nversion: 1\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
