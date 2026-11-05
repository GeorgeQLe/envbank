package vercelworkflow

import (
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/contract"
)

const publicVercelManifest = `version: 1
bundle: arcade/acceptance
records:
  API_SECRET:
    source: import
    sensitivity: secret
targets:
  vercel:
    team_id: team_fixture
    project: disposable-project
    project_id: prj_fixture
    environment: preview
    git_branch: envbank-acceptance
    services:
      environment:
        order: 1
        variables:
          API_SECRET:
            source: record
            record: API_SECRET
`

func TestPublicVercelManifestBindsImmutableScope(t *testing.T) {
	d, e := contract.Parse([]byte(publicVercelManifest))
	if e != nil {
		t.Fatal(e)
	}
	s, e := ScopeForManifest(d)
	if e != nil || s.GitBranch != "envbank-acceptance" || s.TeamID != "team_fixture" {
		t.Fatal("public contract lost exact Vercel scope")
	}
	for _, name := range []string{"NEXT_PUBLIC_SECRET", "VUE_APP_TOKEN", "NODE_OPTIONS", "VERCEL_TOKEN"} {
		altered := strings.Replace(publicVercelManifest, "          API_SECRET:", "          "+name+":", 1)
		doc, e := contract.Parse([]byte(altered))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ScopeForManifest(doc); e == nil {
			t.Fatal("client-exposed/runtime variable was accepted for vault secret")
		}
	}
}
