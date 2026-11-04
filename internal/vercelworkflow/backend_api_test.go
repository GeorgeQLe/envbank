package vercelworkflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
)

// Runs the workflow through the real HTTP adapter. The fake API deliberately
// echoes the private fixture in unrelated response fields; those fields must
// never enter an MCP receipt or encrypted operation payload.
func TestWorkflowAcrossActualVercelHTTPAdapter(t *testing.T) {
	for _, environment := range []string{"preview", "production"} {
		t.Run(environment, func(t *testing.T) {
			b, s, old, _, private := fixture(t, environment)
			scope := old.scope
			var mu sync.Mutex
			writes, creates, promotes, rollbacks := 0, 0, 0, 0
			current := "dpl_source"
			marker := ""
			written := false
			deployment := func(id string) map[string]any {
				meta := map[string]string{"githubCommitRef": scope.GitBranch, "githubCommitSha": "abc1234def5678"}
				if id == "dpl_new" {
					meta[vercel.MetaOperationKey] = marker
					meta[vercel.MetaScopeKey] = scope.Fingerprint()
					meta[vercel.MetaSourceKey] = "dpl_source"
				}
				target := any(nil)
				substate := "STAGED"
				if environment == "production" {
					target = "production"
					if id == current || id == "dpl_source" {
						substate = "PROMOTED"
					}
				}
				return map[string]any{"readySubstate": substate, "id": id, "projectId": scope.ProjectID, "ownerId": scope.TeamID, "target": target, "readyState": "READY", "url": "fixture.vercel.app", "gitSource": map[string]string{"ref": scope.GitBranch, "sha": "abc1234def5678"}, "meta": meta, "untrustedEcho": privateFixture}
			}
			entry := func() map[string]any {
				return map[string]any{"id": "envfixture", "key": "API_SECRET", "type": "sensitive", "target": []string{environment}, "gitBranch": scope.GitBranch, "value": privateFixture}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer fake-api-credential" || r.URL.Query().Get("teamId") != scope.TeamID || r.URL.Query().Get("decrypt") == "true" {
					t.Error("private API credential/scope mismatch")
					w.WriteHeader(403)
					return
				}
				switch {
				case r.Method == "GET" && r.URL.Path == "/v9/projects/"+scope.ProjectID:
					_ = json.NewEncoder(w).Encode(map[string]any{"id": scope.ProjectID, "accountId": scope.TeamID, "name": "fixture", "untrustedEcho": privateFixture})
				case r.Method == "GET" && r.URL.Path == "/v10/projects/"+scope.ProjectID+"/env":
					envs := []any{}
					if written {
						envs = append(envs, entry())
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"envs": envs})
				case r.Method == "POST" && r.URL.Path == "/v10/projects/"+scope.ProjectID+"/env":
					var body struct {
						Key, Value, Type, GitBranch string
						Target                      []string
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Key != "API_SECRET" || body.Value != privateFixture || body.Type != "sensitive" || body.GitBranch != scope.GitBranch || len(body.Target) != 1 || body.Target[0] != environment {
						t.Error("wrong scoped private write")
						w.WriteHeader(400)
						return
					}
					writes++
					written = true
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(map[string]any{"created": entry(), "failed": []any{}})
				case r.Method == "GET" && r.URL.Path == "/v9/projects/"+scope.ProjectID+"/domains":
					_ = json.NewEncoder(w).Encode(map[string]any{"domains": []any{map[string]any{"name": "fixture.example.com", "projectId": scope.ProjectID, "verified": true}}, "pagination": map[string]any{"next": nil}})
				case r.Method == "GET" && r.URL.Path == "/v4/aliases/fixture.example.com":
					_ = json.NewEncoder(w).Encode(map[string]any{"alias": "fixture.example.com", "projectId": scope.ProjectID, "deploymentId": current})
				case r.Method == "POST" && r.URL.Path == "/v10/projects/"+scope.ProjectID+"/promote/dpl_new":
					promotes++
					current = "dpl_new"
					_ = json.NewEncoder(w).Encode(map[string]any{})
				case r.Method == "POST" && r.URL.Path == "/v9/projects/"+scope.ProjectID+"/rollback/dpl_source":
					rollbacks++
					current = "dpl_source"
					_ = json.NewEncoder(w).Encode(map[string]any{})
				case r.Method == "GET" && r.URL.Path == "/v7/deployments":
					list := []any{}
					if creates > 0 {
						list = append(list, map[string]any{"uid": "dpl_new", "projectId": scope.ProjectID, "meta": map[string]string{vercel.MetaOperationKey: marker, vercel.MetaScopeKey: scope.Fingerprint()}})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"deployments": list, "pagination": map[string]any{"next": nil}})
				case r.Method == "POST" && r.URL.Path == "/v13/deployments":
					var body struct {
						Project, DeploymentID, Target             string
						WithLatestCommit, AutoAssignCustomDomains bool
						Meta                                      map[string]string
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Project != scope.ProjectID || body.DeploymentID != "dpl_source" || body.Target != map[string]string{"preview": "", "production": "production"}[environment] || body.WithLatestCommit || body.AutoAssignCustomDomains || body.Meta[vercel.MetaScopeKey] != scope.Fingerprint() {
						t.Error("deployment escaped approved source/scope")
						w.WriteHeader(400)
						return
					}
					marker = body.Meta[vercel.MetaOperationKey]
					creates++
					_ = json.NewEncoder(w).Encode(deployment("dpl_new"))
				case r.Method == "GET" && (r.URL.Path == "/v13/deployments/dpl_source" || r.URL.Path == "/v13/deployments/dpl_new"):
					_ = json.NewEncoder(w).Encode(deployment(strings.TrimPrefix(r.URL.Path, "/v13/deployments/")))
				default:
					t.Errorf("unexpected API route %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			adapter, e := vercel.New([]byte("fake-api-credential"), scope, vercel.Options{Endpoint: server.URL, Client: server.Client(), Now: b.Now})
			if e != nil {
				t.Fatal(e)
			}
			defer adapter.Close()
			b.Adapter = adapter
			r, e := b.Call(context.Background(), "envbank_setup_plan", mcpserver.Request{})
			if e != nil {
				t.Fatal(e)
			}
			s.policy.ID = PolicyID(r.PlanID)
			s.policy.DeploymentPlanID = r.PlanID
			if e = s.policy.Sign(private); e != nil {
				t.Fatal(e)
			}
			r = runTo(t, b, r.PlanID, "complete")
			if environment == "production" {
				r, e = b.Rollback(context.Background(), r.OperationID)
				if e != nil || r.Stage != "rolled-back" || r.VariableState != "applied-not-reverted" {
					t.Fatalf("rollback: %s %v", r.BlockerCode, e)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if writes != 1 || creates != 1 || environment == "production" && (promotes != 1 || rollbacks != 1) || environment == "preview" && (promotes != 0 || rollbacks != 0) {
				t.Fatal("wrong number of API mutations")
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), privateFixture) || strings.Contains(string(raw), "fake-api-credential") {
				t.Fatal("private HTTP response data escaped receipt")
			}
			raw, _ = json.Marshal(s.states)
			if strings.Contains(string(raw), privateFixture) {
				t.Fatal("private HTTP response data escaped journal")
			}
		})
	}
}
