package vercel

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	createPath  = "/v13/deployments"
	listPath    = "/v7/deployments"
	domainsPath = projectPath + "/domains"
	operationID = "op_20261103_0001"
)

func deploymentPath(id string) string { return "/v13/deployments/" + id }
func aliasPath(name string) string    { return "/v4/aliases/" + name }

// forScope shapes a deployment fixture so it belongs to scope.
func forScope(scope Scope, mutate ...func(map[string]any)) func(map[string]any) {
	return func(value map[string]any) {
		switch scope.Environment {
		case EnvironmentProduction:
			production(value)
		case EnvironmentCustom:
			value["customEnvironment"] = map[string]any{"id": scope.CustomEnvironmentID, "slug": "staging"}
			value["target"] = "staging"
		}
		for _, change := range mutate {
			change(value)
		}
	}
}

func withMarkers(operation string, scope Scope) func(map[string]any) {
	return func(value map[string]any) {
		meta := value["meta"].(map[string]any)
		meta[MetaOperationKey] = operation
		meta[MetaScopeKey] = scope.Fingerprint()
	}
}

func set(key string, field any) func(map[string]any) {
	return func(value map[string]any) { value[key] = field }
}

func TestDeploymentReadProvesOwnershipScopeAndIdentity(t *testing.T) {
	fake := newFake(t)
	scope := previewScope()
	fake.json(http.MethodGet, deploymentPath("dpl_ok"), 200, deployment("dpl_ok", nil))
	adapter := fake.adapter(t, scope)
	got, err := adapter.Deployment(background, "dpl_ok")
	if err != nil {
		t.Fatal(err)
	}
	if got != (Deployment{ID: "dpl_ok", ProjectID: testProject, TeamID: testTeam, Environment: EnvironmentPreview,
		GitBranch: testBranch, URL: "siftcut-abc.vercel.app", ReadyState: "READY"}) {
		t.Fatalf("unexpected deployment %+v", got)
	}
	assertNoCanary(t, got)
	if fake.last(http.MethodGet, deploymentPath("dpl_ok")).Query.Get("withGitRepoInfo") != "true" {
		t.Fatal("deployment read did not request git source metadata")
	}

	otherScope := previewScope()
	otherScope.GitBranch = "feature/y"
	cases := map[string]struct {
		body string
		code string
	}{
		"foreign owner":   {deployment("dpl_a", set("ownerId", "team_other1")), codeScopeMismatch},
		"foreign team":    {deployment("dpl_a", set("team", map[string]any{"id": "team_other1"})), codeScopeMismatch},
		"foreign project": {deployment("dpl_a", set("projectId", "prj_other1")), codeScopeMismatch},
		"production":      {deployment("dpl_a", production), codeScopeMismatch},
		"custom":          {deployment("dpl_a", forScope(customScope())), codeScopeMismatch},
		"other branch": {deployment("dpl_a", func(value map[string]any) {
			value["gitSource"] = map[string]any{"ref": "feature/y", "sha": testSHA}
			value["meta"] = map[string]any{"githubCommitRef": "feature/y"}
		}), codeScopeMismatch},
		"branch disagreement": {deployment("dpl_a", set("gitSource", map[string]any{"ref": "feature/y", "sha": testSHA})),
			"DEPLOYMENT_METADATA_INVALID"},
		"forged id":        {deployment("dpl_forged", nil), "DEPLOYMENT_ID_MISMATCH"},
		"unknown target":   {deployment("dpl_a", set("target", "staging")), "DEPLOYMENT_METADATA_INVALID"},
		"unknown state":    {deployment("dpl_a", set("readyState", "WEIRD")), "DEPLOYMENT_METADATA_INVALID"},
		"bad url":          {deployment("dpl_a", set("url", "https://evil/"+canary)), "DEPLOYMENT_METADATA_INVALID"},
		"other scope mark": {deployment("dpl_a", withMarkers(operationID, otherScope)), codeScopeMismatch},
		"non-string mark":  {deployment("dpl_a", func(value map[string]any) { value["meta"].(map[string]any)[MetaOperationKey] = 7 }), "DEPLOYMENT_METADATA_INVALID"},
	}
	for name, testCase := range cases {
		fake.json(http.MethodGet, deploymentPath("dpl_a"), 200, testCase.body)
		_, err := adapter.Deployment(background, "dpl_a")
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		expectCode(t, err, testCase.code)
	}
	before := fake.total()
	_, err = adapter.Deployment(background, "../dpl_a")
	expectCode(t, err, "INVALID_DEPLOYMENT_ID")
	if fake.total() != before {
		t.Fatal("invalid ID reached the provider")
	}
}

const emptyList = `{"deployments":[],"pagination":{"count":0,"next":null,"prev":null}}`

// redeployFake wires a successful redeploy for scope. created customises the
// create response and fresh the follow-up read.
func redeployFake(t *testing.T, scope Scope, created, fresh []func(map[string]any)) *fakeVercel {
	t.Helper()
	fake := newFake(t)
	fake.project("")
	fake.json(http.MethodGet, deploymentPath("dpl_src"), 200, deployment("dpl_src", forScope(scope)))
	fake.json(http.MethodGet, listPath, 200, emptyList)
	createdChanges := append([]func(map[string]any){withMarkers(operationID, scope),
		set("readyState", "QUEUED"), set("readySubstate", "")}, created...)
	freshChanges := append([]func(map[string]any){withMarkers(operationID, scope),
		set("readyState", "BUILDING"), set("readySubstate", "")}, fresh...)
	fake.json(http.MethodPost, createPath, 200, deployment("dpl_new", forScope(scope, createdChanges...)))
	fake.json(http.MethodGet, deploymentPath("dpl_new"), 200, deployment("dpl_new", forScope(scope, freshChanges...)))
	return fake
}

func TestRedeployPinsSourceCommitEnvironmentAndMarkers(t *testing.T) {
	for name, scope := range map[string]Scope{"preview": previewScope(), "production": productionScope(), "custom": customScope()} {
		t.Run(name, func(t *testing.T) {
			fake := redeployFake(t, scope, nil, nil)
			adapter := fake.adapter(t, scope)
			got, err := adapter.Redeploy(background, "dpl_src", operationID)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != "dpl_new" || got.Environment != scope.Environment || got.ReadyState != "BUILDING" {
				t.Fatalf("unexpected deployment %+v", got)
			}
			call := fake.last(http.MethodPost, createPath)
			if call.Query.Get("forceNew") != "1" || call.Query.Get("teamId") != testTeam || fake.mutations() != 1 {
				t.Fatalf("unexpected create query %v", call.Query)
			}
			var body map[string]any
			if err := json.Unmarshal(call.Body, &body); err != nil {
				t.Fatal(err)
			}
			meta, _ := body["meta"].(map[string]any)
			if body["deploymentId"] != "dpl_src" || body["withLatestCommit"] != false ||
				body["autoAssignCustomDomains"] != false || body["name"] != "siftcut-web" || body["project"] != testProject ||
				meta[MetaOperationKey] != operationID || meta[MetaScopeKey] != scope.Fingerprint() || len(meta) != 2 {
				t.Fatalf("unsafe create body: %s", call.Body)
			}
			switch scope.Environment {
			case EnvironmentPreview:
				if _, has := body["target"]; has || body["customEnvironmentSlugOrId"] != nil {
					t.Fatal("preview redeploy set a target")
				}
			case EnvironmentProduction:
				if body["target"] != "production" || body["customEnvironmentSlugOrId"] != nil {
					t.Fatal("production redeploy target not exact")
				}
			case EnvironmentCustom:
				if _, has := body["target"]; has || body["customEnvironmentSlugOrId"] != testCustom {
					t.Fatal("custom redeploy environment not exact")
				}
			}
		})
	}
}

func TestRedeployRefusesCrossScopeSourcesAndReusedOperations(t *testing.T) {
	scope := previewScope()
	t.Run("invalid inputs", func(t *testing.T) {
		fake := redeployFake(t, scope, nil, nil)
		adapter := fake.adapter(t, scope)
		for _, pair := range [][2]string{{"dpl_src", "short"}, {"dpl_src", "op with space"}, {"prj_abc", operationID}} {
			_, err := adapter.Redeploy(background, pair[0], pair[1])
			expectCode(t, err, "INVALID_REDEPLOY")
		}
		if fake.total() != 0 {
			t.Fatal("invalid redeploy reached provider")
		}
	})
	sources := map[string]struct {
		body string
		code string
	}{
		"other branch source": {deployment("dpl_src", func(value map[string]any) {
			value["gitSource"] = map[string]any{"ref": "main", "sha": testSHA}
			value["meta"] = map[string]any{"githubCommitRef": "main"}
		}), codeScopeMismatch},
		"production source": {deployment("dpl_src", production), codeScopeMismatch},
		"foreign source":    {deployment("dpl_src", set("ownerId", "team_other1")), codeScopeMismatch},
		"unready source":    {deployment("dpl_src", set("readyState", "ERROR")), "SOURCE_NOT_READY"},
	}
	for name, testCase := range sources {
		t.Run(name, func(t *testing.T) {
			fake := redeployFake(t, scope, nil, nil)
			fake.json(http.MethodGet, deploymentPath("dpl_src"), 200, testCase.body)
			adapter := fake.adapter(t, scope)
			_, err := adapter.Redeploy(background, "dpl_src", operationID)
			expectCode(t, err, testCase.code)
			if fake.mutations() != 0 {
				t.Fatal("cross-scope redeploy created a deployment")
			}
		})
	}
	t.Run("reused operation", func(t *testing.T) {
		fake := redeployFake(t, scope, nil, nil)
		fake.json(http.MethodGet, listPath, 200, `{"deployments":[{"uid":"dpl_prev","projectId":"`+testProject+
			`","meta":{"`+MetaOperationKey+`":"`+operationID+`"}}],"pagination":{"next":null}}`)
		fake.json(http.MethodGet, deploymentPath("dpl_prev"), 200, deployment("dpl_prev", withMarkers(operationID, scope)))
		adapter := fake.adapter(t, scope)
		_, err := adapter.Redeploy(background, "dpl_src", operationID)
		expectCode(t, err, "OPERATION_ALREADY_EXISTS")
		if fake.mutations() != 0 {
			t.Fatal("reused operation created a deployment")
		}
	})
	t.Run("incomplete reconciliation search", func(t *testing.T) {
		fake := redeployFake(t, scope, nil, nil)
		var page atomic.Int64
		fake.handle(http.MethodGet, listPath, func(response http.ResponseWriter, _ *http.Request) {
			next := 1800000000000 - page.Add(1)
			_, _ = response.Write([]byte(`{"deployments":[],"pagination":{"next":` + strconv.FormatInt(next, 10) + `}}`))
		})
		adapter := fake.adapter(t, scope)
		_, err := adapter.Redeploy(background, "dpl_src", operationID)
		expectCode(t, err, "SEARCH_INCOMPLETE")
		if fake.mutations() != 0 || fake.count(http.MethodGet, listPath) != findMaxPages {
			t.Fatal("incomplete search was not bounded and fail-closed")
		}
	})
}

func TestRedeployDetectsDriftAndAmbiguityWithoutRetrying(t *testing.T) {
	cases := map[string]struct {
		scope   Scope
		created []func(map[string]any)
		fresh   []func(map[string]any)
		create  *struct {
			status int
			body   string
		}
		freshStatus int
		code        string
		retry       provider.RetryClass
	}{
		"preview created as production": {scope: previewScope(), created: []func(map[string]any){production},
			code: codeCreatedMismatch, retry: provider.RetryNever},
		"marker replaced": {scope: previewScope(), created: []func(map[string]any){withMarkers("op_other_000001", previewScope())},
			code: codeCreatedMismatch, retry: provider.RetryNever},
		"fresh commit drift": {scope: previewScope(), fresh: []func(map[string]any){func(value map[string]any) {
			value["gitSource"] = map[string]any{"ref": testBranch, "sha": "fff0000aaa"}
			value["meta"].(map[string]any)["githubCommitSha"] = "fff0000aaa"
		}}, code: "SOURCE_COMMIT_DRIFT", retry: provider.RetryNever},
		"fresh commit missing": {scope: previewScope(), fresh: []func(map[string]any){func(value map[string]any) {
			delete(value, "gitSource")
			delete(value["meta"].(map[string]any), "githubCommitSha")
		}}, code: "SOURCE_COMMIT_UNVERIFIED", retry: provider.RetryNever},
		"production auto-promoted": {scope: productionScope(), fresh: []func(map[string]any){set("readySubstate", "PROMOTED")},
			code: "UNEXPECTED_PROMOTION", retry: provider.RetryNever},
		"fresh foreign": {scope: previewScope(), fresh: []func(map[string]any){set("projectId", "prj_other1")},
			code: codeCreatedMismatch, retry: provider.RetryNever},
		"server error": {scope: previewScope(), create: &struct {
			status int
			body   string
		}{500, canary}, code: "SERVER_ERROR", retry: provider.RetryAmbiguous},
		"garbage success": {scope: previewScope(), create: &struct {
			status int
			body   string
		}{200, canary}, code: "UNCONFIRMED_DEPLOYMENT", retry: provider.RetryAmbiguous},
		"forged created id": {scope: previewScope(), create: &struct {
			status int
			body   string
		}{200, `{"id":"../x"}`}, code: "UNCONFIRMED_DEPLOYMENT", retry: provider.RetryAmbiguous},
		"fresh read failure": {scope: previewScope(), freshStatus: 500, code: "CREATED_UNVERIFIED", retry: provider.RetryAmbiguous},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fake := redeployFake(t, testCase.scope, testCase.created, testCase.fresh)
			if testCase.create != nil {
				fake.json(http.MethodPost, createPath, testCase.create.status, testCase.create.body)
			}
			if testCase.freshStatus != 0 {
				fake.json(http.MethodGet, deploymentPath("dpl_new"), testCase.freshStatus, canary)
			}
			adapter := fake.adapter(t, testCase.scope)
			_, err := adapter.Redeploy(background, "dpl_src", operationID)
			if safe := expectCode(t, err, testCase.code); safe.Retry != testCase.retry {
				t.Fatalf("retry %s, want %s", safe.Retry, testCase.retry)
			}
			if fake.count(http.MethodPost, createPath) != 1 {
				t.Fatal("deployment create was retried")
			}
		})
	}
}

const promotePrefix = "/v10/projects/" + testProject + "/promote/"
const rollbackPrefix = "/v9/projects/" + testProject + "/rollback/"

func productionFake(t *testing.T, projectExtra string) *fakeVercel {
	t.Helper()
	fake := newFake(t)
	fake.project(projectExtra)
	fake.json(http.MethodGet, deploymentPath("dpl_staged"), 200, deployment("dpl_staged", production))
	fake.json(http.MethodGet, deploymentPath("dpl_current"), 200, deployment("dpl_current", forScope(productionScope(), set("readySubstate", "PROMOTED"))))
	fake.json(http.MethodGet, deploymentPath("dpl_prior"), 200, deployment("dpl_prior", forScope(productionScope(), set("readySubstate", "PROMOTED"))))
	fake.json(http.MethodGet, deploymentPath("dpl_building"), 200, deployment("dpl_building", forScope(productionScope(), set("readyState", "BUILDING"))))
	fake.json(http.MethodGet, deploymentPath("dpl_preview"), 200, deployment("dpl_preview", nil))
	fake.json(http.MethodGet, deploymentPath("dpl_foreign"), 200, deployment("dpl_foreign", forScope(productionScope(), set("ownerId", "team_other1"))))
	fake.json(http.MethodGet, domainsPath, 200, `{"domains":[`+
		`{"name":"siftcut.com","apexName":"siftcut.com","projectId":"`+testProject+`","verified":true},`+
		`{"name":"siftcut-web.vercel.app","apexName":"vercel.app","projectId":"`+testProject+`","verified":true},`+
		`{"name":"dev.siftcut.com","apexName":"siftcut.com","projectId":"`+testProject+`","gitBranch":"dev","verified":true},`+
		`{"name":"old.siftcut.com","apexName":"siftcut.com","projectId":"`+testProject+`","redirect":"siftcut.com","verified":true},`+
		`{"name":"pending.siftcut.com","apexName":"siftcut.com","projectId":"`+testProject+`","verified":false}`+
		`],"pagination":{"count":5,"next":null,"prev":null}}`)
	for _, name := range []string{"siftcut.com", "siftcut-web.vercel.app"} {
		fake.json(http.MethodGet, aliasPath(name), 200, `{"alias":"`+name+`","uid":"a1","created":"x","projectId":"`+
			testProject+`","deploymentId":"dpl_current","deployment":{"id":"dpl_current","url":"x","meta":"`+canary+`"}}`)
	}
	fake.json(http.MethodPost, promotePrefix+"dpl_staged", http.StatusCreated, "")
	fake.json(http.MethodPost, rollbackPrefix+"dpl_prior", http.StatusCreated, "")
	return fake
}

func TestPromoteOnlyDirectlyPromotesStagedReadyProduction(t *testing.T) {
	previewFake := productionFake(t, "")
	err := previewFake.adapter(t, previewScope()).Promote(background, "dpl_staged")
	expectCode(t, err, "SCOPE_NOT_PRODUCTION")
	err = previewFake.adapter(t, customScope()).Promote(background, "dpl_staged")
	expectCode(t, err, "SCOPE_NOT_PRODUCTION")
	if previewFake.total() != 0 {
		t.Fatal("non-production promote reached the provider")
	}

	fake := productionFake(t, "")
	adapter := fake.adapter(t, productionScope())
	if err := adapter.Promote(background, "dpl_staged"); err != nil {
		t.Fatal(err)
	}
	call := fake.last(http.MethodPost, promotePrefix+"dpl_staged")
	if string(call.Body) != "{}" || call.Query.Get("teamId") != testTeam {
		t.Fatalf("unexpected promote request %s %v", call.Body, call.Query)
	}
	for id, code := range map[string]string{"dpl_current": "NOT_STAGED_READY_PRODUCTION",
		"dpl_building": "NOT_STAGED_READY_PRODUCTION", "dpl_preview": codeScopeMismatch,
		"dpl_foreign": codeScopeMismatch, "dpl_missing": "NOT_FOUND"} {
		expectCode(t, adapter.Promote(background, id), code)
	}
	if fake.mutations() != 1 {
		t.Fatal("refused promotions mutated")
	}

	fake.json(http.MethodPost, promotePrefix+"dpl_staged", http.StatusAccepted, "")
	if err := adapter.Promote(background, "dpl_staged"); err != nil {
		t.Fatalf("queued promote rejected: %v", err)
	}
	fake.json(http.MethodPost, promotePrefix+"dpl_staged", http.StatusBadGateway, canary)
	if safe := expectCode(t, adapter.Promote(background, "dpl_staged"), "SERVER_ERROR"); safe.Retry != provider.RetryAmbiguous {
		t.Fatal("failed promote was not ambiguous")
	}

	busy := productionFake(t, `,"lastAliasRequest":{"type":"promote","jobStatus":"in-progress","toDeploymentId":"dpl_x","fromDeploymentId":null,"requestedAt":1}`)
	expectCode(t, busy.adapter(t, productionScope()).Promote(background, "dpl_staged"), "ALIAS_JOB_IN_PROGRESS")
	if busy.mutations() != 0 {
		t.Fatal("promote raced an in-flight alias job")
	}
}

func TestRollbackOnlyTargetsPriorProductionThatIsNotLive(t *testing.T) {
	fake := productionFake(t, "")
	adapter := fake.adapter(t, productionScope())
	if err := adapter.Rollback(background, "dpl_prior"); err != nil {
		t.Fatal(err)
	}
	if call := fake.last(http.MethodPost, rollbackPrefix+"dpl_prior"); string(call.Body) != "{}" {
		t.Fatalf("unexpected rollback body %s", call.Body)
	}
	for id, code := range map[string]string{"dpl_current": "ALREADY_CURRENT", "dpl_staged": "NOT_PRIOR_PRODUCTION",
		"dpl_building": "NOT_PRIOR_PRODUCTION", "dpl_preview": codeScopeMismatch, "dpl_foreign": codeScopeMismatch} {
		expectCode(t, adapter.Rollback(background, id), code)
	}
	if fake.mutations() != 1 {
		t.Fatal("refused rollbacks mutated")
	}
	if fake.count(http.MethodGet, aliasPath("dev.siftcut.com")) != 0 || fake.count(http.MethodGet, aliasPath("old.siftcut.com")) != 0 {
		t.Fatal("branch or redirect domains were treated as production aliases")
	}
	preview := productionFake(t, "")
	expectCode(t, preview.adapter(t, previewScope()).Rollback(background, "dpl_prior"), "SCOPE_NOT_PRODUCTION")
	if preview.total() != 0 {
		t.Fatal("preview rollback reached the provider")
	}
}

func TestCurrentDeploymentRequiresConsistentProductionAliases(t *testing.T) {
	fake := productionFake(t, `,"lastAliasRequest":{"type":"rollback","jobStatus":"succeeded","toDeploymentId":"dpl_prior","fromDeploymentId":"dpl_x","requestedAt":1}`)
	adapter := fake.adapter(t, productionScope())
	current, err := adapter.CurrentDeployment(background)
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != "dpl_current" || current.Environment != EnvironmentProduction {
		t.Fatalf("unexpected current deployment %+v", current)
	}
	assertNoCanary(t, current)
	query := fake.last(http.MethodGet, domainsPath).Query
	if query.Get("production") != "true" || query.Get("redirects") != "false" {
		t.Fatalf("unexpected domain query %v", query)
	}
	if fake.last(http.MethodGet, aliasPath("siftcut.com")).Query.Get("projectId") != testProject {
		t.Fatal("alias lookup was not bound to the project")
	}
	expectCodeCurrent := func(fake *fakeVercel, code string) {
		t.Helper()
		_, err := fake.adapter(t, productionScope()).CurrentDeployment(background)
		expectCode(t, err, code)
	}

	_, err = productionFake(t, "").adapter(t, previewScope()).CurrentDeployment(background)
	expectCode(t, err, "SCOPE_NOT_PRODUCTION")

	split := productionFake(t, "")
	split.json(http.MethodGet, aliasPath("siftcut-web.vercel.app"), 200, `{"alias":"siftcut-web.vercel.app","projectId":"`+
		testProject+`","deploymentId":"dpl_prior"}`)
	expectCodeCurrent(split, "PRODUCTION_ALIAS_SPLIT")

	foreignAlias := productionFake(t, "")
	foreignAlias.json(http.MethodGet, aliasPath("siftcut.com"), 200, `{"alias":"siftcut.com","projectId":"prj_other1","deploymentId":"dpl_current"}`)
	expectCodeCurrent(foreignAlias, "PRODUCTION_ALIAS_UNVERIFIED")

	mismatchedAlias := productionFake(t, "")
	mismatchedAlias.json(http.MethodGet, aliasPath("siftcut.com"), 200, `{"alias":"siftcut.com","projectId":"`+testProject+
		`","deploymentId":"dpl_current","deployment":{"id":"dpl_prior"}}`)
	expectCodeCurrent(mismatchedAlias, "PRODUCTION_ALIAS_UNVERIFIED")

	noDomains := productionFake(t, "")
	noDomains.json(http.MethodGet, domainsPath, 200, `{"domains":[],"pagination":{"next":null}}`)
	expectCodeCurrent(noDomains, "NO_PRODUCTION_DOMAIN")

	paged := productionFake(t, "")
	paged.json(http.MethodGet, domainsPath, 200, `{"domains":[],"pagination":{"next":1700000000000}}`)
	expectCodeCurrent(paged, "DOMAIN_LIST_INCOMPLETE")

	rolling := productionFake(t, "")
	rolling.json(http.MethodGet, deploymentPath("dpl_current"), 200, deployment("dpl_current", forScope(productionScope(), set("readySubstate", "ROLLING"))))
	expectCodeCurrent(rolling, "ROLLING_RELEASE_ACTIVE")

	staged := productionFake(t, "")
	staged.json(http.MethodGet, deploymentPath("dpl_current"), 200, deployment("dpl_current", production))
	expectCodeCurrent(staged, "CURRENT_DEPLOYMENT_UNVERIFIED")

	foreignDeployment := productionFake(t, "")
	foreignDeployment.json(http.MethodGet, deploymentPath("dpl_current"), 200, deployment("dpl_current", forScope(productionScope(), set("projectId", "prj_other1"))))
	expectCodeCurrent(foreignDeployment, codeScopeMismatch)

	pending := productionFake(t, `,"lastAliasRequest":{"type":"promote","jobStatus":"pending","toDeploymentId":"dpl_x","fromDeploymentId":null,"requestedAt":1}`)
	expectCodeCurrent(pending, "ALIAS_JOB_IN_PROGRESS")
}

func TestFindDeploymentReconcilesExactlyOneScopedOperation(t *testing.T) {
	scope := previewScope()
	item := func(id, marker string) string {
		return `{"uid":"` + id + `","projectId":"` + testProject + `","meta":{"` + MetaOperationKey + `":"` + marker + `"}}`
	}
	pages := func(fake *fakeVercel, first, second string) {
		fake.handle(http.MethodGet, listPath, func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Query().Get("until") == "" {
				_, _ = response.Write([]byte(`{"deployments":[` + first + `],"pagination":{"next":1700000000000}}`))
				return
			}
			_, _ = response.Write([]byte(`{"deployments":[` + second + `],"pagination":{"next":null}}`))
		})
	}

	fake := newFake(t)
	fake.project("")
	pages(fake, item("dpl_other", "op_other_000001")+","+item("dpl_mine", operationID), item("dpl_old", "op_old_0000001"))
	fake.json(http.MethodGet, deploymentPath("dpl_mine"), 200, deployment("dpl_mine", withMarkers(operationID, scope)))
	adapter := fake.adapter(t, scope)
	found, err := adapter.FindDeployment(background, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != "dpl_mine" {
		t.Fatalf("unexpected deployment %+v", found)
	}
	query := fake.last(http.MethodGet, listPath).Query
	since := strconv.FormatInt(fixedNow.Add(-14*24*time.Hour).UnixMilli(), 10)
	if query.Get("projectId") != testProject || query.Get("since") != since || query.Get("until") != "1700000000000" {
		t.Fatalf("unexpected list query %v", query)
	}

	duplicate := newFake(t)
	duplicate.project("")
	pages(duplicate, item("dpl_mine", operationID), item("dpl_twin", operationID))
	_, err = duplicate.adapter(t, scope).FindDeployment(background, operationID)
	expectCode(t, err, "DUPLICATE_OPERATION")

	otherScope := previewScope()
	otherScope.GitBranch = "feature/y"
	for name, body := range map[string]string{
		"other scope marker": deployment("dpl_mine", withMarkers(operationID, otherScope)),
		"other branch": deployment("dpl_mine", func(value map[string]any) {
			withMarkers(operationID, scope)(value)
			value["gitSource"] = map[string]any{"ref": "feature/y", "sha": testSHA}
			value["meta"].(map[string]any)["githubCommitRef"] = "feature/y"
		}),
		"missing scope marker": deployment("dpl_mine", func(value map[string]any) {
			value["meta"].(map[string]any)[MetaOperationKey] = operationID
		}),
	} {
		crossed := newFake(t)
		crossed.project("")
		pages(crossed, item("dpl_mine", operationID), "")
		crossed.json(http.MethodGet, deploymentPath("dpl_mine"), 200, body)
		_, err := crossed.adapter(t, scope).FindDeployment(background, operationID)
		if err == nil {
			t.Fatalf("%s: crossed-scope deployment accepted", name)
		}
		expectCode(t, err, codeOperationScope)
	}

	foreignItem := newFake(t)
	foreignItem.project("")
	pages(foreignItem, `{"uid":"dpl_mine","projectId":"prj_other1","meta":{"`+MetaOperationKey+`":"`+operationID+`"}}`, "")
	_, err = foreignItem.adapter(t, scope).FindDeployment(background, operationID)
	expectCode(t, err, codeOperationScope)

	none := newFake(t)
	none.project("")
	pages(none, item("dpl_other", "op_other_000001"), "")
	_, err = none.adapter(t, scope).FindDeployment(background, operationID)
	if safe := expectCode(t, err, codeNotFound); safe.Retry != provider.RetrySafe {
		t.Fatal("not-found should be a safe read retry")
	}
}
