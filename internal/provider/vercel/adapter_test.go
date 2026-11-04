package vercel

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

func TestIdentityAndBindRequireExactTeamOwnership(t *testing.T) {
	fake := newFake(t)
	fake.project("")
	adapter := fake.adapter(t, previewScope())
	identity, err := adapter.Identity(background)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != ProviderName || identity.ID != testTeam+":"+testProject {
		t.Fatalf("unexpected identity %+v", identity)
	}
	target, err := adapter.Bind(background)
	if err != nil {
		t.Fatal(err)
	}
	if !previewScope().matchesTarget(target) {
		t.Fatalf("bind returned a foreign target %+v", target)
	}
	assertNoCanary(t, identity, target)

	for name, body := range map[string]string{
		"foreign team":    projectBody("team_other1", ""),
		"personal owner":  projectBody("user123", ""),
		"foreign project": strings.Replace(projectBody(testTeam, ""), `"id":"`+testProject, `"id":"prj_other1`, 1),
		"invalid name":    strings.Replace(projectBody(testTeam, ""), "siftcut-web", "Bad Name", 1),
	} {
		fake.json(http.MethodGet, projectPath, http.StatusOK, body)
		_, err := adapter.Identity(background)
		code := "PROJECT_OWNERSHIP_MISMATCH"
		if name == "invalid name" {
			code = "PROJECT_METADATA_INVALID"
		}
		expectCode(t, err, code)
		_, err = adapter.Bind(background)
		expectCode(t, err, code)
	}
}

func TestCustomScopeRequiresExactPreviewCustomEnvironment(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, customScope())
	cases := map[string]string{
		"missing":     `{"id":"` + testProject + `","name":"siftcut-web","accountId":"` + testTeam + `"}`,
		"other id":    strings.Replace(projectBody(testTeam, ""), testCustom, "env_other1", 1),
		"duplicate":   strings.Replace(projectBody(testTeam, ""), `"customEnvironments":[`, `"customEnvironments":[{"id":"`+testCustom+`","type":"preview"},`, 1),
		"development": strings.Replace(projectBody(testTeam, ""), `"type":"preview"`, `"type":"development"`, 1),
	}
	for name, body := range cases {
		fake.json(http.MethodGet, projectPath, http.StatusOK, body)
		_, err := adapter.Bind(background)
		code := "CUSTOM_ENVIRONMENT_UNVERIFIED"
		if name == "development" {
			code = "CUSTOM_ENVIRONMENT_TYPE"
		}
		expectCode(t, err, code)
	}
	fake.project("")
	if _, err := adapter.Bind(background); err != nil {
		t.Fatal(err)
	}
}

func TestInspectReportsNamesOnlyMetadataAndFlagsAmbiguity(t *testing.T) {
	fake := newFake(t)
	fake.project("")
	fake.envs(
		env("e1", "PRESENT", "sensitive", `["preview"]`, testBranch, ""),
		env("e2", "MULTI", "sensitive", `["preview","production"]`, "", ""),
		env("e3", "DUP", "sensitive", `["preview"]`, testBranch, ""),
		env("e4", "DUP", "sensitive", `["preview"]`, testBranch, ""),
		env("e5", "OTHER_BRANCH", "sensitive", `["preview"]`, "feature/y", ""),
		env("e6", "ALL_PREVIEW", "sensitive", `["preview"]`, "", ""),
		env("e7", "READABLE", "encrypted", `["preview"]`, testBranch, ""),
		env("e8", "PROD_ONLY", "sensitive", `["production"]`, "", ""),
		env("e9", "Mixed_Case", "sensitive", `["preview"]`, testBranch, ""),
		env("e10", "MIXED_CASE", "sensitive", `["preview"]`, testBranch, ""),
		env("e11", "UNKNOWN_TARGET", "sensitive", `["beta"]`, "", ""),
		env("e12", "STRING_TARGET", "sensitive", `"preview"`, testBranch, ""),
		env("e13", "PREVIEW_AND_CUSTOM", "sensitive", `["preview"]`, testBranch, `["`+testCustom+`"]`),
		env("e14", "bad key!", "sensitive", `["preview"]`, testBranch, ""),
		`{"id":"e15","key":"INTEGRATION","type":"sensitive","target":["preview"],"gitBranch":"`+testBranch+`","configurationId":"icfg_1","value":"`+canary+`"}`,
	)
	adapter := fake.adapter(t, previewScope())
	state, err := adapter.Inspect(background, previewScope().Target())
	if err != nil {
		t.Fatal(err)
	}
	assertNoCanary(t, state)
	if fake.last(http.MethodGet, envPath).Query.Get("decrypt") != "false" {
		t.Fatal("env listing did not explicitly request decrypt=false")
	}
	variables := state.Variables[ServiceName]
	expected := map[string]provider.Presence{
		"PRESENT": provider.PresencePresent, "MULTI": provider.PresenceUnknown, "DUP": provider.PresenceUnknown,
		"READABLE": provider.PresenceUnknown, "Mixed_Case": provider.PresenceUnknown,
		"MIXED_CASE": provider.PresenceUnknown, "UNKNOWN_TARGET": provider.PresenceUnknown,
		"STRING_TARGET": provider.PresencePresent, "PREVIEW_AND_CUSTOM": provider.PresenceUnknown,
		"INTEGRATION": provider.PresenceUnknown,
	}
	if len(variables) != len(expected) {
		t.Fatalf("unexpected variables: %+v", variables)
	}
	for name, presence := range expected {
		if variables[name].Presence != presence {
			t.Fatalf("%s: expected %s, got %s", name, presence, variables[name].Presence)
		}
	}
	if state.Revision == "" || !fingerprintPattern.MatchString(state.Revision) {
		t.Fatal("inspect did not provide a metadata revision")
	}

	// A different scope's target, even of the same project, is refused before any request.
	before := fake.total()
	otherBranch := previewScope()
	otherBranch.GitBranch = "feature/y"
	_, err = adapter.Inspect(background, otherBranch.Target())
	expectCode(t, err, "TARGET_SCOPE_MISMATCH")
	forged := previewScope().Target()
	forged.ServiceIDs["extra"] = "x"
	_, err = adapter.Inspect(background, forged)
	expectCode(t, err, "TARGET_SCOPE_MISMATCH")
	if fake.total() != before {
		t.Fatal("mismatched target triggered provider requests")
	}
}

func TestEnvironmentListingFailsClosed(t *testing.T) {
	cases := map[string]struct {
		body string
		code string
	}{
		"paginated":  {`{"envs":[],"pagination":{"count":0,"next":1700000000000,"prev":null}}`, "ENV_LIST_INCOMPLETE"},
		"hidden":     {`{"envs":[],"hiddenProductionEnvCount":2}`, "ENV_LIST_HIDDEN_ENTRIES"},
		"decrypted":  {`{"envs":[{"id":"e1","key":"A","type":"sensitive","target":["preview"],"decrypted":true,"value":"` + canary + `"}]}`, "UNEXPECTED_DECRYPTED_RESPONSE"},
		"single":     {`{"id":"e1","key":"A","type":"sensitive","value":"` + canary + `"}`, "ENV_LIST_INVALID"},
		"not json":   {canary, "INVALID_RESPONSE"},
		"bad target": {`{"envs":[{"id":"e1","key":"A","type":"sensitive","target":{"x":1}}]}`, "INVALID_RESPONSE"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFake(t)
			fake.project("")
			fake.json(http.MethodGet, envPath, http.StatusOK, testCase.body)
			adapter := fake.adapter(t, previewScope())
			_, err := adapter.Inspect(background, previewScope().Target())
			expectCode(t, err, testCase.code)
			// Write must fail closed on the same listing, before any mutation.
			request := provider.NewWriteRequest("upsert", previewScope().Target(), ServiceName,
				previewScope().Fingerprint(), "DATABASE_URL", "", []byte("v"))
			defer request.Destroy()
			_, err = adapter.Write(background, request)
			safe := expectCode(t, err, testCase.code)
			if safe.Retry == provider.RetryAmbiguous || fake.mutations() != 0 {
				t.Fatal("pre-write read failure was ambiguous or mutated")
			}
		})
	}
}

func upsertCreated(response http.ResponseWriter, request *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(response, "bad", http.StatusBadRequest)
		return
	}
	created := map[string]any{"id": "envNEW1", "key": body["key"], "type": body["type"],
		"target": body["target"], "gitBranch": body["gitBranch"], "customEnvironmentIds": body["customEnvironmentIds"],
		"value": canary, "decrypted": false}
	if created["target"] == nil {
		created["target"] = []string{}
	}
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(map[string]any{"created": created, "failed": []any{}})
}

func TestWriteSendsExactSensitiveScopedUpsert(t *testing.T) {
	secret := "line1\n\"quoted\"\\tab\t\x01 ünïcode " + strings.Repeat("x", 32)
	for name, scope := range map[string]Scope{"preview-branch": previewScope(), "production": productionScope(),
		"custom": customScope(), "all-preview": {TeamID: testTeam, ProjectID: testProject, Environment: EnvironmentPreview}} {
		t.Run(name, func(t *testing.T) {
			fake := newFake(t)
			fake.project("")
			fake.envs()
			fake.handle(http.MethodPost, envPath, upsertCreated)
			adapter := fake.adapter(t, scope)
			request := provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(),
				"DATABASE_URL", "", []byte(secret))
			defer request.Destroy()
			evidence, err := adapter.Write(background, request)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.ProviderOperationID != "envNEW1" || evidence.CommittedAt != "2026-11-03T12:00:00Z" ||
				evidence.Validate() != nil {
				t.Fatalf("unexpected evidence %+v", evidence)
			}
			assertNoCanary(t, evidence)
			call := fake.last(http.MethodPost, envPath)
			if call.Query.Get("upsert") != "true" || call.Query.Get("teamId") != testTeam || fake.count(http.MethodPost, envPath) != 1 {
				t.Fatalf("unexpected upsert query %v", call.Query)
			}
			var body map[string]any
			if err := json.Unmarshal(call.Body, &body); err != nil {
				t.Fatalf("body is not valid JSON: %v", err)
			}
			if body["value"] != secret || body["type"] != "sensitive" || body["key"] != "DATABASE_URL" {
				t.Fatalf("value or type was not sent exactly: %v", body["type"])
			}
			targets, _ := json.Marshal(body["target"])
			customs, _ := json.Marshal(body["customEnvironmentIds"])
			branch, hasBranch := body["gitBranch"]
			switch name {
			case "preview-branch":
				if string(targets) != `["preview"]` || branch != testBranch || body["customEnvironmentIds"] != nil {
					t.Fatalf("preview-branch scope not exact: %s %v", targets, branch)
				}
			case "all-preview":
				if string(targets) != `["preview"]` || hasBranch || body["customEnvironmentIds"] != nil {
					t.Fatalf("all-preview scope not exact")
				}
			case "production":
				if string(targets) != `["production"]` || hasBranch || body["customEnvironmentIds"] != nil {
					t.Fatalf("production scope not exact")
				}
			case "custom":
				if string(customs) != `["`+testCustom+`"]` || hasBranch || body["target"] != nil {
					t.Fatalf("custom scope not exact")
				}
			}
		})
	}
}

func TestWriteRefusesUnsafeRequestsWithoutMutating(t *testing.T) {
	scope := previewScope()
	otherBranch := previewScope()
	otherBranch.GitBranch = "feature/y"
	cases := map[string]struct {
		request provider.WriteRequest
		entries []string
		code    string
	}{
		"next public": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "NEXT_PUBLIC_KEY", "", []byte("v")), nil, "NAME_NOT_ALLOWED"},
		"vite":        {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "VITE_KEY", "", []byte("v")), nil, "NAME_NOT_ALLOWED"},
		"revoke":      {provider.NewWriteRequest("revoke", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", nil), nil, "INVALID_WRITE"},
		"other branch target": {provider.NewWriteRequest("upsert", otherBranch.Target(), ServiceName,
			otherBranch.Fingerprint(), "DATABASE_URL", "", []byte("v")), nil, "INVALID_WRITE"},
		"wrong service": {provider.NewWriteRequest("upsert", scope.Target(), "web", scope.Fingerprint(), "DATABASE_URL", "", []byte("v")), nil, "INVALID_WRITE"},
		"wrong service id": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, otherBranch.Fingerprint(),
			"DATABASE_URL", "", []byte("v")), nil, "INVALID_WRITE"},
		"invalid utf8": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", []byte{0xff, 0xfe}), nil, "VALUE_NOT_ALLOWED"},
		"empty value":  {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", nil), nil, "VALUE_NOT_ALLOWED"},
		"overlapping multi-target": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", []byte("v")),
			[]string{env("e1", "DATABASE_URL", "sensitive", `["preview","production"]`, "", "")}, "AMBIGUOUS_EXISTING_ENTRIES"},
		"duplicate exact": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", []byte("v")),
			[]string{env("e1", "DATABASE_URL", "sensitive", `["preview"]`, testBranch, ""), env("e2", "DATABASE_URL", "sensitive", `["preview"]`, testBranch, "")}, "AMBIGUOUS_EXISTING_ENTRIES"},
		"case collision": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", []byte("v")),
			[]string{env("e1", "database_url", "sensitive", `["preview"]`, testBranch, "")}, "AMBIGUOUS_EXISTING_ENTRIES"},
		"readable existing": {provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", []byte("v")),
			[]string{env("e1", "DATABASE_URL", "plain", `["preview"]`, testBranch, "")}, "AMBIGUOUS_EXISTING_ENTRIES"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFake(t)
			fake.project("")
			fake.envs(testCase.entries...)
			fake.handle(http.MethodPost, envPath, upsertCreated)
			adapter := fake.adapter(t, scope)
			request := testCase.request
			defer request.Destroy()
			_, err := adapter.Write(background, request)
			safe := expectCode(t, err, testCase.code)
			if safe.Retry != provider.RetryNever || fake.mutations() != 0 {
				t.Fatalf("refused write mutated or was retryable: %+v", safe)
			}
		})
	}
}

func TestWriteFailuresAreDefinitiveOrAmbiguousAndNeverRetried(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		code   string
		retry  provider.RetryClass
	}{
		"failed array": {201, `{"created":[],"failed":[{"error":{"code":"ENV_CONFLICT","message":"` + canary + `","value":"` + canary + `"}}]}`,
			"WRITE_REJECTED", provider.RetryNever},
		"mixed": {201, `{"created":{"id":"envNEW1","key":"DATABASE_URL","type":"sensitive","target":["preview"],"gitBranch":"` + testBranch + `"},"failed":[{"error":{"code":"x","message":"` + canary + `"}}]}`,
			"MIXED_WRITE_RESULT", provider.RetryAmbiguous},
		"server error":  {500, `{"error":{"message":"` + canary + `"}}`, "SERVER_ERROR", provider.RetryAmbiguous},
		"forbidden":     {403, `{"error":{"code":"forbidden","message":"` + canary + `"}}`, "FORBIDDEN", provider.RetryNever},
		"garbage 2xx":   {201, canary, "UNCONFIRMED_WRITE", provider.RetryAmbiguous},
		"empty created": {201, `{"failed":[]}`, "UNCONFIRMED_WRITE", provider.RetryAmbiguous},
		"rate limited":  {429, canary, "RATE_LIMITED", provider.RetrySafe},
		"wrong scope committed": {201, `{"created":{"id":"envNEW1","key":"DATABASE_URL","type":"sensitive","target":["preview","production"],"value":"` + canary + `"},"failed":[]}`,
			"WRITE_SCOPE_MISMATCH", provider.RetryNever},
		"readable committed": {201, `{"created":{"id":"envNEW1","key":"DATABASE_URL","type":"encrypted","target":["preview"],"gitBranch":"` + testBranch + `"},"failed":[]}`,
			"WRITE_SCOPE_MISMATCH", provider.RetryNever},
		"forged id": {201, `{"created":{"id":"../../x","key":"DATABASE_URL","type":"sensitive","target":["preview"],"gitBranch":"` + testBranch + `"},"failed":[]}`,
			"WRITE_SCOPE_MISMATCH", provider.RetryNever},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFake(t)
			fake.project("")
			fake.envs()
			fake.json(http.MethodPost, envPath, testCase.status, testCase.body)
			adapter := fake.adapter(t, previewScope())
			request := provider.NewWriteRequest("upsert", previewScope().Target(), ServiceName,
				previewScope().Fingerprint(), "DATABASE_URL", "", []byte("v"))
			defer request.Destroy()
			_, err := adapter.Write(background, request)
			safe := expectCode(t, err, testCase.code)
			if safe.Retry != testCase.retry {
				t.Fatalf("retry class %s, want %s", safe.Retry, testCase.retry)
			}
			if fake.count(http.MethodPost, envPath) != 1 {
				t.Fatal("write was retried")
			}
		})
	}
}

func TestWriteTransportDropIsAmbiguous(t *testing.T) {
	fake := newFake(t)
	fake.project("")
	fake.envs()
	fake.handle(http.MethodPost, envPath, func(response http.ResponseWriter, _ *http.Request) {
		connection, _, err := response.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.(*net.TCPConn).SetLinger(0)
			_ = connection.Close()
		}
	})
	adapter := fake.adapter(t, previewScope())
	request := provider.NewWriteRequest("upsert", previewScope().Target(), ServiceName,
		previewScope().Fingerprint(), "DATABASE_URL", "", []byte("v"))
	defer request.Destroy()
	_, err := adapter.Write(background, request)
	if safe := expectCode(t, err, "TRANSPORT"); safe.Retry != provider.RetryAmbiguous {
		t.Fatalf("transport failure was not ambiguous: %+v", safe)
	}
	if fake.count(http.MethodPost, envPath) != 1 {
		t.Fatal("ambiguous write was retried by the transport")
	}
}

func TestWriteUpdatesOnlyTheSingleExistingEntry(t *testing.T) {
	fake := newFake(t)
	fake.project("")
	fake.envs(env("envOLD1", "DATABASE_URL", "sensitive", `["preview"]`, testBranch, ""),
		env("envOTHER", "DATABASE_URL", "sensitive", `["preview"]`, "feature/y", ""),
		env("envPROD", "DATABASE_URL", "sensitive", `["production"]`, "", ""))
	fake.handle(http.MethodPost, envPath, upsertCreated) // returns envNEW1, not envOLD1
	adapter := fake.adapter(t, previewScope())
	request := provider.NewWriteRequest("upsert", previewScope().Target(), ServiceName,
		previewScope().Fingerprint(), "DATABASE_URL", "", []byte("v"))
	defer request.Destroy()
	_, err := adapter.Write(background, request)
	expectCode(t, err, "WRITE_IDENTITY_DRIFT")

	fake.json(http.MethodPost, envPath, http.StatusCreated, `{"created":{"id":"envOLD1","key":"DATABASE_URL",`+
		`"type":"sensitive","target":["preview"],"gitBranch":"`+testBranch+`","value":"`+canary+`"},"failed":[]}`)
	evidence, err := adapter.Write(background, request)
	if err != nil || evidence.ProviderOperationID != "envOLD1" {
		t.Fatalf("update of the single exact entry failed: %+v %v", evidence, err)
	}
}

func TestVerifyIsAlwaysLimitedMetadataPresence(t *testing.T) {
	fake := newFake(t)
	fake.project("")
	fake.envs(env("envOK", "PRESENT", "sensitive", `["preview"]`, testBranch, ""),
		env("envA", "AMBIGUOUS", "sensitive", `["preview","production"]`, "", ""))
	adapter := fake.adapter(t, previewScope())
	verify := func(name, operationID string, expected provider.Presence) provider.VerifyEvidence {
		t.Helper()
		evidence, err := adapter.Verify(background, provider.VerifyRequest{Target: previewScope().Target(),
			Service: ServiceName, ServiceID: previewScope().Fingerprint(), Name: name,
			ProviderOperationID: operationID, ExpectedPresence: expected})
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Result != provider.VerificationLimited || evidence.Validate() != nil {
			t.Fatalf("verification overclaimed or invalid: %+v", evidence)
		}
		return evidence
	}
	if evidence := verify("PRESENT", "envOK", provider.PresencePresent); evidence.Presence != provider.PresencePresent ||
		evidence.Reason != "metadata-presence-only" {
		t.Fatalf("unexpected %+v", evidence)
	}
	if evidence := verify("PRESENT", "envOTHER", provider.PresencePresent); evidence.Presence != provider.PresenceUnknown ||
		evidence.Reason != "operation-id-mismatch" {
		t.Fatalf("replaced entry was not flagged: %+v", evidence)
	}
	if evidence := verify("ABSENT", "", provider.PresenceAbsent); evidence.Presence != provider.PresenceAbsent {
		t.Fatalf("unexpected %+v", evidence)
	}
	if evidence := verify("ABSENT", "", provider.PresencePresent); evidence.Reason != "presence-mismatch" {
		t.Fatalf("unexpected %+v", evidence)
	}
	if evidence := verify("AMBIGUOUS", "", provider.PresencePresent); evidence.Presence != provider.PresenceUnknown {
		t.Fatalf("unexpected %+v", evidence)
	}
	_, err := adapter.Verify(background, provider.VerifyRequest{Target: productionScope().Target(),
		Service: ServiceName, ServiceID: productionScope().Fingerprint(), Name: "PRESENT"})
	expectCode(t, err, "INVALID_VERIFY")
}

func TestResponsesAreBoundedAndClosedAdaptersStop(t *testing.T) {
	fake := newFake(t)
	fake.handle(http.MethodGet, projectPath, func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"id":"` + testProject + `","pad":"`))
		chunk := []byte(strings.Repeat(canary, 1024))
		for written := 0; written <= maxResponseBytes; written += len(chunk) {
			if _, err := response.Write(chunk); err != nil {
				return
			}
		}
	})
	adapter := fake.adapter(t, productionScope())
	_, err := adapter.Identity(background)
	expectCode(t, err, "RESPONSE_TOO_LARGE")

	adapter.Close()
	before := fake.total()
	_, err = adapter.Identity(background)
	expectCode(t, err, "CLOSED")
	if fake.total() != before {
		t.Fatal("closed adapter issued a request")
	}
}

func TestJSONEscapingMatchesEncodingJSON(t *testing.T) {
	inputs := []string{"plain", "q\"b\\", "\x00\x1f\n\r\t", "ü€😀", "<script>&'", "\u2028\u2029"}
	for _, input := range inputs {
		body := previewScope().upsertBody("DATABASE_URL", []byte(input))
		var decoded struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil || decoded.Value != input {
			t.Fatalf("escaping round-trip failed for %q: %v", input, err)
		}
		if cap(body) < len(body) || cap(body) > len(body)+6*len(input)+256 {
			t.Fatal("unexpected body allocation")
		}
	}
}
