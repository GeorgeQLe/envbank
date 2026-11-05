package vercel

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const acceptanceName = "envbank-acceptance-prod1"

func acceptanceProject(fake *fakeVercel, name, account, extra string) {
	fake.json(http.MethodGet, projectPath, http.StatusOK, `{"id":"`+testProject+`","name":"`+name+`","accountId":"`+account+`",`+
		`"env":[{"key":"SECRET","value":"`+canary+`"}]`+extra+`}`)
}

func defaultDomain(extra string) string {
	return `{"name":"` + acceptanceName + `.vercel.app","projectId":"` + testProject + `","redirect":null,"redirectStatusCode":null,"gitBranch":null,"customEnvironmentId":null,"verified":true,"secret":"` + canary + `"` + extra + `}`
}

func TestAcceptanceGuardAcceptsOnlyDefaultDomain(t *testing.T) {
	fake := newFake(t)
	acceptanceProject(fake, acceptanceName, testTeam, `,"lastAliasRequest":{"jobStatus":"succeeded"}`)
	fake.json(http.MethodGet, domainsPath, http.StatusOK, `{"domains":[`+defaultDomain("")+`],"pagination":{"count":1,"next":null,"prev":null}}`)
	adapter := fake.adapter(t, productionScope())
	// No mutation authorization is attached: the guard must be read-only.
	if err := adapter.VerifyDisposableProductionProject(context.Background(), acceptanceName); err != nil {
		t.Fatalf("guard refused the default-only project: %v", err)
	}
	if fake.mutations() != 0 {
		t.Fatal("guard sent a mutation")
	}
	call := fake.last(http.MethodGet, domainsPath)
	if call.Query.Get("production") != "" || call.Query.Get("redirects") != "" || call.Query.Get("gitBranch") != "" {
		t.Fatal("guard filtered the domain list")
	}
	assertNoCanary(t, call.Query)
}

func TestAcceptanceGuardRefusals(t *testing.T) {
	ok := `{"domains":[` + defaultDomain("") + `],"pagination":{"count":1,"next":null}}`
	cases := []struct {
		name, projectName, account, projectExtra, domains, code string
		scope                                                   Scope
	}{
		{"preview scope", acceptanceName, testTeam, "", ok, "SCOPE_NOT_PRODUCTION", previewScope()},
		{"unmarked name", "siftcut-web", testTeam, "", ok, "ACCEPTANCE_PROJECT_NOT_MARKED", productionScope()},
		{"wrong owner", acceptanceName, "team_other", "", ok, "PROJECT_OWNERSHIP_MISMATCH", productionScope()},
		{"alias job", acceptanceName, testTeam, `,"lastAliasRequest":{"jobStatus":"in-progress"}`, ok, "ALIAS_JOB_IN_PROGRESS", productionScope()},
		{"custom domain", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain("") + `,{"name":"shop.example.com","projectId":"` + testProject + `","verified":true}]}`, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", productionScope()},
		{"only custom", acceptanceName, testTeam, "", `{"domains":[{"name":"shop.example.com","projectId":"` + testProject + `","verified":true}]}`, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", productionScope()},
		{"no domains", acceptanceName, testTeam, "", `{"domains":[]}`, "ACCEPTANCE_CUSTOM_DOMAIN_PRESENT", productionScope()},
		{"paginated", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain("") + `],"pagination":{"count":1,"next":1700000000000}}`, "DOMAIN_LIST_INCOMPLETE", productionScope()},
		{"count mismatch", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain("") + `],"pagination":{"count":2,"next":null}}`, "DOMAIN_LIST_INCOMPLETE", productionScope()},
		{"missing list", acceptanceName, testTeam, "", `{}`, "DOMAIN_LIST_INVALID", productionScope()},
		{"redirect", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain(`,"redirect":"example.com"`) + `]}`, "ACCEPTANCE_DOMAIN_NOT_DEFAULT_PRODUCTION", productionScope()},
		{"redirect code", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain(`,"redirectStatusCode":307`) + `]}`, "ACCEPTANCE_DOMAIN_NOT_DEFAULT_PRODUCTION", productionScope()},
		{"branch domain", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain(`,"gitBranch":"main"`) + `]}`, "ACCEPTANCE_DOMAIN_NOT_DEFAULT_PRODUCTION", productionScope()},
		{"custom env domain", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain(`,"customEnvironmentId":"env_x1"`) + `]}`, "ACCEPTANCE_DOMAIN_NOT_DEFAULT_PRODUCTION", productionScope()},
		{"unverified", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain(`,"verified":false`) + `]}`, "ACCEPTANCE_DOMAIN_UNVERIFIED", productionScope()},
		{"other project domain", acceptanceName, testTeam, "", `{"domains":[` + defaultDomain(`,"projectId":"prj_other"`) + `]}`, "DOMAIN_SCOPE_MISMATCH", productionScope()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFake(t)
			acceptanceProject(fake, tc.projectName, tc.account, tc.projectExtra)
			fake.json(http.MethodGet, domainsPath, http.StatusOK, tc.domains)
			adapter := fake.adapter(t, tc.scope)
			err := adapter.VerifyDisposableProductionProject(background, acceptanceName)
			expectCode(t, err, tc.code)
			if fake.mutations() != 0 {
				t.Fatal("guard sent a mutation")
			}
		})
	}
}

func TestAcceptanceGuardRejectsInvalidExpectedName(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, productionScope())
	expectCode(t, adapter.VerifyDisposableProductionProject(background, "siftcut-web"), "ACCEPTANCE_PROJECT_NOT_MARKED")
	if fake.total() != 0 {
		t.Fatal("guard contacted the provider for an unmarked expected name")
	}
}

func TestAdditionalMutationAuthorizationOnlyNarrows(t *testing.T) {
	deny := func(context.Context) error { return errors.New("guard denied") }
	allow := func(context.Context) error { return nil }
	extraCalls := 0
	counting := func(context.Context) error { extraCalls++; return nil }
	cases := []struct {
		name string
		ctx  context.Context
		sent bool
	}{
		{"extra denies", WithAdditionalMutationAuthorization(background, deny), false},
		{"no existing hook", WithAdditionalMutationAuthorization(context.Background(), allow), false},
		{"nil extra", WithAdditionalMutationAuthorization(background, nil), false},
		{"existing denies first", WithAdditionalMutationAuthorization(WithMutationAuthorization(context.Background(), deny), counting), false},
		{"both allow", WithAdditionalMutationAuthorization(background, allow), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := productionFake(t, "")
			err := fake.adapter(t, productionScope()).Promote(tc.ctx, "dpl_staged")
			if tc.sent {
				if err != nil || fake.mutations() != 1 {
					t.Fatalf("composed authorization blocked an allowed promote: %v", err)
				}
				return
			}
			expectCode(t, err, "AUTHORIZATION_DENIED")
			if !MutationNotSent(err) || fake.mutations() != 0 {
				t.Fatal("denied promote was sent or not marked unsent")
			}
		})
	}
	if extraCalls != 0 {
		t.Fatal("extra check ran after the existing check denied")
	}
}

func TestRefusedBeforeSendIsSafeAndUnsent(t *testing.T) {
	err := RefusedBeforeSend("promote", "ACCEPTANCE_GUARD_DENIED")
	safe := expectCode(t, err, "ACCEPTANCE_GUARD_DENIED")
	if !MutationNotSent(err) || safe.Retry != provider.RetrySafe {
		t.Fatal("pre-send refusal not marked unsent")
	}
}

func TestAcceptanceGuardProviderErrorIsSafe(t *testing.T) {
	fake := newFake(t)
	acceptanceProject(fake, acceptanceName, testTeam, "")
	fake.json(http.MethodGet, domainsPath, http.StatusForbidden, `{"error":{"message":"`+canary+`"}}`)
	adapter := fake.adapter(t, productionScope())
	expectCode(t, adapter.VerifyDisposableProductionProject(background, acceptanceName), "FORBIDDEN")
}

func TestAdmissionGuardCannotAgeOutExistingPolicy(t *testing.T) {
	allowed := true
	checks := 0
	ctx := WithMutationAuthorization(context.Background(), func(context.Context) error {
		checks++
		if !allowed {
			return errors.New("policy expired")
		}
		return nil
	})
	ctx = WithAdditionalMutationAuthorization(ctx, func(context.Context) error { allowed = false; return nil })
	fake := productionFake(t, "")
	err := fake.adapter(t, productionScope()).Promote(ctx, "dpl_staged")
	if !MutationNotSent(err) || checks != 2 || fake.mutations() != 0 {
		t.Fatal("slow admission guard bypassed fresh signed-policy check")
	}
}
