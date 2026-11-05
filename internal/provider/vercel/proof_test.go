package vercel

import (
	"context"
	"errors"
	"fmt"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"net/http"
	"strings"
	"testing"
)

func TestRecoveredDeploymentMustProveApprovedSource(t *testing.T) {
	fake := newFake(t)
	scope := previewScope()
	adapter := fake.adapter(t, scope)
	fake.json(http.MethodGet, deploymentPath("dpl_src"), 200, deployment("dpl_src", nil))
	for _, kind := range []string{"valid", "wrong-source", "wrong-commit", "missing-commit", "missing-source"} {
		t.Run(kind, func(t *testing.T) {
			body := deployment("dpl_new", func(value map[string]any) {
				withMarkers(operationID, scope)(value)
				meta := value["meta"].(map[string]any)
				meta[MetaSourceKey] = "dpl_src"
				switch kind {
				case "wrong-source":
					meta[MetaSourceKey] = "dpl_other"
				case "wrong-commit":
					meta["githubCommitSha"] = "deadbeef1234567"
					value["gitSource"] = map[string]any{"ref": testBranch, "sha": "deadbeef1234567"}
				case "missing-commit":
					delete(meta, "githubCommitSha")
					value["gitSource"] = map[string]any{"ref": testBranch}
				case "missing-source":
					delete(meta, MetaSourceKey)
				}
			})
			fake.json(http.MethodGet, deploymentPath("dpl_new"), 200, body)
			got, e := adapter.ProveDeployment(background, "dpl_new", "dpl_src", operationID)
			if kind == "valid" {
				if e != nil || got.ID != "dpl_new" {
					t.Fatal("valid approved source rejected")
				}
			} else if e == nil {
				t.Fatal("reconciled a deployment outside approved source")
			}
			assertNoCanary(t, got, e)
		})
	}
	if fake.mutations() != 0 {
		t.Fatal("source proof mutated provider")
	}
}

func TestAdapterDiagnosticsRedactCredential(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, previewScope())
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(verb, adapter), testToken) {
			t.Fatal("adapter formatting exposed credential")
		}
	}
}

func TestRedeployRejectsPrebuiltAndUnprovenSourceBeforeMutation(t *testing.T) {
	for _, kind := range []string{"prebuilt", "missing-commit"} {
		t.Run(kind, func(t *testing.T) {
			fake := newFake(t)
			scope := previewScope()
			fake.project("")
			fake.envs()
			fake.json(http.MethodGet, deploymentPath("dpl_src"), 200, deployment("dpl_src", func(value map[string]any) {
				if kind == "prebuilt" {
					value["prebuilt"] = true
				} else {
					value["gitSource"] = map[string]any{"ref": testBranch}
					delete(value["meta"].(map[string]any), "githubCommitSha")
				}
			}))
			adapter := fake.adapter(t, scope)
			_, e := adapter.Redeploy(background, "dpl_src", operationID)
			if e == nil || fake.mutations() != 0 {
				t.Fatal("source cannot consume new project variables but a deployment was created")
			}
		})
	}
}

func TestMutationNotSentIsDistinctFromLostResponse(t *testing.T) {
	fake := newFake(t)
	adapter := fake.adapter(t, previewScope())
	// An ownership read failure cannot have sent a deployment mutation.
	fake.json(http.MethodGet, projectPath, 503, `{"error":{"message":"`+canary+`"}}`)
	_, err := adapter.Redeploy(background, "dpl_src", operationID)
	if !MutationNotSent(err) || fake.mutations() != 0 {
		t.Fatal("pre-send error lost definite absence evidence")
	}
	assertNoCanary(t, err)
}

func TestAuthorityIsCheckedAtHTTPMutationBoundary(t *testing.T) {
	fake := newFake(t)
	scope := previewScope()
	fake.project("")
	fake.envs()
	fake.handle(http.MethodPost, envPath, upsertCreated)
	adapter := fake.adapter(t, scope)
	checks := 0
	ctx := WithMutationAuthorization(background, func(context.Context) error { checks++; return errors.New("private reason " + canary) })
	request := provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "API_SECRET", "", []byte(canary))
	defer request.Destroy()
	_, err := adapter.Write(ctx, request)
	if err == nil || checks != 1 || fake.mutations() != 0 {
		t.Fatal("expired or cancelled approval reached provider")
	}
	assertNoCanary(t, err)
}

func TestWriteCheckpointRejectsUnrelatedMetadataChange(t *testing.T) {
	fake := newFake(t)
	scope := previewScope()
	fake.project("")
	fake.envs()
	fake.handle(http.MethodPost, envPath, func(w http.ResponseWriter, r *http.Request) {
		upsertCreated(w, r)
		fake.envs(env("envNEW1", "DATABASE_URL", "sensitive", `["preview"]`, testBranch, ""), env("envOutside", "OTHER", "sensitive", `["preview"]`, testBranch, ""))
	})
	adapter := fake.adapter(t, scope)
	request := provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "DATABASE_URL", "", []byte(canary))
	defer request.Destroy()
	_, err := adapter.Write(background, request)
	if !hasCode(err, "WRITE_CHECKPOINT_UNAVAILABLE") || provider.SanitizeError("write", err).Retry != provider.RetryAmbiguous || fake.mutations() != 1 {
		t.Fatal("unrelated change absorbed into checkpoint")
	}
	assertNoCanary(t, err)
}

func TestWriteChecksExpectedMetadataBeforeMutation(t *testing.T) {
	fake := newFake(t)
	scope := previewScope()
	fake.project("")
	fake.envs()
	adapter := fake.adapter(t, scope)
	request := provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "API_SECRET", "", []byte(canary))
	defer request.Destroy()
	request.ExpectedMetadataRevision = strings.Repeat("f", 64)
	_, err := adapter.Write(background, request)
	if !hasCode(err, "METADATA_DRIFT") || fake.mutations() != 0 {
		t.Fatal("metadata precondition ignored")
	}
}

func TestMissingMutationAuthorityFailsClosed(t *testing.T) {
	fake := newFake(t)
	scope := previewScope()
	fake.project("")
	fake.envs()
	adapter := fake.adapter(t, scope)
	request := provider.NewWriteRequest("upsert", scope.Target(), ServiceName, scope.Fingerprint(), "API_SECRET", "", []byte(canary))
	defer request.Destroy()
	_, err := adapter.Write(context.Background(), request)
	if !hasCode(err, "AUTHORIZATION_DENIED") || fake.mutations() != 0 {
		t.Fatal("missing trusted authority allowed mutation")
	}
}

func TestWrongCommitPromotedBuildStillPermitsEmergencyRecovery(t *testing.T) {
	fake := newFake(t)
	scope := productionScope()
	adapter := fake.adapter(t, scope)
	fake.json(http.MethodGet, deploymentPath("dpl_src"), 200, deployment("dpl_src", func(v map[string]any) { v["target"] = "production"; v["readySubstate"] = "PROMOTED" }))
	fake.json(http.MethodGet, deploymentPath("dpl_new"), 200, deployment("dpl_new", func(v map[string]any) {
		withMarkers(operationID, scope)(v)
		v["target"] = "production"
		v["readySubstate"] = "PROMOTED"
		v["gitSource"] = map[string]any{"ref": testBranch, "sha": "deadbeef1234567"}
		meta := v["meta"].(map[string]any)
		meta["githubCommitSha"] = "deadbeef1234567"
		meta[MetaSourceKey] = "dpl_src"
	}))
	_, err := adapter.ProveDeployment(background, "dpl_new", "dpl_src", operationID)
	if !hasCode(err, "UNEXPECTED_PROMOTION") || fake.mutations() != 0 {
		t.Fatal("wrong commit hid unexpected activation")
	}
}
