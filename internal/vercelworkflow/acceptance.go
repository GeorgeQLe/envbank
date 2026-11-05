package vercelworkflow

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
)

// Disposable Preview acceptance. It drives the SAME configured workflow
// (owner hardware approval, lease, journal, rollout engine, redeploy, health)
// against an owner-selected, clearly marked disposable project and exact
// Preview branch, then proves that the new deployment consumed the exact
// approved fixture record revision. The fixture endpoint returns only a
// status code; no value, hash or proof is ever written to receipts.
//
// This qualifies "provider Preview acceptance" only. It does not qualify
// staged Production promotion/rollback, physical Secure Enclave user
// presence or the external computer-use observation controller.
const (
	AcceptanceRecordName      = "ENVBANK_ACCEPTANCE_FIXTURE_SECRET"
	AcceptanceMarker          = "envbank-acceptance"
	AcceptanceFixturePath     = "/api/envbank-acceptance"
	AcceptanceHealthPath      = "/api/health"
	AcceptanceChallengeHeader = "x-envbank-acceptance-challenge"
	AcceptanceProofHeader     = "x-envbank-acceptance-proof"
	AcceptanceProofDomain     = "envbank.vercel.acceptance.v1"

	// Fixture status contract (see e2e/fixtures/vercel-acceptance).
	FixtureMatch    = http.StatusNoContent        // 204: proof matches the deployed value
	FixtureMismatch = http.StatusConflict         // 409: value present, proof differs
	FixtureAbsent   = http.StatusFailedDependency // 424: value absent or too short

	acceptanceMinSecretBytes = 32
	acceptanceMaxCalls       = 40
)

var acceptanceProjectName = regexp.MustCompile(`^envbank-acceptance-[a-z0-9][a-z0-9._-]{0,80}$`)

// AcceptanceTarget is the operator's out-of-band, non-secret restatement of
// the exact disposable scope. It must match the manifest and the provider.
type AcceptanceTarget struct {
	TeamID, ProjectID, ProjectName, GitBranch string
}

// ParseAcceptanceTarget parses "disposable:TEAM_ID/PROJECT_ID/PROJECT_NAME@BRANCH".
func ParseAcceptanceTarget(raw string) (AcceptanceTarget, error) {
	invalid := errors.New("acceptance target must be disposable:team_ID/prj_ID/envbank-acceptance-NAME@envbank-acceptance-BRANCH")
	rest, ok := strings.CutPrefix(raw, "disposable:")
	if !ok {
		return AcceptanceTarget{}, invalid
	}
	head, branch, ok := strings.Cut(rest, "@")
	parts := strings.Split(head, "/")
	if !ok || len(parts) != 3 {
		return AcceptanceTarget{}, invalid
	}
	target := AcceptanceTarget{TeamID: parts[0], ProjectID: parts[1], ProjectName: parts[2], GitBranch: branch}
	scope := vercel.Scope{TeamID: target.TeamID, ProjectID: target.ProjectID, Environment: vercel.EnvironmentPreview, GitBranch: target.GitBranch}
	if scope.Validate() != nil || target.GitBranch == "" || !strings.HasPrefix(target.GitBranch, AcceptanceMarker) || !acceptanceProjectName.MatchString(target.ProjectName) {
		return AcceptanceTarget{}, invalid
	}
	return target, nil
}

// CheckAcceptanceManifest requires a manifest that can only write the single
// dedicated fixture record into the exact disposable Preview branch.
func CheckAcceptanceManifest(document *contract.Document, target AcceptanceTarget) error {
	invalid := errors.New("acceptance manifest is not the dedicated disposable fixture")
	if document == nil || len(document.Manifest.Targets) != 1 {
		return invalid
	}
	t, ok := document.Manifest.Targets["vercel"]
	if !ok || t.TeamID != target.TeamID || t.ProjectID != target.ProjectID || t.Project != target.ProjectName || t.Environment != vercel.EnvironmentPreview || t.GitBranch != target.GitBranch || t.CustomEnvironmentID != "" || len(t.Services) != 1 {
		return invalid
	}
	service, ok := t.Services["environment"]
	if !ok || len(service.Variables) != 1 || len(service.Absent) != 0 {
		return invalid
	}
	variable, ok := service.Variables[AcceptanceRecordName]
	if !ok || variable.Source != "record" || variable.Value != "" || variable.Record == "" {
		return invalid
	}
	record, ok := document.Manifest.Records[variable.Record]
	if !ok || record.Source != "generate" {
		return invalid
	}
	return nil
}

// AcceptanceProbe sends a status-only GET to AcceptanceFixturePath on a
// proven deployment with fixed challenge/proof headers.
type AcceptanceProbe func(context.Context, vercel.Deployment, map[string]string) (int, error)

// NewAcceptanceProbe reuses the scoped health credential handling: owned
// *.vercel.app host only, optional bypass header, no redirects or body reads.
func NewAcceptanceProbe(scope vercel.Scope, bypass []byte) (AcceptanceProbe, func(), error) {
	return newAcceptanceProbe(scope, bypass, &http.Client{})
}

func newAcceptanceProbe(scope vercel.Scope, bypass []byte, client *http.Client) (AcceptanceProbe, func(), error) {
	probe, closeProbe, e := newScopedProbe(scope, bypass, client)
	if e != nil {
		return nil, nil, e
	}
	return func(ctx context.Context, d vercel.Deployment, headers map[string]string) (int, error) {
		return probe(ctx, d, AcceptanceFixturePath, headers)
	}, closeProbe, nil
}

// AcceptanceProof is HMAC-SHA256(key=fixture value, domain NUL challenge),
// base64url. The fixture implements the identical computation.
func AcceptanceProof(value []byte, challenge string) string {
	mac := hmac.New(sha256.New, value)
	mac.Write([]byte(AcceptanceProofDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(challenge))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type AcceptanceFixtureEvidence struct {
	SourceStatus          int `json:"source_status"`
	DeploymentStatus      int `json:"deployment_status"`
	NegativeControlStatus int `json:"negative_control_status"`
}

// AcceptanceReceipt contains fixed codes, opaque IDs and status integers only.
type AcceptanceReceipt struct {
	Result               string                    `json:"result"`
	Blocker              string                    `json:"blocker,omitempty"`
	Level                string                    `json:"acceptance_level"`
	FullWorkflow         string                    `json:"full_workflow"`
	FullWorkflowBlockers []string                  `json:"full_workflow_blockers"`
	TeamID               string                    `json:"team_id"`
	ProjectID            string                    `json:"project_id"`
	GitBranch            string                    `json:"git_branch"`
	PlanID               string                    `json:"plan_id,omitempty"`
	OperationID          string                    `json:"operation_id,omitempty"`
	RolloutID            string                    `json:"rollout_id,omitempty"`
	SourceDeploymentID   string                    `json:"source_deployment_id,omitempty"`
	DeploymentID         string                    `json:"deployment_id,omitempty"`
	Stage                string                    `json:"stage,omitempty"`
	VariableState        string                    `json:"variable_state,omitempty"`
	HealthChecks         int                       `json:"health_checks"`
	OwnerApprovalKeyID   string                    `json:"owner_approval_key_id,omitempty"`
	Fixture              AcceptanceFixtureEvidence `json:"fixture"`
	Cleanup              []string                  `json:"cleanup,omitempty"`
}

type AcceptanceRunner struct {
	Backend *Backend
	Target  AcceptanceTarget
	Probe   AcceptanceProbe
	Random  io.Reader
}

func (runner AcceptanceRunner) random() io.Reader {
	if runner.Random != nil {
		return runner.Random
	}
	return rand.Reader
}

func (runner AcceptanceRunner) challenge() (string, error) {
	raw := make([]byte, 32)
	if _, e := io.ReadFull(runner.random(), raw); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func blockedAcceptance(receipt AcceptanceReceipt, code string) AcceptanceReceipt {
	receipt.Result, receipt.Blocker = "BLOCKED", code
	return receipt
}

// Run never approves, never imports credentials and never deletes provider
// resources. It refuses unless the owner already approved this exact plan
// with the pinned hardware key.
func (runner AcceptanceRunner) Run(ctx context.Context, planID string) AcceptanceReceipt {
	receipt := AcceptanceReceipt{Result: "BLOCKED", Level: "provider-preview", FullWorkflow: "not-qualified",
		FullWorkflowBlockers: []string{"PRODUCTION_PROMOTION_ROLLBACK_REQUIRES_SEPARATE_DISPOSABLE_PRODUCTION_PROJECT", "PHYSICAL_SECURE_ENCLAVE_PRESENCE_NOT_OBSERVED_BY_HARNESS", "EXTERNAL_OBSERVATION_CONTROLLER_UNQUALIFIED"},
		TeamID:               runner.Target.TeamID, ProjectID: runner.Target.ProjectID, GitBranch: runner.Target.GitBranch, PlanID: planID}
	b := runner.Backend
	if b.ready() != nil || runner.Probe == nil {
		return blockedAcceptance(receipt, "VERCEL_BACKEND_UNAVAILABLE")
	}
	scope := b.Adapter.Scope()
	if scope.Environment != vercel.EnvironmentPreview {
		return blockedAcceptance(receipt, "ACCEPTANCE_PREVIEW_ONLY")
	}
	if scope.TeamID != runner.Target.TeamID || scope.ProjectID != runner.Target.ProjectID || scope.GitBranch != runner.Target.GitBranch || scope.CustomEnvironmentID != "" {
		return blockedAcceptance(receipt, "ACCEPTANCE_TARGET_MISMATCH")
	}
	if CheckAcceptanceManifest(b.Document, runner.Target) != nil {
		return blockedAcceptance(receipt, "ACCEPTANCE_MANIFEST_NOT_DISPOSABLE")
	}
	namer, ok := b.Adapter.(interface {
		ProjectName(context.Context) (string, error)
	})
	if !ok {
		return blockedAcceptance(receipt, "ACCEPTANCE_PROJECT_NOT_MARKED")
	}
	if name, e := namer.ProjectName(ctx); e != nil || name != runner.Target.ProjectName {
		return blockedAcceptance(receipt, "ACCEPTANCE_PROJECT_NOT_MARKED")
	}
	if !ownerapproval.ValidPublicKey(b.OwnerApprovalKey) {
		return blockedAcceptance(receipt, "OWNER_APPROVAL_KEY_NOT_PINNED")
	}
	if !digestID.MatchString(planID) {
		return blockedAcceptance(receipt, "ACCEPTANCE_PLAN_INVALID")
	}
	plan, _, e := b.Store.LoadPlan(ctx, planID)
	if e != nil || b.bindPlan(plan) != nil {
		return blockedAcceptance(receipt, "ACCEPTANCE_PLAN_INVALID")
	}
	policy, e := b.policy(ctx, plan, "stage")
	if e != nil {
		return blockedAcceptance(receipt, "OWNER_APPROVAL_REQUIRED")
	}
	if state, _, journalErr := b.Store.LoadDeployment(ctx, OperationID(planID)); journalErr == nil {
		if b.bindState(ctx, state) != nil {
			return blockedAcceptance(receipt, "ACCEPTANCE_JOURNAL_UNAVAILABLE")
		}
		previous := result(state)
		receipt.OperationID, receipt.RolloutID, receipt.Stage, receipt.VariableState = previous.OperationID, previous.RolloutID, previous.Stage, previous.VariableState
		receipt.DeploymentID = state.DeploymentID
		return blockedAcceptance(receipt, "ACCEPTANCE_OPERATION_ALREADY_STARTED")
	} else if !errors.Is(journalErr, ErrNotFound) {
		return blockedAcceptance(receipt, "ACCEPTANCE_JOURNAL_UNAVAILABLE")
	}
	receipt.OwnerApprovalKeyID = policy.OwnerApproval.KeyID
	receipt.SourceDeploymentID = policy.DeploymentSourceID
	if policy.DeploymentHealthPath != AcceptanceHealthPath {
		return blockedAcceptance(receipt, "ACCEPTANCE_HEALTH_PATH_MISMATCH")
	}
	record, revision := "", int64(0)
	for _, action := range plan.Actions {
		if action.Name == AcceptanceRecordName {
			record, revision = action.Record, action.ExpectedRecordRevision
		}
	}
	if record == "" || revision < 1 || len(plan.Actions) != 1 {
		return blockedAcceptance(receipt, "ACCEPTANCE_PLAN_INVALID")
	}

	// Compute both fresh proofs from the exact approved record revision and
	// wipe the value immediately. Only status codes leave this function.
	sourceChallenge, e1 := runner.challenge()
	deploymentChallenge, e2 := runner.challenge()
	controlChallenge, e3 := runner.challenge()
	controlProof, e4 := runner.challenge()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return blockedAcceptance(receipt, "ACCEPTANCE_RANDOM_UNAVAILABLE")
	}
	// Fixture provenance must be generated, never an imported upstream key.
	snapshot, snapshotRevision, snapshotErr := b.Store.Snapshot(ctx, plan.Bundle)
	if snapshotErr != nil || snapshot.Validate() != nil || snapshotRevision != plan.SnapshotRevision || snapshot.ManifestDigest != plan.ManifestDigest || snapshot.Bundle != plan.Bundle || snapshot.RecordRevisions[record] != revision || snapshot.Sources[record].Source != "generate" || snapshot.Sources[record].Status != "ready" {
		return blockedAcceptance(receipt, "ACCEPTANCE_GENERATED_FIXTURE_REQUIRED")
	}
	// Re-check at the private read boundary: an entropy source or metadata
	// read may have stalled since the first approval check.
	currentPolicy, authErr := b.policy(ctx, plan, "stage")
	if ctx.Err() != nil || authErr != nil || !sameApproval(policy, currentPolicy) {
		return blockedAcceptance(receipt, "OWNER_APPROVAL_REQUIRED")
	}
	value, e := b.Store.LoadRecord(ctx, plan.Bundle, record, revision)
	if e != nil {
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_RECORD_UNAVAILABLE")
	}
	if len(value) < acceptanceMinSecretBytes {
		wipeBytes(value)
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_TOO_SHORT")
	}
	sourceProof := AcceptanceProof(value, sourceChallenge)
	deploymentProof := AcceptanceProof(value, deploymentChallenge)
	wipeBytes(value)

	// Freshness precondition: the approved source deployment must answer the
	// fixture and must NOT already hold this exact value.
	source, e := b.Adapter.Deployment(ctx, policy.DeploymentSourceID)
	if e != nil {
		return blockedAcceptance(receipt, "ACCEPTANCE_SOURCE_UNAVAILABLE")
	}
	status, e := runner.Probe(ctx, source, map[string]string{AcceptanceChallengeHeader: sourceChallenge, AcceptanceProofHeader: sourceProof})
	receipt.Fixture.SourceStatus = status
	switch {
	case e != nil:
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_UNREACHABLE")
	case status == FixtureMatch:
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_NOT_FRESH")
	case status != FixtureMismatch && status != FixtureAbsent:
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_UNREACHABLE")
	}

	// Drive the configured workflow only through its own entry points.
	result, e := b.Call(ctx, "envbank_workflow_start", mcpserver.Request{PlanID: planID})
	for calls := 1; ; calls++ {
		if e != nil {
			return blockedAcceptance(receipt, "ACCEPTANCE_WORKFLOW_CALL_FAILED")
		}
		receipt.OperationID, receipt.RolloutID, receipt.Stage, receipt.VariableState = result.OperationID, result.RolloutID, result.Stage, result.VariableState
		if len(result.Health) > 0 {
			receipt.HealthChecks = result.Health[0].SuccessfulChecks
		}
		if result.BlockerCode != "" {
			return blockedAcceptance(receipt, result.BlockerCode)
		}
		if result.Stage == "complete" {
			break
		}
		if result.Stage == "failed" || calls >= acceptanceMaxCalls || result.OperationID == "" {
			return blockedAcceptance(receipt, "ACCEPTANCE_WORKFLOW_INCOMPLETE")
		}
		if result.Stage == "building" {
			if b.wait(ctx, 10*time.Second) != nil {
				return blockedAcceptance(receipt, "ACCEPTANCE_WORKFLOW_INCOMPLETE")
			}
		}
		result, e = b.Call(ctx, "envbank_workflow_resume", mcpserver.Request{OperationID: result.OperationID})
	}

	state, _, e := b.Store.LoadDeployment(ctx, OperationID(planID))
	if e != nil || state.Stage != "complete" || state.DeploymentID == "" {
		return blockedAcceptance(receipt, "ACCEPTANCE_DEPLOYMENT_UNPROVEN")
	}
	receipt.DeploymentID = state.DeploymentID
	deployment, e := b.Adapter.ProveDeployment(ctx, state.DeploymentID, state.SourceDeploymentID, state.ID)
	if e != nil || deployment.ReadyState != "READY" {
		return blockedAcceptance(receipt, "ACCEPTANCE_DEPLOYMENT_UNPROVEN")
	}
	receipt.Cleanup = []string{
		"delete preview deployment " + state.DeploymentID + " in project " + scope.ProjectID,
		"delete Secret variable " + AcceptanceRecordName + " scoped to preview branch " + scope.GitBranch + " in project " + scope.ProjectID + ", or delete the disposable project itself",
		"revoke the dedicated acceptance API token and any dedicated protection-bypass credential",
	}
	status, e = runner.Probe(ctx, deployment, map[string]string{AcceptanceChallengeHeader: deploymentChallenge, AcceptanceProofHeader: deploymentProof})
	receipt.Fixture.DeploymentStatus = status
	if e != nil {
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_UNREACHABLE")
	}
	if status != FixtureMatch {
		return blockedAcceptance(receipt, "ACCEPTANCE_FRESH_VALUE_NOT_CONSUMED")
	}
	// Negative control: a random proof must be rejected, so a fixture that
	// always answers 204 cannot produce a PASS.
	status, e = runner.Probe(ctx, deployment, map[string]string{AcceptanceChallengeHeader: controlChallenge, AcceptanceProofHeader: controlProof})
	receipt.Fixture.NegativeControlStatus = status
	if e != nil || status != FixtureMismatch {
		return blockedAcceptance(receipt, "ACCEPTANCE_FIXTURE_CONTROL_FAILED")
	}
	receipt.Result, receipt.Blocker = "PASS", ""
	return receipt
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
