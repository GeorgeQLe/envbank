package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
	"github.com/GeorgeQLe/envbank/internal/rollout"
	"github.com/GeorgeQLe/envbank/internal/rotationrun"
	"github.com/GeorgeQLe/envbank/internal/secure"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
	"github.com/GeorgeQLe/envbank/internal/vercelworkflow"
	"github.com/mattn/go-isatty"
)

const vercelCredentialService = "com.envbank.provider.vercel.v1"

var vercelCredentialStore keychain.Store = keychain.SystemStore{}
var vercelAdapterOptions = func() vercel.Options { return vercel.Options{} }
var vercelOwnerConfirmation = confirmVercelOwner

// vercelOwnerSigner is the Secure Enclave signer in production. Tests replace
// it with a software signer; production code never imports that signer.
var vercelOwnerSigner = ownerapproval.OpenSecureEnclave

type vercelBinding struct {
	Scope        vercel.Scope `json:"scope"`
	Token        string       `json:"token"`
	HealthBypass string       `json:"health_bypass,omitempty"`
}

func (vercelBinding) String() string { return "[Vercel credential REDACTED]" }
func (vercelBinding) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "[Vercel credential REDACTED]")
}
func vercelCredentialAccount(vaultID, bundleID string) string {
	digest := sha256.Sum256([]byte("envbank.vercel.v1\x00" + vaultID + "\x00" + bundleID))
	return "v1:" + hex.EncodeToString(digest[:])
}

func vercelCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("Vercel subcommand required: bind, plan, approve, apply, resume, status, rollback, accept, accept-production")
	}
	switch args[0] {
	case "bind", "plan", "approve", "apply", "resume", "status", "rollback", "accept", "accept-production":
	default:
		return errors.New("unknown Vercel subcommand")
	}
	fs := flag.NewFlagSet("vercel "+args[0], flag.ContinueOnError)
	manifest := fs.String("manifest", "", "public bundle manifest")
	planID := fs.String("plan", "", "encrypted Vercel plan ID")
	operationID := fs.String("operation", "", "encrypted Vercel deployment operation ID")
	source := fs.String("source-deployment", "", "approved existing deployment ID")
	health := fs.String("health-path", "/api/health", "credential-free health path on the owned deployment")
	expiry := fs.Duration("expires", time.Hour, "owner approval duration, at most 24 hours")
	auth := addAuthFlags(fs)
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if *manifest == "" || fs.NArg() != 0 {
		return errors.New("Vercel commands require --manifest and no positional arguments")
	}
	if args[0] == "bind" {
		document, e := loadBundleManifest(*manifest)
		if e != nil {
			return e
		}
		scope, e := vercelworkflow.ScopeForManifest(document)
		if e != nil {
			return e
		}
		api, _, e := unlockedAPI(auth)
		if e != nil {
			return e
		}
		if isatty.IsTerminal(os.Stdin.Fd()) {
			return errors.New("Vercel bind requires owner-controlled token stdin; do not paste it into an agent conversation")
		}
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, (16<<10)+1))
		if e != nil || len(raw) > 16<<10 {
			return errors.New("Vercel credential input invalid")
		}
		defer clearBytes(raw)
		token := bytes.TrimSpace(raw)
		var imported struct {
			Token        string `json:"token"`
			HealthBypass string `json:"health_bypass,omitempty"`
		}
		if bytes.HasPrefix(token, []byte("{")) {
			decoder := json.NewDecoder(bytes.NewReader(token))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&imported) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				return errors.New("Vercel credential input invalid")
			}
			token = []byte(imported.Token)
			defer clearBytes(token)
		}
		_, closeProbe, probeErr := vercelworkflow.NewHealthProbe(scope, []byte(imported.HealthBypass))
		if probeErr != nil {
			return errors.New("Vercel health credential input invalid")
		}
		closeProbe()
		adapter, e := vercel.New(token, scope, vercelAdapterOptions())
		if e != nil {
			return errors.New("Vercel credential input invalid")
		}
		defer adapter.Close()
		if _, e = adapter.Bind(context.Background()); e != nil {
			return providerSafeError("bind", e)
		}
		payload, e := json.Marshal(vercelBinding{Scope: scope, Token: string(token), HealthBypass: imported.HealthBypass})
		if e != nil {
			return errors.New("Vercel credential binding invalid")
		}
		defer clearBytes(payload)
		if e = vercelCredentialStore.Put(vercelCredentialService, vercelCredentialAccount(api.Config.VaultID, document.Manifest.Bundle), payload); e != nil {
			return errors.New("Vercel credential binding could not be stored")
		}
		fmt.Printf("bundle: %s\nprovider: vercel\nproject id: %s\nenvironment: %s\nbranch: %s\nstatus: bound\n", document.Manifest.Bundle, scope.ProjectID, scope.Environment, scope.GitBranch)
		return nil
	}
	if args[0] == "accept" {
		return vercelAccept(auth, *manifest, *planID)
	}
	if args[0] == "accept-production" {
		return vercelAcceptProduction(auth, *manifest, *planID)
	}
	backend, api, secrets, closeBackend, e := openVercelBackend(auth, *manifest)
	if e != nil {
		return e
	}
	defer closeBackend()
	ctx := context.Background()
	if args[0] == "approve" {
		if *planID == "" || *source == "" || *expiry <= 0 || *expiry > 24*time.Hour || !vercelworkflow.ValidHealthPath(*health) {
			return errors.New("Vercel approval requires a plan, source deployment, health path and duration up to 24h")
		}
		plan, _, e := backend.Store.LoadPlan(ctx, *planID)
		if e != nil {
			return errors.New("Vercel approval plan unavailable")
		}
		existingOperation, _, operationErr := backend.Store.LoadDeployment(ctx, vercelworkflow.OperationID(plan.ID()))
		if operationErr != nil && !errors.Is(operationErr, vercelworkflow.ErrNotFound) {
			return errors.New("Vercel operation journal unavailable")
		}
		continuing := operationErr == nil
		if continuing && (existingOperation.Validate() != nil || existingOperation.SourceDeploymentID != *source || existingOperation.HealthPath != *health || existingOperation.ScopeFingerprint != backend.Adapter.Scope().Fingerprint()) {
			return errors.New("Vercel reapproval cannot change an existing operation's bindings")
		}
		validationTime := time.Now().UTC()
		if continuing {
			validationTime, e = time.Parse(time.RFC3339, plan.CreatedAt)
			if e != nil {
				return errors.New("Vercel plan invalid")
			}
		}
		if plan.Validate(validationTime) != nil {
			return errors.New("Vercel approval requires a valid current plan or an existing bound operation")
		}
		// Recompute target context and inspect source before asking the owner to
		// sign a concrete scope. Neither operation reads provider secret values.
		scope := backend.Adapter.Scope()
		if backend.ValidatePlan(plan) != nil {
			return errors.New("Vercel approval target mismatch")
		}
		deployment, e := backend.Adapter.Deployment(ctx, *source)
		if e != nil || deployment.ReadyState != "READY" || deployment.CommitSHA == "" || deployment.Prebuilt {
			return errors.New("Vercel approval source is not a ready owned deployment")
		}
		if scope.Environment == "production" {
			current, e := backend.Adapter.CurrentDeployment(ctx)
			if e != nil || current.ID != *source && (!continuing || current.ID != existingOperation.DeploymentID) {
				return errors.New("Vercel approval source is not current production")
			}
		}
		// The owner pin comes only from the passphrase-encrypted config written
		// by the owner-only enrollment command, never from flags or requests.
		pin := backend.OwnerApprovalKey
		if !ownerapproval.ValidPublicKey(pin) {
			return errors.New("hardware owner approval key is not enrolled; the owner must run envbank owner-approval enroll")
		}
		signer, e := vercelOwnerSigner(pin)
		if e != nil {
			return errors.New("hardware owner approval unavailable on this host; Vercel approval refused (no TTY or software fallback)")
		}
		review := fmt.Sprintf("Plan: %s\nManifest: %s\nTeam: %s\n", plan.ID(), plan.ManifestDigest, scope.TeamID)
		for _, action := range plan.Actions {
			review += fmt.Sprintf("  %s <- %s (revision %d)\n", action.Name, action.Record, action.ExpectedRecordRevision)
		}
		prompt := review + fmt.Sprintf("Approve Vercel project %s, %s branch %q, %d secret writes, source %s, health %s and production promotion/rollback where applicable for %s? Type approve: ", scope.ProjectID, scope.Environment, scope.GitBranch, len(plan.Actions), *source, *health, *expiry)
		if e = vercelOwnerConfirmation(prompt); e != nil {
			return e
		}
		environment, grace := "staging", "15m"
		if scope.Environment == "production" {
			environment, grace = "production", "24h"
		}
		signedAt := time.Now().UTC().Truncate(time.Second)
		policy := lifecycle.AutomationPolicy{Version: lifecycle.PolicyVersion, ID: vercelworkflow.PolicyID(plan.ID()), VaultID: api.Config.VaultID, Bundle: plan.Bundle, ManifestDigest: plan.ManifestDigest, Environment: environment, ProviderIdentities: map[string]string{"vercel": scope.TeamID + ":" + scope.ProjectID}, CredentialClasses: []string{"vercel-environment-secret"}, Operations: []string{"stage", "activate", "verify", "rollback"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}}, Schedule: "manual", HealthChecks: []string{*health}, GracePeriod: grace, Rollback: "previous-deployment", RetryBudget: 1, ExpiresAt: signedAt.Add(*expiry).Format(time.RFC3339), ApprovingDevice: api.Config.DeviceID, DeploymentPlanID: plan.ID(), DeploymentSourceID: *source, DeploymentScopeFingerprint: scope.Fingerprint(), DeploymentHealthPath: *health}
		private, e := secure.Decode(secrets.SigningPrivate)
		if e != nil || len(private) != ed25519.PrivateKeySize {
			return errors.New("approval signing key unavailable")
		}
		defer clearBytes(private)
		reason := fmt.Sprintf("approve EnvBank Vercel plan %s for %s %s", plan.ID(), scope.ProjectID, scope.Environment)
		if e = ownerapproval.Approve(ctx, &policy, ed25519.PrivateKey(private), signer, pin, signedAt, reason); e != nil {
			return errors.New("hardware owner approval was not completed; nothing was stored")
		}
		store := backend.Store.(*vercelworkflow.VaultStore)
		expected := int64(0)
		// A reapproval may refresh expiry only for the same exact plan. The
		// backend separately pins source, scope and health path for existing ops.
		if object, err := api.GetObject(store.VaultKey, vaultobject.KindAutomationPolicy, policy.ID); err == nil {
			var previous lifecycle.AutomationPolicy
			decoder := json.NewDecoder(bytes.NewReader(object.Payload))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&previous) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				return errors.New("existing Vercel approval invalid")
			}
			beforeExpiry, parseErr := time.Parse(time.RFC3339, previous.ExpiresAt)
			if parseErr != nil || previous.Validate(beforeExpiry.Add(-time.Second)) != nil || !bytes.Equal(previous.PublicKey, backend.TrustedPolicyKey) || previous.ApprovingDevice != backend.DeviceID {
				return errors.New("existing Vercel approval identity invalid")
			}
			if previous.DeploymentPlanID != policy.DeploymentPlanID || previous.DeploymentSourceID != policy.DeploymentSourceID || previous.DeploymentHealthPath != policy.DeploymentHealthPath || previous.DeploymentScopeFingerprint != policy.DeploymentScopeFingerprint {
				return errors.New("existing Vercel approval has different bindings")
			}
			// Renewal keeps the same owner key. A legacy device-only approval may
			// be replaced only before an operation journal pins it; an in-flight
			// legacy operation needs a new plan, never a silent upgrade.
			if previous.OwnerApproval == nil && continuing {
				return errors.New("existing Vercel operation was approved without hardware owner proof; create and approve a new plan")
			}
			if previous.OwnerApproval != nil && !bytes.Equal(previous.OwnerApproval.PublicKey, pin) {
				return errors.New("existing Vercel approval was signed by a different owner key")
			}
			expected = object.Revision
		} else {
			var status client.HTTPStatusError
			if !errors.As(err, &status) || status.Status != 404 {
				return errors.New("existing Vercel approval unavailable")
			}
		}
		if _, e = store.Lifecycle.SavePolicy(ctx, policy, expected); e != nil {
			return errors.New("Vercel approval could not be stored; existing approval may require expiry reconciliation")
		}
		fmt.Printf("plan: %s\npolicy: %s\nexpires: %s\nstatus: approved\n", plan.ID(), policy.ID, policy.ExpiresAt)
		return nil
	}
	name := ""
	request := mcpserver.Request{PlanID: *planID, OperationID: *operationID}
	switch args[0] {
	case "plan":
		name = "envbank_setup_plan"
	case "apply":
		if *planID == "" {
			return errors.New("Vercel apply requires --plan")
		}
		name = "envbank_workflow_start"
	case "resume":
		name = "envbank_workflow_resume"
	case "status":
		name = "envbank_workflow_status"
	case "rollback":
		name = "envbank_deployment_rollback"
	default:
		return errors.New("unknown Vercel subcommand")
	}
	if (args[0] == "resume" || args[0] == "status" || args[0] == "rollback") && *operationID == "" {
		return errors.New("Vercel operation ID required")
	}
	result, e := backend.Call(ctx, name, request)
	if e != nil {
		return errors.New("Vercel workflow failed; inspect encrypted operation evidence")
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func confirmVercelOwner(prompt string) error {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("Vercel approval requires owner confirmation in an interactive terminal")
	}
	fmt.Fprint(os.Stderr, prompt)
	raw := make([]byte, 32)
	n, e := os.Stdin.Read(raw)
	defer clearBytes(raw)
	if e != nil && e != io.EOF || strings.TrimSpace(string(raw[:n])) != "approve" {
		return errors.New("Vercel approval cancelled")
	}
	return nil
}

func openVercelBackend(auth *authFlags, manifestPath string) (*vercelworkflow.Backend, *client.API, secure.DeviceSecrets, func(), error) {
	backend, api, secrets, closeBackend, _, e := openVercelBackendWith(auth, manifestPath, false)
	return backend, api, secrets, closeBackend, e
}

// openVercelBackendWith optionally builds the acceptance fixture probe from
// the same owner-bound protection-bypass credential as the health probe.
func openVercelBackendWith(auth *authFlags, manifestPath string, acceptance bool) (*vercelworkflow.Backend, *client.API, secure.DeviceSecrets, func(), vercelworkflow.AcceptanceProbe, error) {
	var empty secure.DeviceSecrets
	noop := func() {}
	document, e := loadBundleManifest(manifestPath)
	if e != nil {
		return nil, nil, empty, noop, nil, e
	}
	scope, e := vercelworkflow.ScopeForManifest(document)
	if e != nil {
		return nil, nil, empty, noop, nil, e
	}
	api, secrets, e := unlockedAPI(auth)
	if e != nil {
		return nil, nil, empty, noop, nil, e
	}
	vaultKey, e := requireVaultKey(secrets)
	if e != nil {
		return nil, nil, empty, noop, nil, e
	}
	// Only the signing key is needed after unlocking. Go strings cannot be
	// physically wiped; drop unused references and release all on close.
	secrets = secure.DeviceSecrets{SigningPrivate: secrets.SigningPrivate}
	api.Secrets = secrets
	raw, e := vercelCredentialStore.Get(vercelCredentialService, vercelCredentialAccount(api.Config.VaultID, document.Manifest.Bundle), "Use the exact bound Vercel project credential")
	if e != nil {
		clearBytes(vaultKey)
		return nil, nil, empty, noop, nil, errors.New("Vercel credential unavailable; owner must run vercel bind")
	}
	defer clearBytes(raw)
	var binding vercelBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 32<<10 || decoder.Decode(&binding) != nil || decoder.Decode(&struct{}{}) != io.EOF || binding.Scope != scope {
		clearBytes(vaultKey)
		return nil, nil, empty, noop, nil, errors.New("Vercel credential scope changed; owner must rebind")
	}
	token := []byte(binding.Token)
	adapter, e := vercel.New(token, scope, vercelAdapterOptions())
	clearBytes(token)
	binding.Token = ""
	if e != nil {
		clearBytes(vaultKey)
		return nil, nil, empty, noop, nil, errors.New("Vercel credential binding invalid")
	}
	public, e := secure.Decode(api.Config.SigningPublic)
	if e != nil || len(public) != ed25519.PublicKeySize {
		adapter.Close()
		clearBytes(vaultKey)
		return nil, nil, empty, noop, nil, errors.New("Vercel approval identity invalid")
	}
	store := &vercelworkflow.VaultStore{EncryptedStore: &rollout.EncryptedStore{API: api, VaultKey: vaultKey}, Lifecycle: &lifecycle.VaultStore{API: api, VaultKey: vaultKey}}
	probe, closeProbe, e := vercelworkflow.NewHealthProbe(scope, []byte(binding.HealthBypass))
	if e != nil {
		binding.HealthBypass = ""
		adapter.Close()
		clearBytes(vaultKey)
		return nil, nil, empty, noop, nil, errors.New("Vercel health credential binding invalid")
	}
	var acceptanceProbe vercelworkflow.AcceptanceProbe
	closeAcceptance := func() {}
	if acceptance {
		acceptanceProbe, closeAcceptance, e = vercelAcceptanceProbe(scope, []byte(binding.HealthBypass))
		if e != nil {
			binding.HealthBypass = ""
			closeProbe()
			adapter.Close()
			clearBytes(vaultKey)
			return nil, nil, empty, noop, nil, errors.New("Vercel health credential binding invalid")
		}
	}
	binding.HealthBypass = ""
	backend := &vercelworkflow.Backend{Document: document, Adapter: adapter, Store: store, VaultID: api.Config.VaultID, DeviceID: api.Config.DeviceID, TrustedPolicyKey: ed25519.PublicKey(public), OwnerApprovalKey: api.Config.OwnerApprovalKey(), Probe: probe}
	return backend, api, secrets, func() {
		closeAcceptance()
		closeProbe()
		adapter.Close()
		clearBytes(vaultKey)
		api.Secrets = secure.DeviceSecrets{}
		secrets = secure.DeviceSecrets{}
	}, acceptanceProbe, nil
}

// vercelAcceptanceProbe is replaced by tests with a loopback fixture.
var vercelAcceptanceProbe = vercelworkflow.NewAcceptanceProbe

// vercelAcceptanceForbiddenEnvironment lists provider credential variables
// that must never carry acceptance credentials; the token stays in Keychain.
var vercelAcceptanceForbiddenEnvironment = []string{"VERCEL_TOKEN", "VERCEL_API_TOKEN", "VERCEL_ACCESS_TOKEN", "VERCEL_AUTOMATION_BYPASS_SECRET", "VERCEL_OIDC_TOKEN", "ENVBANK_VERCEL_TOKEN"}

// vercelAccept runs the disposable Preview acceptance through the configured
// workflow. Authorization and target checks happen before unlocking anything.
// It never approves, binds, imports or deletes; the owner does those steps.
func vercelAccept(auth *authFlags, manifestPath, planID string) error {
	if os.Getenv("ENVBANK_LIVE_ACCEPTANCE") != "1" {
		return errors.New("Vercel acceptance BLOCKED: EXPLICIT_AUTHORIZATION_REQUIRED (set ENVBANK_LIVE_ACCEPTANCE=1)")
	}
	for _, name := range vercelAcceptanceForbiddenEnvironment {
		if os.Getenv(name) != "" {
			return errors.New("Vercel acceptance BLOCKED: CREDENTIAL_ENVIRONMENT_FORBIDDEN")
		}
	}
	target, e := vercelworkflow.ParseAcceptanceTarget(os.Getenv("ENVBANK_VERCEL_ACCEPTANCE_TARGET"))
	if e != nil {
		return errors.New("Vercel acceptance BLOCKED: DISPOSABLE_TARGET_REQUIRED (ENVBANK_VERCEL_ACCEPTANCE_TARGET=disposable:team_ID/prj_ID/envbank-acceptance-NAME@envbank-acceptance-BRANCH)")
	}
	if planID == "" {
		return errors.New("Vercel acceptance BLOCKED: OWNER_APPROVED_PLAN_REQUIRED (--plan)")
	}
	document, e := loadBundleManifest(manifestPath)
	if e != nil {
		return e
	}
	if vercelworkflow.CheckAcceptanceManifest(document, target) != nil {
		return errors.New("Vercel acceptance BLOCKED: ACCEPTANCE_MANIFEST_NOT_DISPOSABLE")
	}
	backend, _, _, closeBackend, probe, e := openVercelBackendWith(auth, manifestPath, true)
	if e != nil {
		return e
	}
	defer closeBackend()
	ctx, stop := shutdownSignalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	receipt := (vercelworkflow.AcceptanceRunner{Backend: backend, Target: target, Probe: probe}).Run(ctx, planID)
	if e = json.NewEncoder(os.Stdout).Encode(receipt); e != nil {
		return errors.New("Vercel acceptance receipt could not be written")
	}
	if receipt.Result != "PASS" {
		return fmt.Errorf("Vercel acceptance BLOCKED: %s", receipt.Blocker)
	}
	return nil
}

// vercelAcceptProduction runs disposable Production promotion/rollback
// acceptance through the configured workflow and signed rollback path. Every
// authorization, credential-environment, target-string and manifest check
// happens before anything is unlocked. It never approves, binds, imports,
// creates, deletes or changes project settings.
func vercelAcceptProduction(auth *authFlags, manifestPath, planID string) error {
	if os.Getenv("ENVBANK_LIVE_ACCEPTANCE") != "1" {
		return errors.New("Vercel production acceptance BLOCKED: EXPLICIT_AUTHORIZATION_REQUIRED (set ENVBANK_LIVE_ACCEPTANCE=1)")
	}
	for _, name := range vercelAcceptanceForbiddenEnvironment {
		if os.Getenv(name) != "" {
			return errors.New("Vercel production acceptance BLOCKED: CREDENTIAL_ENVIRONMENT_FORBIDDEN")
		}
	}
	target, e := vercelworkflow.ParseProductionAcceptanceTarget(os.Getenv("ENVBANK_VERCEL_ACCEPTANCE_TARGET"))
	if e != nil {
		return errors.New("Vercel production acceptance BLOCKED: DISPOSABLE_PRODUCTION_TARGET_REQUIRED (ENVBANK_VERCEL_ACCEPTANCE_TARGET=disposable-production:team_ID/prj_ID/envbank-acceptance-NAME)")
	}
	if planID == "" {
		return errors.New("Vercel production acceptance BLOCKED: OWNER_APPROVED_PLAN_REQUIRED (--plan)")
	}
	document, e := loadBundleManifest(manifestPath)
	if e != nil {
		return e
	}
	if vercelworkflow.CheckProductionAcceptanceManifest(document, target) != nil {
		return errors.New("Vercel production acceptance BLOCKED: ACCEPTANCE_MANIFEST_NOT_DISPOSABLE")
	}
	backend, _, _, closeBackend, probe, e := openVercelBackendWith(auth, manifestPath, true)
	if e != nil {
		return e
	}
	defer closeBackend()
	ctx, stop := shutdownSignalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	// Health reuses the configured, owner-bound workflow health probe.
	receipt := (vercelworkflow.ProductionAcceptanceRunner{Backend: backend, Target: target, Probe: probe}).Run(ctx, planID)
	if e = json.NewEncoder(os.Stdout).Encode(receipt); e != nil {
		return errors.New("Vercel production acceptance receipt could not be written")
	}
	if receipt.Result != "PASS" {
		return fmt.Errorf("Vercel production acceptance BLOCKED: %s", receipt.Blocker)
	}
	return nil
}

func vercelMCP(args []string) error {
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "fixed Vercel bundle manifest; approval is separately signed by owner")
	rotationPolicy := fs.String("rotation-policy", "", "standing rotation approval id; enables envbank_rotation_run for the manifest's automatic credentials")
	source := fs.String("source-deployment", "", "Preview/custom scopes: deployment rotations rebuild")
	auth := addAuthFlags(fs)
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *manifest == "" || fs.NArg() != 0 {
		return errors.New("configured MCP requires --manifest and auth flags")
	}
	if *rotationPolicy == "" {
		backend, _, _, closeBackend, e := openVercelBackend(auth, *manifest)
		if e != nil {
			return e
		}
		defer closeBackend()
		return (mcpserver.Server{Backend: backend}).Serve(context.Background(), os.Stdin, os.Stdout)
	}
	document, e := loadBundleManifest(*manifest)
	if e != nil {
		return e
	}
	runners := map[string]*rotationrun.Runner{}
	var closers []func()
	defer func() {
		for _, closeRunner := range closers {
			closeRunner()
		}
	}()
	for _, name := range sortedCredentialNames(document) {
		providerName := document.Manifest.Credentials[name].Provider
		if _, ok := runners[providerName]; ok {
			continue
		}
		runner, closeRunner, e := openRotationRunner(auth, *manifest, *rotationPolicy, *source, providerName)
		if e != nil {
			return e
		}
		closers = append(closers, closeRunner)
		runners[providerName] = runner
	}
	if len(runners) == 0 {
		return errors.New("manifest declares no automatic credentials to rotate")
	}
	var inner mcpserver.Backend
	for _, runner := range runners {
		inner = runner.Engine.Deployer.(*vercelworkflow.RotationDeployer).Backend
		break
	}
	return (mcpserver.Server{Backend: &rotationrun.MCPBackend{Inner: inner, Runners: runners, PolicyID: *rotationPolicy}}).Serve(context.Background(), os.Stdin, os.Stdout)
}
