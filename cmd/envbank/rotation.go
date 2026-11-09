package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/ownerapproval"
	"github.com/GeorgeQLe/envbank/internal/provider/neon"
	"github.com/GeorgeQLe/envbank/internal/provider/stripe"
	"github.com/GeorgeQLe/envbank/internal/rotation"
	"github.com/GeorgeQLe/envbank/internal/rotationrun"
	"github.com/GeorgeQLe/envbank/internal/secure"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
	"github.com/GeorgeQLe/envbank/internal/vercelworkflow"
)

// rotateCredentialStore holds provider control credentials (the Neon or
// Stripe API key EnvBank itself uses) in the Keychain, scoped to one vault
// and bundle. Tests replace it.
var rotateCredentialStore keychain.Store = keychain.SystemStore{}

func rotateCredentialService(providerName string) string {
	return "com.envbank.provider." + providerName
}

func rotateCredentialAccount(vaultID, bundleID string) string {
	digest := sha256.Sum256([]byte("envbank.rotation.v1\x00" + vaultID + "\x00" + bundleID))
	return "v1:" + hex.EncodeToString(digest[:])
}

// rotateProviders maps the manifest provider names the trigger can rotate
// to their adapters. The control credential is wiped by the returned closer.
func openCredentialAdapter(providerName string, control []byte) (lifecycle.CredentialAdapter, func(), error) {
	switch providerName {
	case "neon":
		adapter, err := neon.New(control, neon.Options{})
		if err != nil {
			return nil, func() {}, err
		}
		return adapter, adapter.Close, nil
	case "stripe":
		adapter, err := stripe.New(control, stripe.Options{})
		if err != nil {
			return nil, func() {}, err
		}
		return adapter, adapter.Close, nil
	}
	return nil, func() {}, fmt.Errorf("provider %q has no rotation adapter", providerName)
}

func loadCredentialAdapter(vaultID, bundleID, providerName string) (lifecycle.CredentialAdapter, func(), error) {
	control, err := rotateCredentialStore.Get(rotateCredentialService(providerName), rotateCredentialAccount(vaultID, bundleID), "Use the "+providerName+" control credential for rotation")
	if err != nil {
		return nil, func() {}, fmt.Errorf("%s control credential unavailable; owner must run envbank rotation bind-provider --provider %s", providerName, providerName)
	}
	defer clearBytes(control)
	return openCredentialAdapter(providerName, control)
}

func rotationCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("rotation requires bind-provider, approve, bind, plan, run or status")
	}
	switch args[0] {
	case "bind-provider":
		return rotateBindProvider(args[1:])
	case "approve":
		return rotateApprove(args[1:])
	case "bind":
		return rotateBind(args[1:])
	case "plan":
		return rotatePlanOrRun(args[1:], false)
	case "run":
		return rotatePlanOrRun(args[1:], true)
	case "status":
		return rotateStatus(args[1:])
	}
	return fmt.Errorf("unknown rotation subcommand %q", args[0])
}

// rotateBindProvider stores a provider control credential read from trusted
// stdin, after proving it identifies an account. The identity is printed so
// the owner can check it against the standing approval; the value is not.
func rotateBindProvider(args []string) error {
	fs := flag.NewFlagSet("rotation bind-provider", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	providerName := fs.String("provider", "", "manifest provider name (neon, stripe)")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *providerName == "" || fs.NArg() != 0 {
		return errors.New("rotation bind-provider requires --manifest PATH and --provider NAME")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	if isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("provide the control credential on stdin, never as an argument")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		return errors.New("control credential could not be read")
	}
	control := []byte(strings.TrimSpace(string(raw)))
	clearBytes(raw)
	defer clearBytes(control)
	adapter, closeAdapter, err := openCredentialAdapter(*providerName, control)
	if err != nil {
		return err
	}
	defer closeAdapter()
	identity, err := adapter.Identify(context.Background())
	if err != nil || identity.Provider != *providerName {
		return errors.New("control credential did not identify a " + *providerName + " account")
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	if err := rotateCredentialStore.Put(rotateCredentialService(*providerName), rotateCredentialAccount(api.Config.VaultID, document.Manifest.Bundle), control); err != nil {
		return errors.New("verified control credential could not be stored in Keychain")
	}
	fmt.Printf("bundle: %s\nprovider: %s\nidentity: %s\nstatus: bound\n", document.Manifest.Bundle, *providerName, identity.ID)
	return nil
}

// rotateApprove creates a standing rotation approval: one owner signature
// that authorizes every rotation of the manifest's automatic credentials
// into its Vercel target until the policy expires.
func rotateApprove(args []string) error {
	fs := flag.NewFlagSet("rotation approve", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	policyID := fs.String("policy", "", "standing policy id to create or renew")
	health := fs.String("health-path", "", "application health path checked on every deployment")
	expiry := fs.Duration("expiry", 30*24*time.Hour, "approval lifetime (at most 90 days)")
	grace := fs.Duration("grace", 0, "time the retired credential stays valid after the new one is healthy (default: 15m staging, 24h production)")
	retries := fs.Int("retries", 2, "retry budget per rotation step (1-3)")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *policyID == "" || !vercelworkflow.ValidHealthPath(*health) || fs.NArg() != 0 {
		return errors.New("rotation approve requires --manifest PATH, --policy ID and --health-path /path")
	}
	if strings.HasPrefix(*policyID, "vercel-") {
		return errors.New("standing policy ids must not use the per-plan vercel- prefix")
	}
	backend, api, secrets, closeBackend, err := openVercelBackend(auth, *manifestPath)
	if err != nil {
		return err
	}
	defer closeBackend()
	document := backend.Document
	scope := backend.Adapter.Scope()
	ctx := context.Background()
	environment, defaultGrace := "staging", 15*time.Minute
	if scope.Environment == "production" {
		environment, defaultGrace = "production", 24*time.Hour
	}
	if *grace == 0 {
		*grace = defaultGrace
	}
	identities := map[string]string{"vercel": scope.TeamID + ":" + scope.ProjectID}
	classes := []string{"vercel-environment-secret"}
	credentials := sortedCredentialNames(document)
	if len(credentials) == 0 {
		return errors.New("manifest declares no automatic credentials to rotate")
	}
	review := fmt.Sprintf("Standing rotation approval %s\nManifest: %s\nVercel: %s %s %q\n", *policyID, document.Digest, scope.ProjectID, scope.Environment, scope.GitBranch)
	for _, name := range credentials {
		credential := document.Manifest.Credentials[name]
		if _, seen := identities[credential.Provider]; !seen {
			adapter, closeAdapter, err := loadCredentialAdapter(api.Config.VaultID, document.Manifest.Bundle, credential.Provider)
			if err != nil {
				return err
			}
			identity, err := adapter.Identify(ctx)
			closeAdapter()
			if err != nil || identity.Provider != credential.Provider {
				return fmt.Errorf("%s control credential did not identify an account", credential.Provider)
			}
			identities[credential.Provider] = identity.ID
		}
		if !containsString(classes, credential.Type) {
			classes = append(classes, credential.Type)
		}
		review += fmt.Sprintf("  %s: %s/%s -> record %s (account %s)", name, credential.Provider, credential.Type, credential.Record, identities[credential.Provider])
		if len(credential.Alternates) > 0 {
			review += " alternating " + strings.Join(credential.Alternates, ", ")
		}
		review += "\n"
	}
	pin := backend.OwnerApprovalKey
	if !ownerapproval.ValidPublicKey(pin) {
		return errors.New("hardware owner approval key is not enrolled; the owner must run envbank owner-approval enroll")
	}
	signer, err := vercelOwnerSigner(pin)
	if err != nil {
		return errors.New("hardware owner approval unavailable on this host; standing approval refused")
	}
	prompt := review + fmt.Sprintf("Approve agents to create, deploy, verify and revoke these credentials without further confirmation for %s, with a %s grace period? Type approve: ", *expiry, *grace)
	if err := vercelOwnerConfirmation(prompt); err != nil {
		return err
	}
	signedAt := time.Now().UTC().Truncate(time.Second)
	policy := lifecycle.AutomationPolicy{Version: lifecycle.PolicyVersion, ID: *policyID, VaultID: api.Config.VaultID, Bundle: document.Manifest.Bundle, ManifestDigest: document.Digest, Environment: environment, ProviderIdentities: identities, CredentialClasses: classes, Operations: []string{"create", "stage", "activate", "verify", "rollback", "revoke"}, Targets: []lifecycle.TargetPolicy{{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}}, Schedule: "on-demand", HealthChecks: []string{*health}, GracePeriod: grace.String(), Rollback: "previous-deployment", RetryBudget: *retries, ExpiresAt: signedAt.Add(*expiry).Format(time.RFC3339), ApprovingDevice: api.Config.DeviceID, DeploymentScopeFingerprint: scope.Fingerprint(), DeploymentHealthPath: *health}
	private, err := secure.Decode(secrets.SigningPrivate)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return errors.New("approval signing key unavailable")
	}
	defer clearBytes(private)
	reason := fmt.Sprintf("approve EnvBank standing rotation %s for %s %s", *policyID, scope.ProjectID, scope.Environment)
	if err := ownerapproval.Approve(ctx, &policy, ed25519.PrivateKey(private), signer, pin, signedAt, reason); err != nil {
		return errors.New("hardware owner approval was not completed; nothing was stored")
	}
	store := backend.Store.(*vercelworkflow.VaultStore)
	expected := int64(0)
	if object, err := api.GetObject(store.VaultKey, vaultobject.KindAutomationPolicy, policy.ID); err == nil {
		expected = object.Revision
	}
	if _, err := store.Lifecycle.SavePolicy(ctx, policy, expected); err != nil {
		return errors.New("standing approval could not be stored")
	}
	fmt.Printf("policy: %s\ncredentials: %s\nexpires: %s\nstatus: approved\n", policy.ID, strings.Join(credentials, ", "), policy.ExpiresAt)
	return nil
}

func sortedCredentialNames(document *contract.Document) []string {
	names := []string{}
	for name, credential := range document.Manifest.Credentials {
		if credential.Mode == "automatic" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// openRotationRunner assembles the engine for one credential's provider.
func openRotationRunner(auth *authFlags, manifestPath, policyID, source, providerName string) (*rotationrun.Runner, func(), error) {
	backend, api, secrets, closeBackend, err := openVercelBackend(auth, manifestPath)
	if err != nil {
		return nil, func() {}, err
	}
	backend.StandingPolicyID = policyID
	adapter, closeAdapter, err := loadCredentialAdapter(api.Config.VaultID, backend.Document.Manifest.Bundle, providerName)
	if err != nil {
		closeBackend()
		return nil, func() {}, err
	}
	private, err := secure.Decode(secrets.SigningPrivate)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		closeAdapter()
		closeBackend()
		return nil, func() {}, errors.New("device signing key unavailable")
	}
	store := backend.Store.(*vercelworkflow.VaultStore)
	vault := &rotationrun.Vault{API: api, VaultID: api.Config.VaultID, VaultKey: store.VaultKey}
	pin := api.Config.OwnerApprovalKey()
	engine := &rotation.Engine{Store: store.Lifecycle, Deployer: &vercelworkflow.RotationDeployer{Backend: backend, SourceDeploymentID: source}, Credentials: adapter, Records: &rotationrun.RecordStore{Vault: vault, Document: backend.Document}, VaultID: api.Config.VaultID, DeviceID: api.Config.DeviceID, DevicePrivate: ed25519.PrivateKey(private), PolicyKey: backend.TrustedPolicyKey, OwnerVerify: func(policy lifecycle.AutomationPolicy, now time.Time) error {
		return ownerapproval.Verify(policy, pin, now)
	}}
	runner := &rotationrun.Runner{Engine: engine, Vault: vault, Document: backend.Document}
	return runner, func() {
		clearBytes(private)
		closeAdapter()
		closeBackend()
	}, nil
}

func credentialProvider(manifestPath, name string) (string, error) {
	document, err := loadBundleManifest(manifestPath)
	if err != nil {
		return "", err
	}
	credential, ok := document.Manifest.Credentials[name]
	if !ok {
		return "", errors.New("manifest does not declare that credential")
	}
	return credential.Provider, nil
}

func rotateBind(args []string) error {
	fs := flag.NewFlagSet("rotation bind", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	name := fs.String("credential", "", "manifest credential name")
	current := fs.String("current-id", "", "upstream credential id currently backing the record (for example role:PROJECT/BRANCH/ROLE)")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *name == "" || *current == "" || fs.NArg() != 0 {
		return errors.New("rotation bind requires --manifest PATH, --credential NAME and --current-id ID")
	}
	providerName, err := credentialProvider(*manifestPath, *name)
	if err != nil {
		return err
	}
	runner, closeRunner, err := openRotationRunner(auth, *manifestPath, "", "", providerName)
	if err != nil {
		return err
	}
	defer closeRunner()
	binding, err := runner.Bind(context.Background(), *name, *current)
	if err != nil {
		return err
	}
	fmt.Printf("credential: %s\nrecord: %s\ncurrent: %s\nrecord revision: %d\nstatus: bound\n", *name, binding.Record, binding.CredentialID, binding.RecordRevision)
	return nil
}

func rotatePlanOrRun(args []string, run bool) error {
	verb := "plan"
	if run {
		verb = "run"
	}
	fs := flag.NewFlagSet("rotation "+verb, flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	policyID := fs.String("policy", "", "standing policy id")
	name := fs.String("credential", "", "manifest credential name to rotate")
	operationID := fs.String("operation", "", "existing rotation operation to resume (run only)")
	source := fs.String("source-deployment", "", "Preview/custom scopes: deployment to rebuild")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *policyID == "" || fs.NArg() != 0 || (*name == "") == (*operationID == "") || (!run && *operationID != "") {
		return fmt.Errorf("rotation %s requires --manifest PATH, --policy ID and exactly one of --credential NAME or --operation ID", verb)
	}
	ctx := context.Background()
	var providerName string
	if *name != "" {
		resolved, err := credentialProvider(*manifestPath, *name)
		if err != nil {
			return err
		}
		providerName = resolved
	} else {
		document, err := loadBundleManifest(*manifestPath)
		if err != nil {
			return err
		}
		// Resuming needs the operation's provider; read it with the vault
		// store before opening any provider adapter.
		resolved, err := operationProvider(auth, *manifestPath, *operationID)
		if err != nil {
			return err
		}
		if !providerDeclared(document, resolved) {
			return errors.New("operation provider is not declared by the manifest")
		}
		providerName = resolved
	}
	runner, closeRunner, err := openRotationRunner(auth, *manifestPath, *policyID, *source, providerName)
	if err != nil {
		return err
	}
	defer closeRunner()
	id := *operationID
	if *name != "" {
		operation, err := runner.Plan(ctx, *name, *policyID)
		if err != nil {
			return err
		}
		id = operation.ID
		if !run {
			printRotation(operation)
			return nil
		}
	}
	operation, err := runner.Run(ctx, id)
	printRotation(operation)
	return err
}

func providerDeclared(document *contract.Document, providerName string) bool {
	for _, credential := range document.Manifest.Credentials {
		if credential.Provider == providerName {
			return true
		}
	}
	return false
}

func operationProvider(auth *authFlags, manifestPath, operationID string) (string, error) {
	backend, _, _, closeBackend, err := openVercelBackend(auth, manifestPath)
	if err != nil {
		return "", err
	}
	defer closeBackend()
	store := backend.Store.(*vercelworkflow.VaultStore)
	operation, _, err := store.Lifecycle.LoadOperation(context.Background(), operationID)
	if err != nil {
		return "", errors.New("rotation operation unavailable")
	}
	return operation.Provider, nil
}

func rotateStatus(args []string) error {
	fs := flag.NewFlagSet("rotation status", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	operationID := fs.String("operation", "", "rotation operation id")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *operationID == "" || fs.NArg() != 0 {
		return errors.New("rotation status requires --manifest PATH and --operation ID")
	}
	backend, _, _, closeBackend, err := openVercelBackend(auth, *manifestPath)
	if err != nil {
		return err
	}
	defer closeBackend()
	store := backend.Store.(*vercelworkflow.VaultStore)
	operation, _, err := store.Lifecycle.LoadOperation(context.Background(), *operationID)
	if err != nil {
		return errors.New("rotation operation unavailable")
	}
	printRotation(operation)
	chain, err := store.Lifecycle.LoadEvidence(context.Background(), *operationID, backend.TrustedPolicyKey)
	if err != nil {
		return err
	}
	fmt.Println("evidence:")
	for _, evidence := range chain {
		fmt.Printf("  %d %s %s/%s\n", evidence.Sequence, evidence.At, evidence.Stage, evidence.Code)
	}
	return nil
}

// printRotation prints identifiers and state only; records are named, never
// shown.
func printRotation(operation lifecycle.Operation) {
	if operation.ID == "" {
		return
	}
	fmt.Printf("operation: %s\nstate: %s\nprovider: %s\ncredential class: %s\nrecord: %s (revision %d -> %d)\nprevious credential: %s\n", operation.ID, operation.State, operation.Provider, operation.CredentialClass, operation.DestinationRecord, operation.PreviousRecordRevision, operation.NewRecordRevision, operation.PreviousCredentialID)
	if operation.NewCredentialID != "" {
		fmt.Printf("new credential: %s\n", operation.NewCredentialID)
	}
	if operation.DeploymentID != "" {
		fmt.Printf("deployment: %s\n", operation.DeploymentID)
	}
	if operation.GraceEndsAt != "" {
		fmt.Printf("grace ends: %s\n", operation.GraceEndsAt)
	}
	if operation.Attempts > 0 {
		fmt.Printf("attempts: %d\n", operation.Attempts)
	}
}
