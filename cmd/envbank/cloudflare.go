package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/provider"
	cloudflareprovider "github.com/GeorgeQLe/envbank/internal/provider/cloudflare"
	"github.com/GeorgeQLe/envbank/internal/rollout"
	"github.com/mattn/go-isatty"
)

var cloudflareCredentialStore keychain.Store = keychain.SystemStore{}
var cloudflareAPIOptions = func() cloudflareprovider.Options { return cloudflareprovider.Options{} }
var cloudflareConfirmation rollout.ConfirmFunc = confirmCloudflareAction

func cloudflareCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("cloudflare subcommand is required (supported: bind, plan, apply, resume, verify, promote, rollback)")
	}
	switch args[0] {
	case "bind":
		return cloudflareBind(args[1:])
	case "plan":
		return cloudflarePlan(args[1:])
	case "apply":
		return cloudflareApply(args[1:])
	case "resume":
		return cloudflareResume(args[1:])
	case "verify":
		return cloudflareVerify(args[1:])
	case "promote":
		return cloudflarePromote(args[1:])
	case "rollback":
		return cloudflareRollback(args[1:])
	default:
		return fmt.Errorf("unknown cloudflare subcommand %q", args[0])
	}
}

func cloudflareBind(args []string) error {
	fs := flag.NewFlagSet("cloudflare bind", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("cloudflare bind requires --manifest PATH and no positional arguments")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	target, providerTarget, err := cloudflareprovider.TargetForManifest(document)
	if err != nil {
		return err
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	token, err := readCloudflareToken(os.Stdin)
	if err != nil {
		return err
	}
	defer clearBytes(token)
	remote, err := cloudflareprovider.New(token, cloudflareAPIOptions())
	if err != nil {
		return err
	}
	defer remote.Close()
	adapter := &cloudflareprovider.Adapter{API: remote, Target: target}
	if _, err := adapter.Identity(context.Background()); err != nil {
		return providerSafeError("identity", err)
	}
	state, err := adapter.Inspect(context.Background(), providerTarget)
	if err != nil {
		return providerSafeError("inspect", err)
	}
	account, err := cloudflareprovider.CredentialAccount(api.Config.VaultID, document.Manifest.Bundle)
	if err != nil {
		return err
	}
	if err := cloudflareCredentialStore.Put(cloudflareprovider.CredentialService, account, token); err != nil {
		return errors.New("verified Cloudflare API token could not be stored in Keychain")
	}
	fmt.Printf("bundle: %s\nprovider: cloudflare\naccount id: %s\nzone id: %s\nworker script: %s\nprior version: %s\nstatus: bound\n",
		document.Manifest.Bundle, target.AccountID, target.ZoneID, target.ScriptName, state.Revision)
	return nil
}

func cloudflarePlan(args []string) error {
	fs := flag.NewFlagSet("cloudflare plan", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("cloudflare plan requires --manifest PATH and no positional arguments")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	target, providerTarget, err := cloudflareprovider.TargetForManifest(document)
	if err != nil {
		return err
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	snapshot, snapshotRevision, err := bundle.LoadSnapshot(api, vaultKey, document.Manifest.Bundle)
	if err != nil {
		return err
	}
	adapter, closeAdapter, err := cloudflareAdapter(api.Config.VaultID, document.Manifest.Bundle, target, nil)
	if err != nil {
		return err
	}
	defer closeAdapter()
	input, err := cloudflareprovider.BuildPlanInput(document, snapshot, snapshotRevision, providerTarget)
	if err != nil {
		return err
	}
	plan, err := (&rollout.Engine{Adapter: adapter, Store: &rollout.EncryptedStore{API: api, VaultKey: vaultKey}}).
		Plan(context.Background(), input)
	if err != nil {
		return err
	}
	fmt.Printf("plan: %s\nbundle: %s\nprovider: cloudflare\naccount id: %s\nzone id: %s\nworker script: %s\nprior version: %s\nexpires: %s\nbindings:\n",
		plan.ID(), plan.Bundle, target.AccountID, target.ZoneID, target.ScriptName, plan.ProviderRevision, plan.ExpiresAt)
	for _, item := range plan.Names {
		fmt.Printf("  %s: desired=%s current=%s\n", item.Name, item.Desired, item.State)
	}
	fmt.Println("status: planned; no values read from Cloudflare and no provider changes made")
	return nil
}

func cloudflareApply(args []string) error {
	fs := flag.NewFlagSet("cloudflare apply", flag.ContinueOnError)
	planID := fs.String("plan", "", "encrypted provider plan ID")
	modulePath := fs.String("worker-module", "", "compiled Worker module")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planID == "" || *modulePath == "" || fs.NArg() != 0 {
		return errors.New("cloudflare apply requires --plan PLAN_ID --worker-module PATH")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	plan, _, err := store.LoadPlan(context.Background(), *planID)
	if err != nil {
		return err
	}
	module, err := readWorkerModule(*modulePath)
	if err != nil {
		return err
	}
	defer clearBytes(module)
	target, err := targetFromRollout(plan.Target)
	if err != nil {
		return err
	}
	adapter, closeAdapter, err := cloudflareAdapter(api.Config.VaultID, plan.Bundle, target, module)
	if err != nil {
		return err
	}
	defer closeAdapter()
	operation, err := (&rollout.Engine{Adapter: adapter, Store: store}).Apply(context.Background(), *planID, cloudflareConfirmation)
	printCloudflareOperation(operation)
	return err
}

func cloudflareResume(args []string) error {
	fs := flag.NewFlagSet("cloudflare resume", flag.ContinueOnError)
	operationID := fs.String("operation", "", "encrypted rollout operation ID")
	modulePath := fs.String("worker-module", "", "compiled Worker module")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operationID == "" || *modulePath == "" || fs.NArg() != 0 {
		return errors.New("cloudflare resume requires --operation OPERATION_ID --worker-module PATH")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	operation, _, err := store.LoadOperation(context.Background(), *operationID)
	if err != nil {
		return err
	}
	module, err := readWorkerModule(*modulePath)
	if err != nil {
		return err
	}
	defer clearBytes(module)
	target, err := targetFromRollout(operation.Target)
	if err != nil {
		return err
	}
	adapter, closeAdapter, err := cloudflareAdapter(api.Config.VaultID, operation.Bundle, target, module)
	if err != nil {
		return err
	}
	defer closeAdapter()
	operation, err = (&rollout.Engine{Adapter: adapter, Store: store}).Resume(context.Background(), *operationID)
	printCloudflareOperation(operation)
	return err
}

func cloudflareVerify(args []string) error {
	fs := flag.NewFlagSet("cloudflare verify", flag.ContinueOnError)
	operationID := fs.String("operation", "", "encrypted rollout operation ID")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operationID == "" || fs.NArg() != 0 {
		return errors.New("cloudflare verify requires --operation OPERATION_ID")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	operation, _, err := store.LoadOperation(context.Background(), *operationID)
	if err != nil {
		return err
	}
	plan, _, err := store.LoadPlan(context.Background(), operation.PlanID)
	if err != nil || !rollout.OperationMatchesPlan(operation, plan) {
		return errors.New("Cloudflare operation does not match its encrypted plan")
	}
	if err := store.ValidateSnapshot(context.Background(), plan); err != nil {
		return err
	}
	target, err := targetFromRollout(operation.Target)
	if err != nil {
		return err
	}
	adapter, closeAdapter, err := cloudflareAdapter(api.Config.VaultID, operation.Bundle, target, nil)
	if err != nil {
		return err
	}
	defer closeAdapter()
	for _, item := range operation.Actions {
		if item.WriteEvidence == nil {
			return errors.New("Cloudflare operation has no staged version evidence")
		}
		expected := expectedCloudflarePresence(item.Action.Operation)
		evidence, err := adapter.Verify(context.Background(), provider.VerifyRequest{Target: provider.Target{
			ProjectID: operation.Target.ProjectID, EnvironmentID: operation.Target.EnvironmentID,
			ServiceIDs: operation.Target.ServiceIDs}, Service: item.Action.Service, ServiceID: item.Action.ServiceID,
			Name: item.Action.Name, ProviderOperationID: item.WriteEvidence.ProviderOperationID,
			ExpectedPresence: expected})
		if err != nil || evidence.Presence != expected {
			return errors.New("Cloudflare staged version binding verification failed")
		}
	}
	printCloudflareOperation(operation)
	return nil
}

func cloudflarePromote(args []string) error {
	fs := flag.NewFlagSet("cloudflare promote", flag.ContinueOnError)
	operationID := fs.String("operation", "", "encrypted rollout operation ID")
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operationID == "" || *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("cloudflare promote requires --operation OPERATION_ID --manifest PATH")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	operation, revision, err := store.LoadOperation(context.Background(), *operationID)
	if err != nil {
		return err
	}
	plan, _, err := store.LoadPlan(context.Background(), operation.PlanID)
	if err != nil || !rollout.OperationMatchesPlan(operation, plan) || document.Digest != operation.ManifestDigest ||
		document.Manifest.Bundle != operation.Bundle || operation.Status != rollout.StatusReady {
		return errors.New("Cloudflare promotion evidence does not match the plan, manifest, or ready operation")
	}
	if err := store.ValidateSnapshot(context.Background(), plan); err != nil {
		return err
	}
	target, err := targetFromRollout(operation.Target)
	if err != nil {
		return err
	}
	adapter, closeAdapter, err := cloudflareAdapter(api.Config.VaultID, operation.Bundle, target, nil)
	if err != nil {
		return err
	}
	defer closeAdapter()
	state, err := adapter.Inspect(context.Background(), provider.Target{ProjectID: operation.Target.ProjectID,
		EnvironmentID: operation.Target.EnvironmentID, ServiceIDs: operation.Target.ServiceIDs})
	if err != nil || state.Revision != operation.ProviderRevision {
		return errors.New("Cloudflare deployed version changed after planning")
	}
	stagedVersion, err := stagedVersion(operation)
	if err != nil {
		return err
	}
	for _, item := range operation.Actions {
		expected := expectedCloudflarePresence(item.Action.Operation)
		evidence, verifyErr := adapter.Verify(context.Background(), provider.VerifyRequest{Target: provider.Target{
			ProjectID: operation.Target.ProjectID, EnvironmentID: operation.Target.EnvironmentID,
			ServiceIDs: operation.Target.ServiceIDs}, Service: item.Action.Service, ServiceID: item.Action.ServiceID,
			Name: item.Action.Name, ProviderOperationID: stagedVersion, ExpectedPresence: expected})
		if verifyErr != nil || evidence.Presence != expected {
			return errors.New("Cloudflare staged version no longer matches the plan")
		}
	}
	healthChecks := document.Manifest.Targets[cloudflareprovider.ProviderName].HealthChecks
	if err := validateCloudflareHealthChecks(api, healthChecks); err != nil {
		return err
	}
	if err := cloudflareConfirmation(context.Background(), rollout.Confirmation{Kind: "promote", Provider: "cloudflare",
		Bundle: operation.Bundle, ActionCount: len(operation.Actions), Destructive: true}); err != nil {
		return errors.New("Cloudflare promotion cancelled")
	}
	deploymentID, err := adapter.Promote(context.Background(), stagedVersion)
	if err != nil {
		return providerSafeError("promote", err)
	}
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	operation.Status = rollout.StatusPromoted
	operation.DeploymentID, operation.DeployedVersion = deploymentID, stagedVersion
	operation.PromotedAt, operation.UpdatedAt = now, now
	revision, err = store.SaveOperation(context.Background(), operation, revision)
	if err != nil {
		return fmt.Errorf("Cloudflare version was promoted but evidence could not be saved: %w", err)
	}
	if err := runCloudflareHealthChecks(context.Background(), api, healthChecks); err != nil {
		rollbackID, rollbackErr := adapter.Rollback(context.Background(), operation.ProviderRevision)
		if rollbackErr != nil {
			return errors.New("Cloudflare health checks failed and automatic rollback failed")
		}
		operation.Status, operation.RollbackID = rollout.StatusRolledBack, rollbackID
		operation.RolledBackAt, operation.UpdatedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
		if _, saveErr := store.SaveOperation(context.Background(), operation, revision); saveErr != nil {
			return errors.New("Cloudflare health checks failed; rollback succeeded but evidence could not be saved")
		}
		return errors.New("Cloudflare health checks failed; prior version was restored")
	}
	printCloudflareOperation(operation)
	return nil
}

func cloudflareRollback(args []string) error {
	fs := flag.NewFlagSet("cloudflare rollback", flag.ContinueOnError)
	operationID := fs.String("operation", "", "encrypted rollout operation ID")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operationID == "" || fs.NArg() != 0 {
		return errors.New("cloudflare rollback requires --operation OPERATION_ID")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	operation, revision, err := store.LoadOperation(context.Background(), *operationID)
	if err != nil || operation.ProviderRevision == "" {
		return errors.New("Cloudflare operation has no prior version evidence")
	}
	target, err := targetFromRollout(operation.Target)
	if err != nil {
		return err
	}
	adapter, closeAdapter, err := cloudflareAdapter(api.Config.VaultID, operation.Bundle, target, nil)
	if err != nil {
		return err
	}
	defer closeAdapter()
	plan, _, err := store.LoadPlan(context.Background(), operation.PlanID)
	if err != nil || !rollout.OperationMatchesPlan(operation, plan) {
		return errors.New("Cloudflare rollback operation does not match its encrypted plan")
	}
	if err := store.ValidateSnapshot(context.Background(), plan); err != nil {
		return err
	}
	state, err := adapter.Inspect(context.Background(), provider.Target{ProjectID: operation.Target.ProjectID,
		EnvironmentID: operation.Target.EnvironmentID, ServiceIDs: operation.Target.ServiceIDs})
	if err != nil {
		return providerSafeError("inspect", err)
	}
	if operation.Status == rollout.StatusPromoted && state.Revision != operation.DeployedVersion {
		return errors.New("Cloudflare deployed version changed after promotion")
	}
	if err := cloudflareConfirmation(context.Background(), rollout.Confirmation{Kind: "rollback", Provider: "cloudflare",
		Bundle: operation.Bundle, ActionCount: 1, Destructive: true}); err != nil {
		return errors.New("Cloudflare rollback cancelled")
	}
	rollbackID, err := adapter.Rollback(context.Background(), operation.ProviderRevision)
	if err != nil {
		return providerSafeError("rollback", err)
	}
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	operation.Status, operation.RollbackID, operation.RolledBackAt, operation.UpdatedAt =
		rollout.StatusRolledBack, rollbackID, now, now
	if _, err := store.SaveOperation(context.Background(), operation, revision); err != nil {
		return fmt.Errorf("Cloudflare rollback succeeded but evidence could not be saved: %w", err)
	}
	printCloudflareOperation(operation)
	return nil
}

func cloudflareAdapter(vaultID, bundleID string, target cloudflareprovider.Target,
	module []byte) (*cloudflareprovider.Adapter, func(), error) {
	account, err := cloudflareprovider.CredentialAccount(vaultID, bundleID)
	if err != nil {
		return nil, nil, err
	}
	token, err := cloudflareprovider.LoadCredential(cloudflareCredentialStore, account)
	if err != nil {
		return nil, nil, err
	}
	options := cloudflareAPIOptions()
	options.Module = module
	remote, err := cloudflareprovider.New(token, options)
	clearBytes(token)
	if err != nil {
		return nil, nil, err
	}
	return &cloudflareprovider.Adapter{API: remote, Target: target}, remote.Close, nil
}

func targetFromRollout(target rollout.TargetBinding) (cloudflareprovider.Target, error) {
	if len(target.ServiceIDs) != 1 {
		return cloudflareprovider.Target{}, errors.New("Cloudflare rollout target must contain one Worker script")
	}
	for name, id := range target.ServiceIDs {
		if name != id {
			return cloudflareprovider.Target{}, errors.New("Cloudflare Worker script binding is invalid")
		}
		return cloudflareprovider.Target{AccountID: target.ProjectID, ZoneID: target.EnvironmentID, ScriptName: name}, nil
	}
	return cloudflareprovider.Target{}, errors.New("Cloudflare Worker script binding is missing")
}

func readCloudflareToken(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("Cloudflare API token could not be read from trusted stdin")
	}
	token := bytes.TrimSpace(raw)
	if len(token) < 8 || bytes.IndexAny(token, "\r\n\x00") >= 0 {
		clearBytes(raw)
		return nil, errors.New("Cloudflare API token is invalid")
	}
	result := append([]byte(nil), token...)
	clearBytes(raw)
	return result, nil
}

func readWorkerModule(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Worker module: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (20<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 20<<20 {
		clearBytes(raw)
		return nil, errors.New("compiled Worker module must be between 1 byte and 20 MiB")
	}
	return raw, nil
}

func stagedVersion(operation rollout.Operation) (string, error) {
	version := ""
	for _, item := range operation.Actions {
		if item.WriteEvidence == nil || item.WriteEvidence.ProviderOperationID == "" {
			return "", errors.New("Cloudflare operation has incomplete staged version evidence")
		}
		if version == "" {
			version = item.WriteEvidence.ProviderOperationID
		} else if version != item.WriteEvidence.ProviderOperationID {
			return "", errors.New("Cloudflare operation contains multiple staged versions")
		}
	}
	return version, nil
}

func confirmCloudflareAction(_ context.Context, request rollout.Confirmation) error {
	if request.Provider != cloudflareprovider.ProviderName ||
		(!isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd())) {
		return errors.New("Cloudflare action confirmation requires an interactive terminal")
	}
	label := request.Kind
	if label != "" {
		label = strings.ToUpper(label[:1]) + label[1:]
	}
	fmt.Fprintf(os.Stderr, "%s Cloudflare Worker version for %s? Type %s: ",
		label, request.Bundle, request.Kind)
	var response string
	if _, err := fmt.Fscanln(os.Stdin, &response); err != nil || response != request.Kind {
		return errors.New("Cloudflare action confirmation was declined")
	}
	return nil
}

func runCloudflareHealthChecks(ctx context.Context, api *client.API, checks []contract.HealthCheck) error {
	if err := validateCloudflareHealthChecks(api, checks); err != nil {
		return err
	}
	for _, check := range checks {
		duration, _ := time.ParseDuration(check.MinimumDuration)
		method := check.Method
		if method == "" {
			method = http.MethodGet
		}
		for attempt := 0; attempt < check.Successes; attempt++ {
			if attempt > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(duration / time.Duration(check.Successes-1)):
				}
			}
			request, _ := http.NewRequestWithContext(ctx, method, check.URL, nil)
			if api.Access != nil {
				request.Header.Set("CF-Access-Client-Id", api.Access.ClientID)
				request.Header.Set("CF-Access-Client-Secret", api.Access.ClientSecret)
			}
			response, err := (&http.Client{Timeout: 15 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return client.ErrAuthenticatedRedirect }}).Do(request)
			if err != nil {
				return errors.New("Cloudflare health check request failed")
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode != check.ExpectedStatus {
				return errors.New("Cloudflare health check returned an unexpected status")
			}
		}
	}
	return nil
}

func validateCloudflareHealthChecks(api *client.API, checks []contract.HealthCheck) error {
	if len(checks) == 0 {
		return errors.New("Cloudflare promotion requires health checks")
	}
	base, baseErr := url.Parse(api.BaseURL)
	for _, check := range checks {
		duration, err := time.ParseDuration(check.MinimumDuration)
		if err != nil || check.Successes < 3 || duration < 30*time.Second {
			return errors.New("Cloudflare health check requires at least three successes over 30 seconds")
		}
		checkURL, err := url.Parse(check.URL)
		if err != nil || checkURL.Scheme != "https" || checkURL.Host == "" || checkURL.User != nil {
			return errors.New("Cloudflare health check URL is invalid")
		}
		if api.Access != nil && (baseErr != nil || base.Scheme != checkURL.Scheme ||
			!strings.EqualFold(base.Host, checkURL.Host)) {
			return errors.New("Cloudflare Access health check must use the configured EnvBank origin")
		}
	}
	return nil
}

func expectedCloudflarePresence(operation string) provider.Presence {
	if operation == "revoke" {
		return provider.PresenceAbsent
	}
	return provider.PresencePresent
}

func printCloudflareOperation(operation rollout.Operation) {
	if operation.ID == "" {
		return
	}
	versions := make([]string, 0, len(operation.Actions))
	for _, item := range operation.Actions {
		if item.WriteEvidence != nil {
			versions = append(versions, item.WriteEvidence.ProviderOperationID)
		}
	}
	sort.Strings(versions)
	version := "not-staged"
	if len(versions) != 0 {
		version = versions[0]
	}
	fmt.Printf("operation: %s\nprovider: cloudflare\nstatus: %s\nprior version: %s\nstaged version: %s\n",
		operation.ID, operation.Status, operation.ProviderRevision, version)
}
