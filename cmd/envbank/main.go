package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/GeorgeQLe/envbank/internal/browser"
	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/intake"
	"github.com/GeorgeQLe/envbank/internal/keychain"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	"github.com/GeorgeQLe/envbank/internal/nativehost"
	"github.com/GeorgeQLe/envbank/internal/password"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/provider"
	"github.com/GeorgeQLe/envbank/internal/provider/railway"
	"github.com/GeorgeQLe/envbank/internal/rollout"
	"github.com/GeorgeQLe/envbank/internal/secure"
	"github.com/GeorgeQLe/envbank/internal/server"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
	"github.com/mattn/go-isatty"
)

const (
	maxRequestHeaderBytes = 16 << 10
	shutdownTimeout       = 10 * time.Second
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	args := os.Args[1:]
	if filepath.Base(os.Args[0]) == "envbank-native-host" {
		args = []string{"native-host"}
	}
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, "envbank:", err)
		var codeError exitCodeError
		if errors.As(err, &codeError) {
			os.Exit(codeError.code)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "version":
		return printVersion(args[1:])
	case "serve":
		return serve(args[1:])
	case "init":
		return initialize(args[1:])
	case "enroll-request":
		return enrollRequest(args[1:])
	case "enroll-list":
		return enrollList(args[1:])
	case "enroll-approve":
		return enrollApprove(args[1:])
	case "enroll-accept":
		return enrollAccept(args[1:])
	case "device-list":
		return deviceList(args[1:])
	case "device-revoke":
		return deviceRevoke(args[1:])
	case "event-list":
		return eventList(args[1:])
	case "set":
		return setSecret(args[1:], false)
	case "rotate":
		return setSecret(args[1:], true)
	case "generate":
		return generatePassword(args[1:])
	case "list":
		return listSecrets(args[1:])
	case "get":
		return getSecret(args[1:])
	case "due":
		return dueSecrets(args[1:])
	case "run":
		return runCommand(args[1:])
	case "browser-allow":
		return browserOriginCommand(args[1:], true)
	case "browser-deny":
		return browserOriginCommand(args[1:], false)
	case "browser-origins":
		return browserOrigins(args[1:])
	case "keychain-store":
		return keychainStore(args[1:])
	case "native-host":
		return runNativeHost(args[1:])
	case "browser-install":
		return browserInstall(args[1:])
	case "browser-uninstall":
		return browserUninstall(args[1:])
	case "recovery-export":
		return recoveryExport(args[1:])
	case "recovery-verify":
		return recoveryVerify(args[1:])
	case "recovery-list":
		return recoveryList(args[1:])
	case "recovery-get":
		return recoveryGet(args[1:])
	case "recovery-run":
		return recoveryRun(args[1:])
	case "recovery-restore":
		return recoveryRestore(args[1:])
	case "bundle":
		return bundleCommand(args[1:])
	case "railway":
		return railwayCommand(args[1:])
	case "mcp":
		return mcpCommand(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `EnvBank: encrypted, multi-device environment variables

Usage:
  envbank version
  envbank serve [--listen 127.0.0.1:7337] [--database PATH]
  envbank init --server URL --vault NAME --device NAME [auth flags]
  envbank enroll-request --server URL --vault-id ID --device NAME [auth flags]
  envbank enroll-list [auth flags]
  envbank enroll-approve --fingerprint HEX [auth flags] DEVICE_ID
  envbank enroll-accept [auth flags]
  envbank device-list [auth flags]
  envbank device-revoke --fingerprint HEX [--allow-self] [auth flags] DEVICE_ID
  envbank event-list [--limit N] [--before CURSOR] [auth flags]
  envbank set [--rotate-days N] [auth flags] NAME       # value from stdin
  envbank rotate [--bytes 32] [auth flags] NAME         # generated value
  envbank generate [--length 24] [--lowercase=true] [--uppercase=true] [--digits=true] [--symbols=true] [--replace] [--rotate-days N] [auth flags] NAME
  envbank list [auth flags]
  envbank get NAME [auth flags]
  envbank due [--notify] [auth flags]
  envbank run [auth flags] -- COMMAND [ARGS...]
  envbank browser-allow [auth flags] NAME ORIGIN
  envbank browser-deny [auth flags] NAME ORIGIN
  envbank browser-origins [auth flags] NAME
  envbank keychain-store [auth flags]
  envbank native-host [--config PATH]
  envbank browser-install [--config PATH]
  envbank browser-uninstall [--delete-keychain]
  envbank recovery-export --output PATH --recovery-passphrase-file PATH [auth flags]
  envbank recovery-verify --artifact PATH [recovery auth flags]
  envbank recovery-list --artifact PATH [recovery auth flags]
  envbank recovery-get --artifact PATH [recovery auth flags] NAME
  envbank recovery-run --artifact PATH [recovery auth flags] -- COMMAND [ARGS...]
  envbank recovery-restore --artifact PATH --server URL --vault NAME --device NAME [recovery auth flags] [auth flags]
  envbank recovery-restore --resume --artifact PATH [recovery auth flags] [auth flags]
  envbank bundle check --manifest PATH
  envbank bundle prepare --manifest PATH [auth flags]  # missing imports from a JSON object on stdin
  envbank bundle prepare-exec --manifest PATH [--allow-env NAMES] [--source-sha256 HEX] [--source-timeout DURATION] [auth flags] -- /ABSOLUTE/SOURCE [SAFE ARGS...]
  envbank bundle status --manifest PATH [auth flags]
  envbank railway bind --manifest PATH [auth flags]  # project token from trusted stdin
  envbank railway plan --manifest PATH [auth flags]
  envbank railway apply --plan PLAN_ID [auth flags]
  envbank railway resume --operation OPERATION_ID [auth flags]
  envbank railway verify --bundle BUNDLE [auth flags]
  envbank mcp serve  # local stdio; workflow tools only

Auth flags:
  --config PATH           encrypted device config
  --passphrase-file PATH  file containing the local passphrase

If --passphrase-file is omitted, ENVBANK_PASSPHRASE is used. Secret values are
never accepted as command-line arguments. If --recovery-passphrase-file is
omitted, ENVBANK_RECOVERY_PASSPHRASE is used.
`)
}

func mcpCommand(args []string) error {
	if len(args) != 1 || args[0] != "serve" {
		return errors.New("mcp subcommand is required (supported: serve)")
	}
	return (mcpserver.Server{}).Serve(context.Background(), os.Stdin, os.Stdout)
}

var railwayCredentialStore keychain.Store = keychain.SystemStore{}
var railwayAdapterOptions = func() railway.Options { return railway.Options{} }
var railwayConfirmation rollout.ConfirmFunc = confirmRailwayWrites

func railwayCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("railway subcommand is required (supported: bind, plan, apply, resume, verify)")
	}
	switch args[0] {
	case "bind":
		return railwayBind(args[1:])
	case "plan":
		return railwayPlan(args[1:])
	case "apply":
		return railwayApply(args[1:])
	case "resume":
		return railwayResume(args[1:])
	case "verify":
		return railwayVerify(args[1:])
	default:
		return fmt.Errorf("unknown railway subcommand %q", args[0])
	}
}

func railwayApply(args []string) error {
	fs := flag.NewFlagSet("railway apply", flag.ContinueOnError)
	planID := fs.String("plan", "", "encrypted provider plan ID")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planID == "" || fs.NArg() != 0 {
		return errors.New("railway apply requires --plan PLAN_ID and no positional arguments")
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
	adapter, err := railwayAdapterForBundle(api.Config.VaultID, plan.Bundle)
	if err != nil {
		return err
	}
	defer adapter.Close()
	operation, err := (&rollout.Engine{Adapter: adapter, Store: store}).Apply(
		context.Background(), *planID, railwayConfirmation)
	printRailwayOperation(operation)
	return err
}

func railwayResume(args []string) error {
	fs := flag.NewFlagSet("railway resume", flag.ContinueOnError)
	operationID := fs.String("operation", "", "encrypted rollout operation ID")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operationID == "" || fs.NArg() != 0 {
		return errors.New("railway resume requires --operation OPERATION_ID and no positional arguments")
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
	adapter, err := railwayAdapterForBundle(api.Config.VaultID, operation.Bundle)
	if err != nil {
		return err
	}
	defer adapter.Close()
	operation, err = (&rollout.Engine{Adapter: adapter, Store: store}).Resume(context.Background(), *operationID)
	printRailwayOperation(operation)
	return err
}

func railwayVerify(args []string) error {
	fs := flag.NewFlagSet("railway verify", flag.ContinueOnError)
	bundleID := fs.String("bundle", "", "bundle identifier")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundleID == "" || fs.NArg() != 0 {
		return errors.New("railway verify requires --bundle BUNDLE and no positional arguments")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	plan, operation, err := latestRailwayEvidence(api, vaultKey, *bundleID)
	if err != nil {
		return err
	}
	adapter, err := railwayAdapterForBundle(api.Config.VaultID, *bundleID)
	if err != nil {
		return err
	}
	defer adapter.Close()
	identity, err := adapter.Identity(context.Background())
	if err != nil {
		return providerSafeError("identity", err)
	}
	if identity.Provider != plan.Provider || identity.ID != plan.ProviderIdentity {
		return errors.New("provider identity does not match the latest plan")
	}
	if _, err := adapter.Inspect(context.Background(), provider.Target{ProjectID: plan.Target.ProjectID,
		EnvironmentID: plan.Target.EnvironmentID, ServiceIDs: plan.Target.ServiceIDs}); err != nil {
		return providerSafeError("inspect", err)
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	if err := store.ValidateSnapshot(context.Background(), plan); err != nil {
		return err
	}
	fmt.Printf("bundle: %s\nprovider: railway\nproject id: %s\nenvironment id: %s\nlocal snapshot revision: %d\nnames:\n",
		plan.Bundle, plan.Target.ProjectID, plan.Target.EnvironmentID, plan.SnapshotRevision)
	for _, item := range plan.Names {
		write := "not-written"
		for _, action := range operation.Actions {
			if action.Action.Service == item.Service && action.Action.Name == item.Name && action.WriteEvidence != nil {
				write = "committed"
				break
			}
		}
		fmt.Printf("  %s/%s: desired=%s presence=unknown local-write=%s\n", item.Service, item.Name, item.Desired, write)
	}
	fmt.Printf("operation: %s\noperation status: %s\nprovider verification: limited (names-only metadata unavailable)\n", operation.ID, operation.Status)
	fmt.Println("staged changes: committed writes recorded locally; exact provider state is unreadable without values")
	fmt.Println("deployed state: not inspected; no deployment mutation issued")
	if operation.Status == rollout.StatusReady || operation.Status == rollout.StatusLimited {
		fmt.Println("status: ready for separately authorized deployment")
	} else {
		fmt.Printf("status: incomplete; resume operation %s before deployment authorization\n", operation.ID)
	}
	return nil
}

func railwayBind(args []string) error {
	fs := flag.NewFlagSet("railway bind", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("railway bind requires --manifest PATH and no positional arguments")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	binding, err := railway.BindingRequestForManifest(document)
	if err != nil {
		return err
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	token, err := readRailwayCredential(os.Stdin)
	if err != nil {
		return err
	}
	defer clearBytes(token)
	adapter, err := railway.New(token, railwayAdapterOptions())
	if err != nil {
		return err
	}
	defer adapter.Close()
	target, err := adapter.Bind(context.Background(), binding)
	if err != nil {
		return providerSafeError("bind", err)
	}
	account, err := railway.CredentialAccount(api.Config.VaultID, document.Manifest.Bundle)
	if err != nil {
		return err
	}
	if err := railwayCredentialStore.Put(railway.CredentialService, account, token); err != nil {
		return errors.New("verified Railway project credential could not be stored in Keychain")
	}
	fmt.Printf("bundle: %s\nprovider: railway\nproject id: %s\nenvironment id: %s\nservices:\n",
		document.Manifest.Bundle, target.ProjectID, target.EnvironmentID)
	for _, name := range railway.SiftCutServiceNames() {
		fmt.Printf("  %s: %s\n", name, target.ServiceIDs[name])
	}
	fmt.Println("status: bound")
	return nil
}

func railwayPlan(args []string) error {
	fs := flag.NewFlagSet("railway plan", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("railway plan requires --manifest PATH and no positional arguments")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	binding, err := railway.BindingRequestForManifest(document)
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
	account, err := railway.CredentialAccount(api.Config.VaultID, document.Manifest.Bundle)
	if err != nil {
		return err
	}
	token, err := railway.LoadCredential(railwayCredentialStore, account)
	if err != nil {
		return err
	}
	defer clearBytes(token)
	adapter, err := railway.New(token, railwayAdapterOptions())
	if err != nil {
		return err
	}
	defer adapter.Close()
	target, err := adapter.Bind(context.Background(), binding)
	if err != nil {
		return providerSafeError("bind", err)
	}
	input, err := railway.BuildNamesOnlyInput(document, snapshot, snapshotRevision, target)
	if err != nil {
		return err
	}
	engine := rollout.Engine{Adapter: adapter, Store: &rollout.EncryptedStore{API: api, VaultKey: vaultKey}}
	plan, err := engine.Plan(context.Background(), input)
	if err != nil {
		return err
	}
	fmt.Printf("plan: %s\nbundle: %s\nprovider: railway\nproject id: %s\nenvironment id: %s\nexpires: %s\nnames:\n",
		plan.ID(), plan.Bundle, plan.Target.ProjectID, plan.Target.EnvironmentID, plan.ExpiresAt)
	for _, item := range plan.Names {
		fmt.Printf("  %s/%s: desired=%s state=%s\n", item.Service, item.Name, item.Desired, item.State)
	}
	fmt.Println("status: names-only; no provider values read and no provider changes made")
	return nil
}

func railwayAdapterForBundle(vaultID, bundleID string) (*railway.Adapter, error) {
	account, err := railway.CredentialAccount(vaultID, bundleID)
	if err != nil {
		return nil, err
	}
	token, err := railway.LoadCredential(railwayCredentialStore, account)
	if err != nil {
		return nil, err
	}
	defer clearBytes(token)
	return railway.New(token, railwayAdapterOptions())
}

func confirmRailwayWrites(_ context.Context, request rollout.Confirmation) error {
	if request.Kind != "apply" || request.Destructive || request.Provider != railway.ProviderName ||
		request.ActionCount < 1 || !isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("Railway apply confirmation requires an interactive terminal")
	}
	fmt.Fprintf(os.Stderr, "Apply %d Railway variable writes for %s with deployments skipped? Type apply: ",
		request.ActionCount, request.Bundle)
	answer, err := bufio.NewReader(io.LimitReader(os.Stdin, 32)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("Railway apply confirmation could not be read")
	}
	if strings.TrimSpace(answer) != "apply" {
		return errors.New("Railway apply confirmation was declined")
	}
	return nil
}

func printRailwayOperation(operation rollout.Operation) {
	if operation.ID == "" {
		return
	}
	fmt.Printf("operation: %s\nbundle: %s\nstatus: %s\nactions:\n",
		operation.ID, operation.Bundle, operation.Status)
	for _, item := range operation.Actions {
		fmt.Printf("  %s/%s: %s attempts=%d\n", item.Action.Service, item.Action.Name, item.Status, item.Attempts)
	}
	if operation.Status == rollout.StatusReady || operation.Status == rollout.StatusLimited {
		fmt.Println("staged changes: committed writes recorded locally")
		fmt.Println("deployed state: not inspected; no deployment mutation issued")
		fmt.Println("deployment: ready for separately authorized deployment")
	}
}

func latestRailwayEvidence(api *client.API, vaultKey []byte, bundleID string) (rollout.ProviderPlan, rollout.Operation, error) {
	objects, err := api.ListObjects(vaultKey)
	if err != nil {
		return rollout.ProviderPlan{}, rollout.Operation{}, err
	}
	var operation rollout.Operation
	for _, object := range objects {
		if object.Kind != vaultobject.KindRolloutOperation {
			continue
		}
		var candidate rollout.Operation
		if json.Unmarshal(object.Payload, &candidate) != nil || candidate.Bundle != bundleID ||
			candidate.Provider != railway.ProviderName || candidate.Validate() != nil {
			continue
		}
		if operation.UpdatedAt == "" || candidate.UpdatedAt > operation.UpdatedAt {
			operation = candidate
		}
	}
	if operation.ID == "" {
		return rollout.ProviderPlan{}, rollout.Operation{}, errors.New("no confirmed Railway operation exists for the bundle")
	}
	store := &rollout.EncryptedStore{API: api, VaultKey: vaultKey}
	plan, _, err := store.LoadPlan(context.Background(), operation.PlanID)
	if err != nil {
		return rollout.ProviderPlan{}, rollout.Operation{}, err
	}
	if !rollout.OperationMatchesPlan(operation, plan) {
		return rollout.ProviderPlan{}, rollout.Operation{}, errors.New("Railway operation does not match its provider plan")
	}
	return plan, operation, nil
}

func readRailwayCredential(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("Railway project credential is required on trusted stdin")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		clearBytes(raw)
		return nil, errors.New("Railway project credential could not be read from trusted stdin")
	}
	token := bytes.TrimSpace(raw)
	if len(token) == 0 || bytes.IndexFunc(token, func(character rune) bool { return character <= ' ' || character == 0x7f }) >= 0 {
		clearBytes(raw)
		return nil, errors.New("Railway project credential is invalid")
	}
	result := append([]byte(nil), token...)
	clearBytes(raw)
	return result, nil
}

func providerSafeError(operation string, err error) error {
	safe := provider.SanitizeError(operation, err)
	return safe
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func bundleCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("bundle subcommand is required (supported: check, prepare, prepare-exec, status)")
	}
	switch args[0] {
	case "check":
		return bundleCheck(args[1:])
	case "prepare":
		return bundlePrepare(args[1:])
	case "prepare-exec":
		return bundlePrepareExec(args[1:])
	case "status":
		return bundleStatus(args[1:])
	default:
		return fmt.Errorf("unknown bundle subcommand %q", args[0])
	}
}

func bundlePrepareExec(args []string) error {
	separator := -1
	for index, argument := range args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator == len(args)-1 {
		return errors.New("bundle prepare-exec requires -- /ABSOLUTE/SOURCE [SAFE ARGS...]")
	}
	flagArgs, sourceArgs := args[:separator], args[separator+1:]
	fs := flag.NewFlagSet("bundle prepare-exec", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	allowEnvironment := fs.String("allow-env", "", "comma-separated source environment variable names")
	sourceSHA256 := fs.String("source-sha256", "", "optional pinned source executable SHA-256")
	sourceTimeout := fs.Duration("source-timeout", intake.DefaultTimeout, "source execution timeout")
	auth := addAuthFlags(fs)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("bundle prepare-exec requires --manifest PATH and no positional arguments before --")
	}
	if auth.passphraseFile == "" {
		return errors.New("bundle prepare-exec requires --passphrase-file; EnvBank passphrases are never inherited by a source")
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
	preparer := &bundle.Preparer{API: api, VaultKey: vaultKey}
	status, err := preparer.Status(document)
	if err != nil {
		return err
	}
	if status.State == "prepared" {
		printBundleStatus(status)
		return nil
	}
	allowed := []string{"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "XDG_CONFIG_HOME"}
	if *allowEnvironment != "" {
		allowed = append(allowed, strings.Split(*allowEnvironment, ",")...)
	}
	raw, err := (intake.CommandSource{
		Executable: sourceArgs[0], Arguments: sourceArgs[1:], Environment: os.Environ(),
		AllowedEnvironment: allowed, ExecutableSHA256: *sourceSHA256, Timeout: *sourceTimeout,
	}).Read(context.Background())
	if err != nil {
		return err
	}
	defer intake.Wipe(raw)
	status, err = preparer.Prepare(document, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	printBundleStatus(status)
	return nil
}

func bundleCheck(args []string) error {
	fs := flag.NewFlagSet("bundle check", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("bundle check requires --manifest PATH and no positional arguments")
	}
	document, err := loadBundleManifest(*manifestPath)
	if err != nil {
		return err
	}
	providers := make([]string, 0, len(document.Manifest.Targets))
	for provider := range document.Manifest.Targets {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	fmt.Printf("bundle: %s\nmanifest digest: %s\nrecords: %d\ntargets: %s\nstatus: valid\n",
		document.Manifest.Bundle, document.Digest, len(document.Manifest.Records), strings.Join(providers, ","))
	return nil
}

func bundlePrepare(args []string) error {
	fs := flag.NewFlagSet("bundle prepare", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("bundle prepare requires --manifest PATH and no positional arguments")
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
	status, err := (&bundle.Preparer{API: api, VaultKey: vaultKey}).Prepare(document, os.Stdin)
	if err != nil {
		return err
	}
	printBundleStatus(status)
	return nil
}

func bundleStatus(args []string) error {
	fs := flag.NewFlagSet("bundle status", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "bundle manifest path")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return errors.New("bundle status requires --manifest PATH and no positional arguments")
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
	status, err := (&bundle.Preparer{API: api, VaultKey: vaultKey}).Status(document)
	if err != nil {
		return err
	}
	printBundleStatus(status)
	return nil
}

func loadBundleManifest(path string) (*contract.Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, contract.MaxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return contract.Parse(data)
}

func printBundleStatus(status bundle.Status) {
	fmt.Printf("bundle: %s\nmanifest digest: %s\nstatus: %s\nrecords:\n",
		status.Bundle, status.ManifestDigest, status.State)
	names := make([]string, 0, len(status.Records))
	for name := range status.Records {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("  %s: %s\n", name, status.Records[name])
	}
}

func printVersion(args []string) error {
	if len(args) != 0 {
		return errors.New("version does not accept arguments")
	}
	fmt.Printf("envbank %s (commit %s, built %s)\n", version, commit, buildDate)
	return nil
}

type authFlags struct {
	configPath     string
	passphraseFile string
}

func addAuthFlags(fs *flag.FlagSet) *authFlags {
	auth := &authFlags{}
	fs.StringVar(&auth.configPath, "config", defaultConfigPath(), "encrypted device config")
	fs.StringVar(&auth.passphraseFile, "passphrase-file", "", "file containing the local passphrase")
	return auth
}

func serve(args []string) error {
	ctx, stop := shutdownSignalContext()
	defer stop()
	return serveContext(ctx, args)
}

func shutdownSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func serveContext(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:7337", "listen address")
	database := fs.String("database", "envbank-server.db", "SQLite database file")
	legacyState := fs.String("state", "", "deprecated alias for --database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *legacyState != "" {
		if *database != "envbank-server.db" {
			return errors.New("--database and --state cannot be used together")
		}
		*database = *legacyState
	}
	service, err := server.Open(*database)
	if err != nil {
		return err
	}
	defer service.Close()
	httpServer := newHTTPServer(*listen, service)
	fmt.Fprintf(os.Stderr, "EnvBank sync service listening on %s\n", *listen)
	return runHTTPServer(ctx, httpServer, httpServer.ListenAndServe)
}

func runHTTPServer(ctx context.Context, httpServer *http.Server, listen func() error) error {
	result := make(chan error, 1)
	go func() {
		result <- listen()
	}()

	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down sync service: %w", err)
		}
		err := <-result
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newHTTPServer(listen string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}
}

func initialize(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	serverURL := fs.String("server", "", "sync service URL")
	vaultName := fs.String("vault", "", "vault name")
	deviceName := fs.String("device", "", "device name")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" || *vaultName == "" || *deviceName == "" {
		return errors.New("--server, --vault, and --device are required")
	}
	if _, err := os.Stat(auth.configPath); err == nil {
		return fmt.Errorf("config already exists at %s", auth.configPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	passphrase, err := readPassphrase(auth.passphraseFile)
	if err != nil {
		return err
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		return err
	}
	vaultKey, err := secure.RandomBytes(32)
	if err != nil {
		return err
	}
	keys.Secrets.VaultKey = secure.Encode(vaultKey)
	api := client.NewAPI(*serverURL)
	created, err := api.CreateVault(*vaultName, protocol.PublicDevice{
		Name: *deviceName, SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic,
	})
	if err != nil {
		return err
	}
	cfg, err := client.NewConfig(*serverURL, created.VaultID, created.DeviceID, *deviceName, keys, passphrase)
	if err != nil {
		return err
	}
	if err := cfg.Save(auth.configPath); err != nil {
		return fmt.Errorf("vault was created but local config could not be saved: %w", err)
	}
	fmt.Printf("vault %s initialized; device fingerprint %s\n",
		created.VaultID, secure.PublicFingerprint(keys.SigningPublic, keys.WrappingPublic))
	return nil
}

func enrollRequest(args []string) error {
	fs := flag.NewFlagSet("enroll-request", flag.ContinueOnError)
	serverURL := fs.String("server", "", "sync service URL")
	vaultID := fs.String("vault-id", "", "existing vault ID")
	deviceName := fs.String("device", "", "device name")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" || *vaultID == "" || *deviceName == "" {
		return errors.New("--server, --vault-id, and --device are required")
	}
	if _, err := os.Stat(auth.configPath); err == nil {
		return fmt.Errorf("config already exists at %s", auth.configPath)
	}
	passphrase, err := readPassphrase(auth.passphraseFile)
	if err != nil {
		return err
	}
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		return err
	}
	api := client.NewAPI(*serverURL)
	status, err := api.RequestEnrollment(*vaultID, protocol.EnrollmentRequest{
		Name: *deviceName, SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic,
	})
	if err != nil {
		return err
	}
	cfg, err := client.NewConfig(*serverURL, *vaultID, status.Device.ID, *deviceName, keys, passphrase)
	if err != nil {
		return err
	}
	if err := cfg.Save(auth.configPath); err != nil {
		return fmt.Errorf("enrollment was requested but local config could not be saved: %w", err)
	}
	fmt.Printf("enrollment requested for device %s\nfingerprint: %s\n",
		status.Device.ID, status.Device.Fingerprint)
	return nil
}

func enrollList(args []string) error {
	fs := flag.NewFlagSet("enroll-list", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	enrollments, err := api.ListEnrollments()
	if err != nil {
		return err
	}
	for _, enrollment := range enrollments {
		status := "pending"
		if enrollment.RevokedAt != "" {
			status = "revoked"
		} else if enrollment.Approved {
			status = "approved"
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", enrollment.Device.ID, enrollment.Device.Name,
			enrollment.Device.Fingerprint, status)
	}
	return nil
}

func deviceList(args []string) error {
	fs := flag.NewFlagSet("device-list", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("device-list accepts no positional arguments")
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	devices, err := api.ListDevices()
	if err != nil {
		return err
	}
	for _, device := range devices {
		status := "active"
		if device.RevokedAt != "" {
			status = "revoked"
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", device.Device.ID, device.Device.Name,
			device.Device.Fingerprint, status, device.RevokedAt)
	}
	return nil
}

func deviceRevoke(args []string) error {
	fs := flag.NewFlagSet("device-revoke", flag.ContinueOnError)
	fingerprint := fs.String("fingerprint", "", "fingerprint verified out of band")
	allowSelf := fs.Bool("allow-self", false, "confirm revocation of this configured device")
	auth := addAuthFlags(fs)
	args = normalizeDeviceRevokeArgs(args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || strings.TrimSpace(*fingerprint) == "" {
		return errors.New("DEVICE_ID and --fingerprint are required")
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	targetID := fs.Arg(0)
	devices, err := api.ListDevices()
	if err != nil {
		return err
	}
	var target *protocol.DeviceStatus
	for i := range devices {
		if devices[i].Device.ID == targetID {
			target = &devices[i]
			break
		}
	}
	if target == nil {
		return errors.New("device not found")
	}
	if target.RevokedAt != "" {
		return errors.New("device is already revoked")
	}
	if !strings.EqualFold(target.Device.Fingerprint, strings.TrimSpace(*fingerprint)) {
		return errors.New("fingerprint does not match; revocation cancelled")
	}
	self := targetID == api.Config.DeviceID
	if self && !*allowSelf {
		return errors.New("refusing to revoke the current device without --allow-self")
	}
	revoked, err := api.RevokeDevice(targetID)
	if err != nil {
		return err
	}
	fmt.Printf("revoked device %s (%s) at %s\n",
		revoked.Device.ID, revoked.Device.Name, revoked.RevokedAt)
	if self {
		fmt.Fprintln(os.Stderr, "warning: this device can no longer access the vault; its local config and Keychain entry were preserved")
	}
	return nil
}

func normalizeDeviceRevokeArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	for _, arg := range args[:len(args)-1] {
		if arg == "--" {
			return args
		}
	}
	candidate := args[len(args)-1]
	if !strings.HasPrefix(candidate, "-") {
		return args
	}
	decoded, err := secure.Decode(candidate)
	if err != nil || len(decoded) != 18 || secure.Encode(decoded) != candidate {
		return args
	}
	normalized := make([]string, 0, len(args)+1)
	normalized = append(normalized, args[:len(args)-1]...)
	return append(normalized, "--", candidate)
}

func eventList(args []string) error {
	fs := flag.NewFlagSet("event-list", flag.ContinueOnError)
	limit := fs.Int("limit", 0, "events to return (default 100, maximum 500)")
	before := fs.String("before", "", "opaque pagination cursor")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("event-list accepts no positional arguments")
	}
	var limitSet bool
	fs.Visit(func(current *flag.Flag) {
		if current.Name == "limit" {
			limitSet = true
		}
	})
	if limitSet && (*limit < 1 || *limit > 500) {
		return errors.New("--limit must be between 1 and 500")
	}
	api, _, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	page, err := api.ListAccessEvents(*limit, *before)
	if err != nil {
		return err
	}
	for _, event := range page.Events {
		identityID := event.IdentityID
		if identityID == "" {
			identityID = "-"
		}
		reason := event.Reason
		if reason == "" {
			reason = "-"
		}
		targetID := event.TargetIdentityID
		if targetID == "" {
			targetID = "-"
		}
		fmt.Printf("%s\t%s\t%t\t%s\t%s\t%s\t%s\n",
			event.Timestamp, identityID, event.IdentityVerified, event.Operation,
			event.Outcome, reason, targetID)
	}
	if page.NextCursor != "" {
		fmt.Fprintf(os.Stderr, "next cursor: %s\n", page.NextCursor)
	}
	return nil
}

func enrollApprove(args []string) error {
	fs := flag.NewFlagSet("enroll-approve", flag.ContinueOnError)
	fingerprint := fs.String("fingerprint", "", "fingerprint verified out of band")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *fingerprint == "" {
		return errors.New("DEVICE_ID and --fingerprint are required")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	enrollments, err := api.ListEnrollments()
	if err != nil {
		return err
	}
	var selected *protocol.EnrollmentStatus
	for i := range enrollments {
		if enrollments[i].Device.ID == fs.Arg(0) {
			selected = &enrollments[i]
			break
		}
	}
	if selected == nil {
		return errors.New("pending enrollment not found")
	}
	if selected.Approved {
		return errors.New("device is already approved")
	}
	recomputed := secure.PublicFingerprint(selected.Device.SigningPublic, selected.Device.WrappingPublic)
	if client.ValidateDeviceIdentity(selected.Device, selected.Device.SigningPublic,
		selected.Device.WrappingPublic) != nil ||
		!strings.EqualFold(recomputed, strings.TrimSpace(*fingerprint)) {
		return errors.New("fingerprint does not match; approval cancelled")
	}
	envelope, err := secure.WrapVaultKey(vaultKey, selected.Device.WrappingPublic,
		api.Config.VaultID, selected.Device.ID)
	if err != nil {
		return err
	}
	if err := api.ApproveEnrollment(selected.Device.ID, envelope); err != nil {
		return err
	}
	fmt.Printf("approved device %s (%s)\n", selected.Device.ID, selected.Device.Name)
	return nil
}

func enrollAccept(args []string) error {
	fs := flag.NewFlagSet("enroll-accept", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	api, secrets, passphrase, err := unlockedAPIWithPassphrase(auth)
	if err != nil {
		return err
	}
	if secrets.VaultKey != "" {
		return errors.New("this device already has a vault key")
	}
	status, err := api.GetEnrollment(api.Config.DeviceID)
	if err != nil {
		return err
	}
	if !status.Approved || status.Envelope == nil {
		return errors.New("enrollment is still pending")
	}
	vaultKey, err := client.UnwrapEnrollmentVaultKey(status, secrets,
		api.Config.VaultID, api.Config.DeviceID)
	if err != nil {
		return err
	}
	secrets.VaultKey = secure.Encode(vaultKey)
	if err := api.Config.Lock(secrets, passphrase); err != nil {
		return err
	}
	if err := api.Config.Save(auth.configPath); err != nil {
		return err
	}
	fmt.Println("enrollment accepted; this device can now access the vault")
	return nil
}

func setSecret(args []string, rotate bool) error {
	command := "set"
	if rotate {
		command = "rotate"
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	rotateDays := fs.Int("rotate-days", -1, "rotation interval in days; 0 disables")
	generatedBytes := fs.Int("bytes", 32, "random bytes for generated rotations")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || !validEnvName(fs.Arg(0)) {
		return errors.New("exactly one valid environment variable NAME is required")
	}
	if *rotateDays < -1 {
		return errors.New("--rotate-days must be zero or greater")
	}
	var value string
	if rotate {
		if *generatedBytes < 16 || *generatedBytes > 256 {
			return errors.New("--bytes must be between 16 and 256")
		}
		raw, err := secure.RandomBytes(*generatedBytes)
		if err != nil {
			return err
		}
		value = base64.RawURLEncoding.EncodeToString(raw)
	} else {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return err
		}
		if len(raw) == 1<<20 {
			return errors.New("secret value exceeds 1 MiB")
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	encrypted, err := api.ListRecords()
	if err != nil {
		return err
	}
	records, err := client.DecryptRecords(api.Config.VaultID, vaultKey, encrypted)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := protocol.SecretRecord{
		Name: fs.Arg(0), Value: value, CreatedAt: now, RotatedAt: now, Revision: 1,
	}
	var expected int64
	for _, existing := range records {
		if existing.Name == record.Name {
			expected = existing.Revision
			record.CreatedAt = existing.CreatedAt
			record.RotateEveryDays = existing.RotateEveryDays
			record.AllowedOrigins = append([]string(nil), existing.AllowedOrigins...)
			record.Revision = existing.Revision + 1
			break
		}
	}
	if *rotateDays >= 0 {
		record.RotateEveryDays = *rotateDays
	}
	id, blob, err := client.EncryptRecord(api.Config.VaultID, vaultKey, record)
	if err != nil {
		return err
	}
	if _, err := api.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
		return err
	}
	action := "stored"
	if rotate {
		action = "rotated with a generated value"
	}
	fmt.Printf("%s %s (revision %d)\n", record.Name, action, record.Revision)
	return nil
}

func generatePassword(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	policy := password.DefaultPolicy()
	fs.IntVar(&policy.Length, "length", policy.Length, "password length")
	fs.BoolVar(&policy.Lowercase, "lowercase", policy.Lowercase, "include lowercase letters")
	fs.BoolVar(&policy.Uppercase, "uppercase", policy.Uppercase, "include uppercase letters")
	fs.BoolVar(&policy.Digits, "digits", policy.Digits, "include digits")
	fs.BoolVar(&policy.Symbols, "symbols", policy.Symbols, "include symbols")
	replace := fs.Bool("replace", false, "replace an existing record")
	rotateDays := fs.Int("rotate-days", -1, "rotation interval in days; 0 disables")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rotateDaysSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "rotate-days" {
			rotateDaysSet = true
		}
	})
	if fs.NArg() != 1 || !validEnvName(fs.Arg(0)) {
		return errors.New("exactly one valid environment variable NAME is required")
	}
	if rotateDaysSet && *rotateDays < 0 {
		return errors.New("--rotate-days must be zero or greater")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	api, vaultKey, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := protocol.SecretRecord{Name: fs.Arg(0), CreatedAt: now, RotatedAt: now, Revision: 1}
	var expected int64
	for _, existing := range records {
		if existing.Name != record.Name {
			continue
		}
		if !*replace {
			return errors.New("record already exists; use --replace to replace it")
		}
		expected = existing.Revision
		record.CreatedAt = existing.CreatedAt
		record.RotateEveryDays = existing.RotateEveryDays
		record.AllowedOrigins = append([]string(nil), existing.AllowedOrigins...)
		record.Revision = existing.Revision + 1
		break
	}
	if rotateDaysSet {
		record.RotateEveryDays = *rotateDays
	}
	record.Value, err = password.Generate(policy)
	if err != nil {
		return err
	}
	id, blob, err := client.EncryptRecord(api.Config.VaultID, vaultKey, record)
	if err != nil {
		return err
	}
	if _, err := api.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
		return err
	}
	fmt.Printf("%s revision %d\n", record.Name, record.Revision)
	return nil
}

func browserOriginCommand(args []string, allow bool) error {
	command := "browser-deny"
	if allow {
		command = "browser-allow"
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || !validEnvName(fs.Arg(0)) {
		return errors.New("NAME and an exact ORIGIN are required")
	}
	origin, err := browser.NormalizeOrigin(fs.Arg(1))
	if err != nil {
		return err
	}
	api, vaultKey, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	var record *protocol.SecretRecord
	for i := range records {
		if records[i].Name == fs.Arg(0) {
			record = &records[i]
			break
		}
	}
	if record == nil {
		return errors.New("secret not found")
	}
	var changed bool
	if allow {
		record.AllowedOrigins, changed = browser.AddOrigin(record.AllowedOrigins, origin)
	} else {
		record.AllowedOrigins, changed = browser.RemoveOrigin(record.AllowedOrigins, origin)
	}
	if !changed {
		fmt.Printf("%s already %s for %s\n", origin, map[bool]string{true: "allowed", false: "denied"}[allow], record.Name)
		return nil
	}
	expected := record.Revision
	record.Revision++
	id, blob, err := client.EncryptRecord(api.Config.VaultID, vaultKey, *record)
	if err != nil {
		return err
	}
	if _, err := api.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
		return fmt.Errorf("browser policy update conflicted or failed: %w", err)
	}
	action := "denied"
	if allow {
		action = "allowed"
	}
	fmt.Printf("%s %s for %s\n", origin, action, record.Name)
	return nil
}

func browserOrigins(args []string) error {
	fs := flag.NewFlagSet("browser-origins", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || !validEnvName(fs.Arg(0)) {
		return errors.New("exactly one valid environment variable NAME is required")
	}
	_, _, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Name == fs.Arg(0) {
			for _, origin := range record.AllowedOrigins {
				fmt.Println(origin)
			}
			return nil
		}
	}
	return errors.New("secret not found")
}

func listSecrets(args []string) error {
	api, vaultKey, records, err := loadRecords(args, "list")
	if err != nil {
		return err
	}
	_ = api
	_ = vaultKey
	for _, record := range records {
		policy := "-"
		if record.RotateEveryDays > 0 {
			policy = fmt.Sprintf("%dd", record.RotateEveryDays)
		}
		fmt.Printf("%s\trotation=%s\trevision=%d\n", record.Name, policy, record.Revision)
	}
	return nil
}

func getSecret(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("NAME is required")
	}
	_, _, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Name == fs.Arg(0) {
			fmt.Print(record.Value)
			return nil
		}
	}
	return errors.New("secret not found")
}

func dueSecrets(args []string) error {
	fs := flag.NewFlagSet("due", flag.ContinueOnError)
	notify := fs.Bool("notify", false, "send a local notification with the due count")
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, _, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	due := client.Due(records, time.Now())
	for _, record := range due {
		fmt.Printf("%s\tlast_rotated=%s\tpolicy=%dd\n",
			record.Name, record.RotatedAt, record.RotateEveryDays)
	}
	if *notify && len(due) > 0 {
		if err := notifyDue(len(due)); err != nil {
			return err
		}
	}
	if len(due) > 0 {
		return exitCodeError{code: 2, message: fmt.Sprintf("%d secret(s) are due for rotation", len(due))}
	}
	fmt.Println("no secrets are due for rotation")
	return nil
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return errors.New("COMMAND is required after --")
	}
	_, _, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	return executeWithRecords(command, records)
}

func unlockedAPI(auth *authFlags) (*client.API, secure.DeviceSecrets, error) {
	api, secrets, _, err := unlockedAPIWithPassphrase(auth)
	return api, secrets, err
}

func unlockedAPIWithPassphrase(auth *authFlags) (*client.API, secure.DeviceSecrets, []byte, error) {
	cfg, err := client.LoadConfig(auth.configPath)
	if err != nil {
		return nil, secure.DeviceSecrets{}, nil, err
	}
	passphrase, err := readPassphrase(auth.passphraseFile)
	if err != nil {
		return nil, secure.DeviceSecrets{}, nil, err
	}
	secrets, err := cfg.Unlock(passphrase)
	if err != nil {
		return nil, secure.DeviceSecrets{}, nil, err
	}
	api := client.NewAPI(cfg.Server)
	api.Config = cfg
	api.Secrets = secrets
	return api, secrets, passphrase, nil
}

func loadRecords(args []string, command string) (*client.API, []byte, []protocol.SecretRecord, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, err
	}
	return loadRecordsWithAuth(auth)
}

func loadRecordsWithAuth(auth *authFlags) (*client.API, []byte, []protocol.SecretRecord, error) {
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return nil, nil, nil, err
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return nil, nil, nil, err
	}
	encrypted, err := api.ListRecords()
	if err != nil {
		return nil, nil, nil, err
	}
	records, err := client.DecryptRecords(api.Config.VaultID, vaultKey, encrypted)
	return api, vaultKey, records, err
}

func requireVaultKey(secrets secure.DeviceSecrets) ([]byte, error) {
	if secrets.VaultKey == "" {
		return nil, errors.New("device enrollment has not been accepted")
	}
	key, err := secure.Decode(secrets.VaultKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("local vault key is invalid")
	}
	return key, nil
}

func readPassphrase(path string) ([]byte, error) {
	return readSecretPassphrase(path, "ENVBANK_PASSPHRASE", "--passphrase-file")
}

func readSecretPassphrase(path, environmentName, flagName string) ([]byte, error) {
	if path == "" {
		value := os.Getenv(environmentName)
		if value == "" {
			return nil, fmt.Errorf("%s or %s is required", flagName, environmentName)
		}
		return []byte(value), nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("passphrase file must not be accessible by group or others")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if value == "" {
		return nil, errors.New("passphrase must not be empty")
	}
	return []byte(value), nil
}

func validEnvName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func setEnv(environment []string, name, value string) []string {
	prefix := name + "="
	for i := range environment {
		if strings.HasPrefix(environment[i], prefix) {
			environment[i] = prefix + value
			return environment
		}
	}
	return append(environment, prefix+value)
}

func unsetEnv(environment []string, name string) []string {
	prefix := name + "="
	out := environment[:0]
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return out
}

func notifyDue(count int) error {
	if runtime.GOOS != "darwin" {
		return errors.New("local notifications are currently supported only on macOS")
	}
	script := `display notification "` + fmt.Sprintf("%d secret(s) need rotation", count) + `" with title "EnvBank"`
	return exec.Command("osascript", "-e", script).Run()
}

func keychainStore(args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("Keychain storage is supported only on macOS")
	}
	fs := flag.NewFlagSet("keychain-store", flag.ContinueOnError)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("keychain-store accepts no positional arguments")
	}
	cfg, err := client.LoadConfig(auth.configPath)
	if err != nil {
		return err
	}
	passphrase, err := readPassphrase(auth.passphraseFile)
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)
	if _, err := cfg.Unlock(passphrase); err != nil {
		return errors.New("passphrase did not unlock the configured EnvBank device")
	}
	if err := (keychain.SystemStore{}).Put(keychain.Service, cfg.VaultID+":"+cfg.DeviceID, passphrase); err != nil {
		return err
	}
	fmt.Println("passphrase stored in macOS Keychain with user-presence protection")
	return nil
}

func runNativeHost(args []string) error {
	fs := flag.NewFlagSet("native-host", flag.ContinueOnError)
	configPath := fs.String("config", "", "encrypted device config (normally read from browser locator)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("native-host accepts no positional arguments")
	}
	if *configPath == "" {
		locator, err := os.ReadFile(browserLocatorPath())
		if err != nil {
			return errors.New("browser configuration locator is unavailable; run browser-install")
		}
		*configPath = strings.TrimSpace(string(locator))
	}
	if *configPath == "" {
		return errors.New("browser configuration locator is empty")
	}
	host := nativehost.New(*configPath, keychain.SystemStore{})
	return host.Run(os.Stdin, os.Stdout)
}

const defaultExtensionID = "pgbpmecaapiknpejgdkpaifpjcnckcnk"

func browserInstall(args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("browser installation is supported only on macOS")
	}
	fs := flag.NewFlagSet("browser-install", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath(), "encrypted device config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("browser-install accepts no positional arguments")
	}
	absConfig, err := filepath.Abs(*configPath)
	if err != nil {
		return err
	}
	if _, err := client.LoadConfig(absConfig); err != nil {
		return fmt.Errorf("load config before install: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binPath := browserBinaryPath()
	if err := copyExecutable(executable, binPath); err != nil {
		return err
	}
	if err := writePrivateFile(browserLocatorPath(), []byte(absConfig+"\n")); err != nil {
		return err
	}
	manifest := struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Path           string   `json:"path"`
		Type           string   `json:"type"`
		AllowedOrigins []string `json:"allowed_origins"`
	}{"com.envbank.native", "EnvBank browser fill native host", binPath, "stdio", []string{"chrome-extension://" + defaultExtensionID + "/"}}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateFile(browserManifestPath(), append(raw, '\n')); err != nil {
		return err
	}
	fmt.Printf("installed native host for extension %s\n", defaultExtensionID)
	fmt.Printf("load the unpacked extension from %s\n", extensionSourcePath(executable))
	return nil
}

func browserUninstall(args []string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("browser uninstallation is supported only on macOS")
	}
	fs := flag.NewFlagSet("browser-uninstall", flag.ContinueOnError)
	deleteKeychain := fs.Bool("delete-keychain", false, "also delete this device's Keychain passphrase")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("browser-uninstall accepts no positional arguments")
	}
	if *deleteKeychain {
		raw, err := os.ReadFile(browserLocatorPath())
		if err != nil {
			return errors.New("cannot identify the Keychain item because the browser locator is unavailable")
		}
		cfg, err := client.LoadConfig(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		if err := (keychain.SystemStore{}).Delete(keychain.Service, cfg.VaultID+":"+cfg.DeviceID); err != nil {
			return err
		}
	}
	for _, path := range []string{browserManifestPath(), browserLocatorPath(), browserBinaryPath()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	fmt.Println("removed the EnvBank native host; vault data was preserved")
	if !*deleteKeychain {
		fmt.Println("the Keychain passphrase was preserved")
	}
	return nil
}

func browserSupportDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "EnvBank")
	}
	return filepath.Join(home, "Library", "Application Support", "EnvBank")
}
func browserBinaryPath() string {
	return filepath.Join(browserSupportDir(), "bin", "envbank-native-host")
}
func browserLocatorPath() string { return filepath.Join(browserSupportDir(), "native-config") }
func browserManifestPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "com.envbank.native.json"
	}
	return filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", "com.envbank.native.json")
}
func extensionSourcePath(executable string) string {
	return filepath.Join(filepath.Dir(executable), "extension")
}
func writePrivateFile(path string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, contents, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
func copyExecutable(source, destination string) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	if err := os.WriteFile(tmp, raw, 0700); err != nil {
		return err
	}
	if err := os.Rename(tmp, destination); err != nil {
		return err
	}
	return os.Chmod(destination, 0700)
}
func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ".envbank/device.json"
	}
	return filepath.Join(dir, "envbank", "device.json")
}

type exitCodeError struct {
	code    int
	message string
}

func (e exitCodeError) Error() string { return e.message }
