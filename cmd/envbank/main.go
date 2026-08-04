package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/browser"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/keychain"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/nativehost"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/server"
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

Auth flags:
  --config PATH           encrypted device config
  --passphrase-file PATH  file containing the local passphrase

If --passphrase-file is omitted, ENVBANK_PASSPHRASE is used. Secret values are
never accepted as command-line arguments.
`)
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
	httpServer := &http.Server{
		Addr: *listen, Handler: service,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "EnvBank sync service listening on %s\n", *listen)
	return httpServer.ListenAndServe()
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
	if !strings.EqualFold(selected.Device.Fingerprint, strings.TrimSpace(*fingerprint)) {
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
	vaultKey, err := secure.UnwrapVaultKey(*status.Envelope, secrets.WrappingPrivate,
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
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append([]string(nil), os.Environ()...)
	for _, record := range records {
		cmd.Env = setEnv(cmd.Env, record.Name, record.Value)
	}
	return cmd.Run()
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
	if path == "" {
		value := os.Getenv("ENVBANK_PASSPHRASE")
		if value == "" {
			return nil, errors.New("--passphrase-file or ENVBANK_PASSPHRASE is required")
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
