package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"reflect"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/client"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/protocol"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/recovery"
	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
)

type recoveryFlags struct {
	artifactPath   string
	passphraseFile string
}

func addRecoveryFlags(fs *flag.FlagSet) *recoveryFlags {
	flags := &recoveryFlags{}
	fs.StringVar(&flags.artifactPath, "artifact", "", "encrypted recovery artifact")
	fs.StringVar(&flags.passphraseFile, "recovery-passphrase-file", "",
		"file containing the recovery passphrase")
	return flags
}

func recoveryExport(args []string) error {
	fs := flag.NewFlagSet("recovery-export", flag.ContinueOnError)
	output := fs.String("output", "", "new recovery artifact path")
	recoveryAuth := addRecoveryFlags(fs)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" {
		return errors.New("--output is required and recovery-export accepts no positional arguments")
	}
	if recoveryAuth.artifactPath != "" {
		return errors.New("--artifact is not valid for recovery-export")
	}
	passphrase, err := readRecoveryPassphrase(recoveryAuth.passphraseFile)
	if err != nil {
		return err
	}
	_, _, records, err := loadRecordsWithAuth(auth)
	if err != nil {
		return err
	}
	raw, err := recovery.Seal(records, passphrase)
	if err != nil {
		return err
	}
	if err := recovery.Write(*output, raw); err != nil {
		return err
	}
	fmt.Printf("recovery artifact written with %d record(s)\n", len(records))
	return nil
}

func recoveryVerify(args []string) error {
	records, _, err := loadRecoveryRecords(args, "recovery-verify", false)
	if err != nil {
		return err
	}
	fmt.Printf("recovery artifact verified with %d record(s)\n", len(records))
	return nil
}

func recoveryList(args []string) error {
	records, _, err := loadRecoveryRecords(args, "recovery-list", false)
	if err != nil {
		return err
	}
	for _, record := range records {
		policy := "-"
		if record.RotateEveryDays > 0 {
			policy = fmt.Sprintf("%dd", record.RotateEveryDays)
		}
		fmt.Printf("%s\trotation=%s\tsource_revision=%d\n",
			record.Name, policy, record.Revision)
	}
	return nil
}

func recoveryGet(args []string) error {
	records, _, err := loadRecoveryRecords(args, "recovery-get", true)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("recovery-get", flag.ContinueOnError)
	addRecoveryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := fs.Arg(0)
	for _, record := range records {
		if record.Name == name {
			fmt.Print(record.Value)
			return nil
		}
	}
	return errors.New("secret not found")
}

func recoveryRun(args []string) error {
	fs := flag.NewFlagSet("recovery-run", flag.ContinueOnError)
	recoveryAuth := addRecoveryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if recoveryAuth.artifactPath == "" || len(command) == 0 {
		return errors.New("--artifact and COMMAND after -- are required")
	}
	passphrase, err := readRecoveryPassphrase(recoveryAuth.passphraseFile)
	if err != nil {
		return err
	}
	records, _, err := recovery.Read(recoveryAuth.artifactPath, passphrase)
	if err != nil {
		return err
	}
	return executeWithRecords(command, records)
}

func recoveryRestore(args []string) error {
	fs := flag.NewFlagSet("recovery-restore", flag.ContinueOnError)
	resume := fs.Bool("resume", false, "resume uploads using an existing recovery config")
	serverURL := fs.String("server", "", "replacement sync service URL")
	vaultName := fs.String("vault", "", "new vault name")
	deviceName := fs.String("device", "", "new device name")
	recoveryAuth := addRecoveryFlags(fs)
	auth := addAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || recoveryAuth.artifactPath == "" {
		return errors.New("--artifact is required and recovery-restore accepts no positional arguments")
	}
	recoveryPassphrase, err := readRecoveryPassphrase(recoveryAuth.passphraseFile)
	if err != nil {
		return err
	}
	records, artifactID, err := recovery.Read(recoveryAuth.artifactPath, recoveryPassphrase)
	if err != nil {
		return err
	}
	if *resume {
		if *serverURL != "" || *vaultName != "" || *deviceName != "" {
			return errors.New("--server, --vault, and --device are not accepted with --resume")
		}
		return resumeRecoveryRestore(auth, records, artifactID)
	}
	if *serverURL == "" || *vaultName == "" || *deviceName == "" {
		return errors.New("--server, --vault, and --device are required")
	}
	return beginRecoveryRestore(auth, records, artifactID, *serverURL, *vaultName, *deviceName)
}

func beginRecoveryRestore(auth *authFlags, records []protocol.SecretRecord, artifactID, serverURL, vaultName, deviceName string) error {
	if _, err := os.Stat(auth.configPath); err == nil {
		return fmt.Errorf("config already exists at %s", auth.configPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	localPassphrase, err := readPassphrase(auth.passphraseFile)
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
	api := client.NewAPI(serverURL)
	created, err := api.CreateVault(vaultName, protocol.PublicDevice{
		Name: deviceName, SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic,
	})
	if err != nil {
		return err
	}
	cfg, err := client.NewConfig(serverURL, created.VaultID, created.DeviceID,
		deviceName, keys, localPassphrase)
	if err != nil {
		return err
	}
	cfg.RecoveryArtifact = artifactID
	if err := cfg.Lock(keys.Secrets, localPassphrase); err != nil {
		return err
	}
	if err := cfg.Save(auth.configPath); err != nil {
		return fmt.Errorf("replacement vault was created but recovery config could not be saved: %w", err)
	}
	api.Config = cfg
	api.Secrets = keys.Secrets
	if err := restoreRecords(api, vaultKey, records); err != nil {
		return fmt.Errorf("recovery upload incomplete; use recovery-restore --resume with the saved config: %w", err)
	}
	fmt.Printf("restored %d record(s) into new vault %s\n", len(records), created.VaultID)
	return nil
}

func resumeRecoveryRestore(auth *authFlags, records []protocol.SecretRecord, artifactID string) error {
	api, secrets, err := unlockedAPI(auth)
	if err != nil {
		return err
	}
	if api.Config.RecoveryArtifact == "" || api.Config.RecoveryArtifact != artifactID {
		return errors.New("config does not belong to this recovery artifact")
	}
	vaultKey, err := requireVaultKey(secrets)
	if err != nil {
		return err
	}
	if err := restoreRecords(api, vaultKey, records); err != nil {
		return fmt.Errorf("recovery resume failed: %w", err)
	}
	fmt.Printf("recovery complete with %d record(s)\n", len(records))
	return nil
}

func restoreRecords(api *client.API, vaultKey []byte, source []protocol.SecretRecord) error {
	expected := make(map[string]protocol.SecretRecord, len(source))
	expectedIDs := make(map[string]string, len(source))
	for _, recovered := range source {
		recovered.Revision = 1
		expected[recovered.Name] = recovered
		expectedIDs[secure.RecordID(vaultKey, recovered.Name)] = recovered.Name
	}
	present, err := validateRecoveryTarget(api, vaultKey, expected, expectedIDs)
	if err != nil {
		return err
	}
	for _, recovered := range source {
		if _, exists := present[recovered.Name]; exists {
			continue
		}
		recovered.Revision = 1
		id, blob, err := client.EncryptRecord(api.Config.VaultID, vaultKey, recovered)
		if err != nil {
			return err
		}
		if _, err := api.PutRecord(id, protocol.PutRecordRequest{
			ExpectedRevision: 0,
			Blob:             blob,
		}); err != nil {
			return fmt.Errorf("upload %s: %w", recovered.Name, err)
		}
	}
	present, err = validateRecoveryTarget(api, vaultKey, expected, expectedIDs)
	if err != nil {
		return err
	}
	if len(present) != len(expected) {
		return errors.New("replacement vault is missing one or more restored records")
	}
	return nil
}

func validateRecoveryTarget(api *client.API, vaultKey []byte, expected map[string]protocol.SecretRecord, expectedIDs map[string]string) (map[string]struct{}, error) {
	encrypted, err := api.ListRecords()
	if err != nil {
		return nil, err
	}
	for _, record := range encrypted {
		if _, exists := expectedIDs[record.ID]; !exists {
			return nil, errors.New("replacement vault contains an unexpected record")
		}
	}
	existing, err := client.DecryptRecords(api.Config.VaultID, vaultKey, encrypted)
	if err != nil {
		return nil, errors.New("replacement vault key or record contents could not be verified")
	}
	present := make(map[string]struct{}, len(existing))
	for _, record := range existing {
		want, exists := expected[record.Name]
		if !exists {
			return nil, errors.New("replacement vault contains an unexpected record")
		}
		if !reflect.DeepEqual(record, want) {
			return nil, fmt.Errorf("replacement vault contains a conflicting record for %s", record.Name)
		}
		present[record.Name] = struct{}{}
	}
	return present, nil
}

func loadRecoveryRecords(args []string, command string, requireName bool) ([]protocol.SecretRecord, string, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	recoveryAuth := addRecoveryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}
	wantArgs := 0
	if requireName {
		wantArgs = 1
	}
	if recoveryAuth.artifactPath == "" || fs.NArg() != wantArgs {
		return nil, "", fmt.Errorf("--artifact is required and %s expects %d positional argument(s)",
			command, wantArgs)
	}
	passphrase, err := readRecoveryPassphrase(recoveryAuth.passphraseFile)
	if err != nil {
		return nil, "", err
	}
	return recovery.Read(recoveryAuth.artifactPath, passphrase)
}

func readRecoveryPassphrase(path string) ([]byte, error) {
	return readSecretPassphrase(path, "ENVBANK_RECOVERY_PASSPHRASE",
		"--recovery-passphrase-file")
}

func executeWithRecords(command []string, records []protocol.SecretRecord) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append([]string(nil), os.Environ()...)
	cmd.Env = unsetEnv(cmd.Env, "ENVBANK_PASSPHRASE")
	cmd.Env = unsetEnv(cmd.Env, "ENVBANK_RECOVERY_PASSPHRASE")
	for _, record := range records {
		cmd.Env = setEnv(cmd.Env, record.Name, record.Value)
	}
	return cmd.Run()
}
