// Package rotationrun turns a manifest credential into rotation engine
// operations. It supplies the engine's two vault-facing collaborators, a
// record writer that advances the bundle snapshot and a per-record binding
// that remembers which upstream credential is live, and exposes the result
// to the CLI and the MCP rotation tools.
package rotationrun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/bundle"
	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/rotation"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
	"github.com/GeorgeQLe/envbank/internal/vercelworkflow"
)

const BindingVersion = 1

var credentialIDPattern = regexp.MustCompile(`^[a-z-]+:[A-Za-z0-9._:/-]{1,255}$`)

// Binding records which upstream credential currently backs a record. It is
// names and identifiers only. The trigger reads it to pick the standby
// alternate and to name the credential the engine retires.
type Binding struct {
	Version        int    `json:"version"`
	Bundle         string `json:"bundle"`
	Record         string `json:"record"`
	CredentialID   string `json:"credential_id"`
	RecordRevision int64  `json:"record_revision"`
	OperationID    string `json:"operation_id,omitempty"`
	UpdatedAt      string `json:"updated_at"`
}

func (binding Binding) Validate() error {
	if binding.Version != BindingVersion || binding.Bundle == "" || binding.Record == "" || !credentialIDPattern.MatchString(binding.CredentialID) || binding.RecordRevision < 1 {
		return errors.New("credential binding is invalid")
	}
	if _, err := time.Parse(time.RFC3339, binding.UpdatedAt); err != nil {
		return errors.New("credential binding time is invalid")
	}
	return nil
}

func BindingKey(bundleID, record string) string { return bundleID + "/" + record }

// VaultAPI is the slice of client.API the package needs, so tests can supply
// an in-memory vault.
type VaultAPI interface {
	ListRecords() ([]protocol.Record, error)
	PutRecord(string, protocol.PutRecordRequest) (protocol.Record, error)
	GetObject([]byte, string, string) (vaultobject.VaultObject, error)
	PutObject([]byte, string, string, any, int64) (vaultobject.VaultObject, error)
}

// Vault is the encrypted vault seen through one device's unlocked key.
type Vault struct {
	API      VaultAPI
	VaultID  string
	VaultKey []byte
	Now      func() time.Time
}

func (vault *Vault) ready() error {
	if vault == nil || vault.API == nil || vault.VaultID == "" || len(vault.VaultKey) != 32 {
		return errors.New("rotation vault is not unlocked")
	}
	return nil
}
func (vault *Vault) now() time.Time {
	if vault.Now != nil {
		return vault.Now().UTC()
	}
	return time.Now().UTC()
}

func (vault *Vault) LoadBinding(bundleID, record string) (Binding, int64, error) {
	if err := vault.ready(); err != nil {
		return Binding{}, 0, err
	}
	object, err := vault.API.GetObject(vault.VaultKey, vaultobject.KindCredentialBinding, BindingKey(bundleID, record))
	if err != nil {
		return Binding{}, 0, err
	}
	var binding Binding
	if err := decodeStrict(object.Payload, &binding); err != nil || binding.Validate() != nil || binding.Bundle != bundleID || binding.Record != record {
		return Binding{}, 0, errors.New("encrypted credential binding is invalid")
	}
	return binding, object.Revision, nil
}

func (vault *Vault) SaveBinding(binding Binding, expected int64) (int64, error) {
	if err := vault.ready(); err != nil {
		return 0, err
	}
	if err := binding.Validate(); err != nil {
		return 0, err
	}
	object, err := vault.API.PutObject(vault.VaultKey, vaultobject.KindCredentialBinding, BindingKey(binding.Bundle, binding.Record), binding, expected)
	return object.Revision, err
}

// RecordStore implements lifecycle.RecordWriter over the vault. Storing a
// logical record writes the bundle's physical record at its next revision
// and advances the bundle snapshot to that revision, so the deployer plans
// the value the engine just stored and nothing older.
type RecordStore struct {
	Vault    *Vault
	Document *contract.Document
}

func (store *RecordStore) StoreSecret(_ context.Context, logical string, provide func(func([]byte) error) error) (int64, error) {
	if store == nil || store.Document == nil || provide == nil {
		return 0, errors.New("record store is not configured")
	}
	vault := store.Vault
	if err := vault.ready(); err != nil {
		return 0, err
	}
	if _, ok := store.Document.Manifest.Records[logical]; !ok {
		return 0, errors.New("record is not declared by the manifest")
	}
	bundleID := store.Document.Manifest.Bundle
	physical := bundle.PhysicalName(bundleID, logical)
	encrypted, err := vault.API.ListRecords()
	if err != nil {
		return 0, err
	}
	records, err := client.DecryptRecords(vault.VaultID, vault.VaultKey, encrypted)
	if err != nil {
		return 0, err
	}
	var existing *protocol.SecretRecord
	for index := range records {
		if records[index].Name == physical {
			existing = &records[index]
		}
	}
	snapshot, snapshotRevision, err := vault.loadSnapshot(bundleID)
	if err != nil {
		return 0, errors.New("bundle snapshot unavailable; prepare the bundle first")
	}
	if snapshot.ManifestDigest != store.Document.Digest || (existing != nil && snapshot.RecordRevisions[logical] != existing.Revision) {
		return 0, errors.New("bundle snapshot is stale; prepare the bundle first")
	}
	now := vault.now().Format(time.RFC3339)
	var revision int64
	err = provide(func(value []byte) error {
		record := protocol.SecretRecord{Name: physical, Value: string(value), CreatedAt: now, RotatedAt: now, Revision: 1}
		var expected int64
		if existing != nil {
			expected = existing.Revision
			record.CreatedAt = existing.CreatedAt
			record.RotateEveryDays = existing.RotateEveryDays
			record.AllowedOrigins = existing.AllowedOrigins
			record.Revision = expected + 1
		}
		id, blob, err := client.EncryptRecord(vault.VaultID, vault.VaultKey, record)
		if err != nil {
			return err
		}
		if _, err := vault.API.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
			return err
		}
		revision = record.Revision
		return nil
	})
	if err != nil {
		return 0, err
	}
	if previous := snapshot.RecordRevisions[logical]; previous > 0 && previous != revision {
		if snapshot.PreviousRecordRevisions == nil {
			snapshot.PreviousRecordRevisions = map[string][]int64{}
		}
		snapshot.PreviousRecordRevisions[logical] = append(snapshot.PreviousRecordRevisions[logical], previous)
	}
	snapshot.RecordRevisions[logical] = revision
	snapshot.CreatedAt = now
	if err := snapshot.Validate(); err != nil {
		return 0, err
	}
	if _, err := vault.API.PutObject(vault.VaultKey, vaultobject.KindBundleSnapshot, bundleID, snapshot, snapshotRevision); err != nil {
		// The record advanced but the snapshot did not: the engine treats the
		// store as failed and reconciles rather than deploying a stale plan.
		return 0, errors.New("bundle snapshot could not be advanced")
	}
	return revision, nil
}

func (vault *Vault) loadSnapshot(bundleID string) (bundle.Snapshot, int64, error) {
	object, err := vault.API.GetObject(vault.VaultKey, vaultobject.KindBundleSnapshot, bundleID)
	if err != nil {
		return bundle.Snapshot{}, 0, err
	}
	var snapshot bundle.Snapshot
	if err := decodeStrict(object.Payload, &snapshot); err != nil || snapshot.Validate() != nil || snapshot.Bundle != bundleID {
		return bundle.Snapshot{}, 0, errors.New("encrypted bundle snapshot is invalid")
	}
	return snapshot, object.Revision, nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Runner plans and runs rotations for one manifest.
type Runner struct {
	Engine   *rotation.Engine
	Vault    *Vault
	Document *contract.Document
}

var ErrUnbound = errors.New("record has no bound upstream credential; run envbank rotation bind first")

func (runner *Runner) ready() error {
	if runner == nil || runner.Engine == nil || runner.Vault == nil || runner.Document == nil {
		return errors.New("rotation runner is not configured")
	}
	return runner.Vault.ready()
}

func (runner *Runner) snapshot() (bundle.Snapshot, error) {
	snapshot, _, err := runner.Vault.loadSnapshot(runner.Document.Manifest.Bundle)
	return snapshot, err
}

// Credential resolves a manifest credential that the runner can rotate.
func (runner *Runner) Credential(name string) (contract.Credential, error) {
	credential, ok := runner.Document.Manifest.Credentials[name]
	if !ok {
		return contract.Credential{}, errors.New("manifest does not declare that credential")
	}
	if credential.Mode != "automatic" {
		return contract.Credential{}, errors.New("credential is interactive; it cannot be rotated without the owner")
	}
	return credential, nil
}

// Target is the single Vercel target every rotation of this manifest
// activates against.
func (runner *Runner) Target() (lifecycle.TargetPolicy, error) {
	scope, err := vercelworkflow.ScopeForManifest(runner.Document)
	if err != nil {
		return lifecycle.TargetPolicy{}, err
	}
	return lifecycle.TargetPolicy{Provider: "vercel", ProjectID: scope.ProjectID, EnvironmentID: scope.Target().EnvironmentID}, nil
}

// Bind records the upstream credential that currently backs a record. The
// owner runs it once before the first rotation; afterwards the runner keeps
// it current itself.
func (runner *Runner) Bind(ctx context.Context, name, credentialID string) (Binding, error) {
	if err := runner.ready(); err != nil {
		return Binding{}, err
	}
	credential, err := runner.Credential(name)
	if err != nil {
		return Binding{}, err
	}
	if !strings.HasPrefix(credentialID, prefixFor(credential)) {
		return Binding{}, fmt.Errorf("credential id must start with %q", prefixFor(credential))
	}
	if parameter, alternates := contract.AlternateParameter(credential.Provider, credential.Type); alternates {
		if _, ok := alternateOf(credential, credentialID); !ok {
			return Binding{}, fmt.Errorf("credential id does not name one of the manifest alternates for %s", parameter)
		}
	}
	snapshot, err := runner.snapshot()
	if err != nil {
		return Binding{}, errors.New("bundle snapshot unavailable; prepare the bundle first")
	}
	revision := snapshot.RecordRevisions[credential.Record]
	if revision < 1 {
		return Binding{}, errors.New("record has no prepared revision; prepare the bundle first")
	}
	_, expected, err := runner.Vault.LoadBinding(runner.Document.Manifest.Bundle, credential.Record)
	if err != nil {
		expected = 0
	}
	binding := Binding{Version: BindingVersion, Bundle: runner.Document.Manifest.Bundle, Record: credential.Record, CredentialID: credentialID, RecordRevision: revision, UpdatedAt: runner.Vault.now().Format(time.RFC3339)}
	if _, err := runner.Vault.SaveBinding(binding, expected); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// Plan creates a planned operation for one credential under a policy. For an
// alternating credential it mints for the alternate that is not bound now.
func (runner *Runner) Plan(ctx context.Context, name, policyID string) (lifecycle.Operation, error) {
	if err := runner.ready(); err != nil {
		return lifecycle.Operation{}, err
	}
	credential, err := runner.Credential(name)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	target, err := runner.Target()
	if err != nil {
		return lifecycle.Operation{}, err
	}
	binding, _, err := runner.Vault.LoadBinding(runner.Document.Manifest.Bundle, credential.Record)
	if err != nil {
		return lifecycle.Operation{}, ErrUnbound
	}
	snapshot, err := runner.snapshot()
	if err != nil {
		return lifecycle.Operation{}, errors.New("bundle snapshot unavailable; prepare the bundle first")
	}
	if snapshot.ManifestDigest != runner.Document.Digest {
		return lifecycle.Operation{}, errors.New("bundle snapshot is stale; prepare the bundle first")
	}
	revision := snapshot.RecordRevisions[credential.Record]
	if revision < 1 || revision != binding.RecordRevision {
		return lifecycle.Operation{}, errors.New("record revision changed outside rotation; rebind the credential")
	}
	parameters := make(map[string][]string, len(credential.Parameters)+1)
	for key, value := range credential.Parameters {
		parameters[key] = []string{value}
	}
	if parameter, alternates := contract.AlternateParameter(credential.Provider, credential.Type); alternates {
		standby, err := standbyAlternate(credential, binding.CredentialID)
		if err != nil {
			return lifecycle.Operation{}, err
		}
		parameters[parameter] = []string{standby}
	}
	identity, err := runner.Engine.Credentials.Identify(ctx)
	if err != nil || identity.Provider != credential.Provider {
		return lifecycle.Operation{}, errors.New("provider control credential does not match the manifest provider")
	}
	id, err := operationID()
	if err != nil {
		return lifecycle.Operation{}, err
	}
	return runner.Engine.Plan(ctx, rotation.PlanInput{OperationID: id, PolicyID: policyID, Bundle: runner.Document.Manifest.Bundle, ManifestDigest: runner.Document.Digest, Provider: credential.Provider, ProviderIdentity: identity.ID, CredentialClass: credential.Type, DestinationRecord: credential.Record, PreviousRecordRevision: revision, PreviousCredentialID: binding.CredentialID, Target: target, CreateParameters: parameters})
}

// Run advances an operation and, once the new credential serves traffic,
// rebinds the record to it so the next rotation retires the right one.
func (runner *Runner) Run(ctx context.Context, operationID string) (lifecycle.Operation, error) {
	if err := runner.ready(); err != nil {
		return lifecycle.Operation{}, err
	}
	operation, err := runner.Engine.Run(ctx, operationID)
	if err != nil {
		return operation, err
	}
	if operation.NewCredentialID != "" && (operation.State == lifecycle.StateGracePeriod || operation.State == lifecycle.StateRevoking || operation.State == lifecycle.StateComplete) {
		if err := runner.rebind(operation); err != nil {
			return operation, err
		}
	}
	return operation, nil
}

func (runner *Runner) rebind(operation lifecycle.Operation) error {
	current, expected, err := runner.Vault.LoadBinding(operation.Bundle, operation.DestinationRecord)
	if err != nil {
		expected = 0
	} else if current.CredentialID == operation.NewCredentialID && current.RecordRevision == operation.NewRecordRevision {
		return nil
	}
	binding := Binding{Version: BindingVersion, Bundle: operation.Bundle, Record: operation.DestinationRecord, CredentialID: operation.NewCredentialID, RecordRevision: operation.NewRecordRevision, OperationID: operation.ID, UpdatedAt: runner.Vault.now().Format(time.RFC3339)}
	if _, err := runner.Vault.SaveBinding(binding, expected); err != nil {
		return fmt.Errorf("rotation succeeded but the credential binding could not be updated: %w", err)
	}
	return nil
}

func prefixFor(credential contract.Credential) string {
	switch credential.Provider + "/" + credential.Type {
	case "neon/role-password":
		return "role:"
	case "neon/api-key":
		return "api-key:"
	case "stripe/webhook-signing-secret":
		return "we_"
	}
	return ""
}

// alternateOf extracts which alternate a credential ID names.
func alternateOf(credential contract.Credential, credentialID string) (string, bool) {
	for _, alternate := range credential.Alternates {
		if strings.HasSuffix(credentialID, "/"+alternate) {
			return alternate, true
		}
	}
	return "", false
}

func standbyAlternate(credential contract.Credential, currentID string) (string, error) {
	current, ok := alternateOf(credential, currentID)
	if !ok {
		return "", errors.New("bound credential does not name a manifest alternate; rebind the credential")
	}
	for _, alternate := range credential.Alternates {
		if alternate != current {
			return alternate, nil
		}
	}
	return "", errors.New("no standby alternate available")
}

func operationID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("operation id could not be generated")
	}
	return "rot-" + hex.EncodeToString(raw), nil
}
