// Package testlab implements the hermetic, test-only EnvBank workflow runtime.
// It deliberately has no dependency from cmd/envbank.
package testlab

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/mcpserver"
	stripeprovider "github.com/GeorgeQLe/envbank/internal/provider/stripe"
	"github.com/GeorgeQLe/envbank/internal/secure"
	_ "modernc.org/sqlite"
)

const (
	defaultBundle = "full-matrix"
	testVaultID   = "test-vault"
	testManifest  = "5d32b3337fe7d531146b1cb402b607694e92c80ee855c5221cb124d3bbb10bf2"
)

type Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *Clock) Now() time.Time { clock.mu.Lock(); defer clock.mu.Unlock(); return clock.now }
func (clock *Clock) Advance(duration time.Duration) (time.Time, time.Time, error) {
	if duration <= 0 || duration > 31*24*time.Hour {
		return time.Time{}, time.Time{}, errors.New("duration is outside the test bound")
	}
	clock.mu.Lock()
	defer clock.mu.Unlock()
	previous := clock.now
	clock.now = clock.now.Add(duration)
	return previous, clock.now, nil
}

type fault struct {
	Behavior  string `json:"behavior"`
	Remaining int    `json:"remaining"`
}
type operation struct {
	ID                   string    `json:"id"`
	Provider             string    `json:"provider"`
	Bundle               string    `json:"bundle"`
	State                string    `json:"state"`
	Record               string    `json:"record"`
	Revision             int64     `json:"revision"`
	PreviousRevision     int64     `json:"previous_revision"`
	CredentialID         string    `json:"credential_id"`
	PreviousCredentialID string    `json:"previous_credential_id"`
	Resources            []string  `json:"resources"`
	Checkpoints          []string  `json:"checkpoints"`
	StartedAt            time.Time `json:"started_at"`
	FirstHealth          time.Time `json:"first_health"`
	HealthChecks         int       `json:"health_checks"`
	GraceEnds            time.Time `json:"grace_ends"`
	Quarantined          bool      `json:"quarantined"`
	LeaseOwner           string    `json:"lease_owner"`
	ErrorCode            string    `json:"error_code,omitempty"`
	Attempts             int       `json:"attempts"`
}
type persisted struct {
	Sequence    int64                 `json:"sequence"`
	Clock       time.Time             `json:"clock"`
	Operations  map[string]*operation `json:"operations"`
	Records     map[string]record     `json:"records"`
	Faults      map[string]fault      `json:"faults"`
	LeaseOwner  string                `json:"lease_owner"`
	LeaseBundle string                `json:"lease_bundle"`
	Flows       map[string]secretFlow `json:"flows"`
}
type secretFlow struct {
	Provider []byte `json:"provider"`
	Vercel   []byte `json:"vercel"`
	Railway  []byte `json:"railway"`
	Active   bool   `json:"active"`
}
type record struct {
	Revision int64  `json:"revision"`
	Value    []byte `json:"value"`
	Previous []byte `json:"previous,omitempty"`
}

type Lab struct {
	mu        sync.Mutex
	db        *sql.DB
	key       []byte
	oracle    []byte
	signer    ed25519.PrivateKey
	clock     *Clock
	state     persisted
	emulators *providerEmulators
}

func Open(stateDir string) (*Lab, error) {
	if stateDir == "" {
		return nil, errors.New("test state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(stateDir, "device.key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key, err = secure.RandomBytes(32)
		if err == nil {
			err = os.WriteFile(keyPath, key, 0600)
		}
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("test device key is unavailable")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(stateDir, "vault.sqlite"))+"?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS vault_state (id INTEGER PRIMARY KEY CHECK(id=1), blob BLOB NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(filepath.Join(stateDir, "vault.sqlite"), 0600)
	oracle, err := secure.RandomBytes(32)
	if err != nil {
		db.Close()
		return nil, err
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		db.Close()
		return nil, err
	}
	emulators, err := startProviderEmulators()
	if err != nil {
		db.Close()
		return nil, err
	}
	lab := &Lab{db: db, key: key, oracle: oracle, signer: signer, emulators: emulators, clock: &Clock{now: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)}}
	lab.state = persisted{Operations: map[string]*operation{}, Records: map[string]record{}, Faults: map[string]fault{}, Flows: map[string]secretFlow{}}
	if err := lab.load(); err != nil {
		emulators.Close()
		db.Close()
		return nil, err
	}
	return lab, nil
}

func (lab *Lab) Close() error {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	wipe(lab.key)
	wipe(lab.oracle)
	wipe(lab.signer)
	if lab.emulators != nil {
		lab.emulators.Close()
	}
	return lab.db.Close()
}

func (lab *Lab) load() error {
	var raw []byte
	err := lab.db.QueryRow(`SELECT blob FROM vault_state WHERE id=1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return lab.saveLocked()
	}
	if err != nil {
		return err
	}
	var blob secure.Blob
	if json.Unmarshal(raw, &blob) != nil || secure.DecryptJSON(lab.key, blob, []byte("envbank.testlab.state.v1"), &lab.state) != nil {
		return errors.New("encrypted test vault is invalid")
	}
	if lab.state.Operations == nil || lab.state.Records == nil || lab.state.Faults == nil {
		return errors.New("encrypted test vault is invalid")
	}
	if lab.state.Flows == nil {
		lab.state.Flows = map[string]secretFlow{}
	}
	if !lab.state.Clock.IsZero() {
		lab.clock.now = lab.state.Clock
	}
	return nil
}

func (lab *Lab) saveLocked() error {
	lab.state.Clock = lab.clock.Now()
	blob, err := secure.EncryptJSON(lab.key, lab.state, []byte("envbank.testlab.state.v1"))
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(blob)
	_, err = lab.db.Exec(`INSERT INTO vault_state(id,blob) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET blob=excluded.blob`, raw)
	return err
}

func (lab *Lab) Production() mcpserver.Backend  { return productionBackend{lab} }
func (lab *Lab) Extension() mcpserver.Extension { return extensionBackend{lab} }

type productionBackend struct{ lab *Lab }
type extensionBackend struct{ lab *Lab }

func (backend productionBackend) Call(ctx context.Context, name string, request mcpserver.Request) (mcpserver.Result, error) {
	return backend.lab.callProduction(ctx, name, request)
}

func (lab *Lab) callProduction(ctx context.Context, name string, request mcpserver.Request) (mcpserver.Result, error) {
	lab.mu.Lock()
	defer lab.mu.Unlock()
	if (request.VaultID != "" && request.VaultID != testVaultID) || (request.Bundle != "" && request.Bundle != defaultBundle) || (request.ManifestDigest != "" && request.ManifestDigest != testManifest) || (request.PolicyID != "" && request.PolicyID != "test-policy") {
		return mcpserver.Result{BlockerCode: "POLICY_BINDING_MISMATCH"}, nil
	}
	switch name {
	case "envbank_setup_plan":
		return mcpserver.Result{PlanID: "plan-full-matrix", Stage: "ready", ResourceIDs: []string{"stripe-account", "clerk-application", "vercel-project", "railway-project"}}, nil
	case "envbank_workflow_start", "envbank_rotation_run":
		provider := request.Provider
		if provider == "" {
			provider = "stripe"
		}
		return lab.startLocked(ctx, provider)
	case "envbank_workflow_resume":
		return lab.resumeLocked(ctx, request.OperationID)
	case "envbank_workflow_status":
		return lab.resultLocked(request.OperationID)
	case "envbank_rotation_due":
		ids := []string{}
		for id, op := range lab.state.Operations {
			if op.State == "complete" {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		return mcpserver.Result{Stage: "due", ResourceIDs: ids}, nil
	case "envbank_operation_evidence":
		op := lab.state.Operations[request.OperationID]
		if op == nil {
			return mcpserver.Result{BlockerCode: "OPERATION_NOT_FOUND"}, nil
		}
		return mcpserver.Result{OperationID: op.ID, Stage: op.State, ResourceIDs: append([]string(nil), op.Checkpoints...)}, nil
	case "envbank_policy_status":
		return mcpserver.Result{Stage: "valid", ResourceIDs: []string{"test-policy"}}, nil
	default:
		return mcpserver.Result{BlockerCode: "WORKFLOW_UNSUPPORTED"}, nil
	}
}

func (lab *Lab) startLocked(ctx context.Context, provider string) (mcpserver.Result, error) {
	if provider != "stripe" && provider != "clerk" {
		return mcpserver.Result{BlockerCode: "PROVIDER_OUTSIDE_SCENARIO"}, nil
	}
	lab.state.Sequence++
	id := fmt.Sprintf("op-%06d", lab.state.Sequence)
	if lab.state.LeaseOwner != "" {
		return mcpserver.Result{OperationID: id, Stage: "safe-no-op", BlockerCode: "LEASE_HELD"}, nil
	}
	op := &operation{ID: id, Provider: provider, Bundle: defaultBundle, State: "planned", StartedAt: lab.clock.Now(), LeaseOwner: "worker-" + id}
	if provider == "stripe" {
		op.Record = "STRIPE_WEBHOOK_SECRET"
		op.CredentialID = "webhook-" + id
		op.PreviousCredentialID = "webhook-bootstrap"
	} else {
		op.Record = "CLERK_SECRET_KEY"
		op.CredentialID = "key-" + id
		op.PreviousCredentialID = "key-bootstrap"
		op.Checkpoints = append(op.Checkpoints, "simulated-interactive")
	}
	lab.state.Operations[id] = op
	lab.state.LeaseOwner = op.LeaseOwner
	lab.state.LeaseBundle = defaultBundle
	if err := lab.checkpointLocked(op, "acquire"); err != nil {
		return lab.failureLocked(op, err)
	}
	return lab.continueLocked(ctx, op)
}

func (lab *Lab) continueLocked(ctx context.Context, op *operation) (mcpserver.Result, error) {
	if op.Revision == 0 {
		if err := lab.acquireCredentialLocked(ctx, op); err != nil {
			return lab.failureLocked(op, err)
		}
	}
	if err := lab.checkpointLocked(op, "store"); err != nil {
		return lab.failureLocked(op, err)
	}
	op.Resources = []string{"vercel-deployment-" + op.ID, "railway-deployment-" + op.ID}
	for _, stage := range []string{"stage:vercel", "stage:railway", "activate:vercel", "activate:railway", "verify"} {
		if err := lab.checkpointLocked(op, stage); err != nil {
			return lab.failureLocked(op, err)
		}
		if stage == "stage:vercel" || stage == "stage:railway" {
			if err := lab.stageFromRecordLocked(ctx, op, stage); err != nil {
				return lab.failureLocked(op, err)
			}
		}
	}
	flow := lab.state.Flows[op.ID]
	flow.Active = true
	lab.state.Flows[op.ID] = flow
	op.State = "verifying"
	op.FirstHealth = lab.clock.Now()
	op.HealthChecks = 1
	if err := lab.saveLocked(); err != nil {
		return mcpserver.Result{}, err
	}
	return lab.resultLocked(op.ID)
}

func (lab *Lab) acquireCredentialLocked(ctx context.Context, op *operation) error {
	if op.Provider == "stripe" && lab.emulators != nil && lab.emulators.Stripe != nil {
		adapter, err := stripeprovider.New([]byte("testlab-control"), stripeprovider.Options{Endpoint: lab.emulators.Stripe.URL})
		if err != nil {
			return err
		}
		defer adapter.Close()
		identity, err := adapter.Identify(ctx)
		if err != nil {
			return err
		}
		writer := &recordWriter{lab: lab, op: op}
		sink, _ := lifecycle.NewSecretSink(writer, op.Record)
		evidence, err := adapter.Create(ctx, lifecycle.CredentialRequest{ProviderIdentity: identity.ID, CredentialType: "webhook-signing-secret", DestinationRecord: op.Record, IdempotencyKey: op.ID, Parameters: map[string][]string{"url": {"https://receiver.test/webhook"}, "enabled_events": {"checkout.session.completed"}}}, sink)
		if err != nil {
			return err
		}
		op.CredentialID = evidence.CredentialID
		op.Revision = evidence.Receipt.Revision
		value := lab.emulators.stripeSecret(evidence.CredentialID)
		defer wipe(value)
		if len(value) == 0 {
			return errors.New("provider credential capture failed")
		}
		lab.state.Flows[op.ID] = secretFlow{Provider: append([]byte(nil), value...)}
		return nil
	}
	secret, err := synthetic(op.Provider)
	if err != nil {
		return err
	}
	defer wipe(secret)
	lab.state.Flows[op.ID] = secretFlow{Provider: append([]byte(nil), secret...)}
	return lab.storeSecretLocked(ctx, op, secret)
}

func (lab *Lab) resumeLocked(ctx context.Context, id string) (mcpserver.Result, error) {
	op := lab.state.Operations[id]
	if op == nil {
		return mcpserver.Result{BlockerCode: "OPERATION_NOT_FOUND"}, nil
	}
	now := lab.clock.Now()
	if op.State == "retryable" || op.State == "reconciliation-required" {
		return lab.continueLocked(ctx, op)
	}
	if op.State == "verifying" {
		elapsed := now.Sub(op.FirstHealth)
		op.HealthChecks = 1 + int(elapsed/(15*time.Second))
		if op.HealthChecks > 3 {
			op.HealthChecks = 3
		}
		if op.HealthChecks >= 3 && elapsed >= 30*time.Second {
			op.Checkpoints = appendUnique(op.Checkpoints, "healthy")
			op.State = "grace-period"
			op.GraceEnds = now.Add(15 * time.Minute)
		}
	}
	if op.State == "grace-period" && !now.Before(op.GraceEnds) {
		if err := lab.checkpointLocked(op, "revoke"); err != nil {
			return lab.failureLocked(op, err)
		}
		op.State = "complete"
		op.Checkpoints = appendUnique(op.Checkpoints, "complete")
		lab.state.LeaseOwner = ""
		lab.state.LeaseBundle = ""
	}
	if err := lab.saveLocked(); err != nil {
		return mcpserver.Result{}, err
	}
	_ = ctx
	return lab.resultLocked(id)
}

func (lab *Lab) resultLocked(id string) (mcpserver.Result, error) {
	op := lab.state.Operations[id]
	if op == nil {
		return mcpserver.Result{BlockerCode: "OPERATION_NOT_FOUND"}, nil
	}
	health := []mcpserver.HealthEvidence{{CheckID: "deployment-health", SuccessfulChecks: op.HealthChecks, Healthy: op.HealthChecks >= 3}}
	return mcpserver.Result{OperationID: op.ID, Provider: op.Provider, Stage: op.State, ResourceIDs: append([]string(nil), op.Resources...), Health: health, BlockerCode: op.ErrorCode}, nil
}

func (lab *Lab) storeSecretLocked(ctx context.Context, op *operation, value []byte) error {
	writer := &recordWriter{lab: lab, op: op}
	sink, _ := lifecycle.NewSecretSink(writer, op.Record)
	receipt, err := sink.StoreBytes(ctx, value)
	if err != nil {
		return err
	}
	op.Revision = receipt.Revision
	return nil
}

type recordWriter struct {
	lab *Lab
	op  *operation
}

type recordReader struct{ lab *Lab }

func (reader recordReader) ReadSecret(_ context.Context, name string, revision int64, consume func([]byte) error) error {
	record := reader.lab.state.Records[name]
	if record.Revision != revision || len(record.Value) == 0 {
		return errors.New("encrypted record revision changed")
	}
	view := append([]byte(nil), record.Value...)
	defer wipe(view)
	return consume(view)
}

func (lab *Lab) stageFromRecordLocked(ctx context.Context, op *operation, stage string) error {
	source, err := lifecycle.NewSecretSource(recordReader{lab}, op.Record, op.Revision)
	if err != nil {
		return err
	}
	return source.WithSecret(ctx, func(value []byte) error {
		flow := lab.state.Flows[op.ID]
		if stage == "stage:vercel" {
			flow.Vercel = append([]byte(nil), value...)
		} else {
			flow.Railway = append([]byte(nil), value...)
		}
		lab.state.Flows[op.ID] = flow
		return lab.saveLocked()
	})
}

func (writer *recordWriter) StoreSecret(_ context.Context, name string, provide func(func([]byte) error) error) (int64, error) {
	current := writer.lab.state.Records[name]
	err := provide(func(value []byte) error {
		writer.op.PreviousRevision = current.Revision
		current.Previous = append([]byte(nil), current.Value...)
		current.Value = append([]byte(nil), value...)
		current.Revision++
		writer.lab.state.Records[name] = current
		return writer.lab.saveLocked()
	})
	return current.Revision, err
}

func (lab *Lab) checkpointLocked(op *operation, checkpoint string) error {
	op.Checkpoints = appendUnique(op.Checkpoints, checkpoint)
	keys := []string{op.Provider + ":" + checkpoint, "any:" + checkpoint}
	if pieces := strings.SplitN(checkpoint, ":", 2); len(pieces) == 2 {
		keys = append([]string{pieces[1] + ":" + checkpoint}, keys...)
	}
	var key string
	var configured fault
	var ok bool
	for _, candidate := range keys {
		if configured, ok = lab.state.Faults[candidate]; ok {
			key = candidate
			break
		}
	}
	if !ok || configured.Remaining < 1 {
		return lab.saveLocked()
	}
	configured.Remaining--
	lab.state.Faults[key] = configured
	_ = lab.saveLocked()
	return faultError(configured.Behavior)
}
func faultError(behavior string) error { return errors.New(behavior) }
func (lab *Lab) failureLocked(op *operation, err error) (mcpserver.Result, error) {
	behavior := err.Error()
	op.Attempts++
	op.ErrorCode = strings.ToUpper(strings.ReplaceAll(behavior, "-", "_"))
	switch behavior {
	case "ambiguous-commit", "interrupt-after-commit", "timeout":
		op.State = "reconciliation-required"
	case "retryable", "revision-conflict":
		if op.Attempts >= 3 {
			op.State = "terminal-failure"
			op.ErrorCode = "CIRCUIT_OPEN"
			op.Quarantined = op.Revision > 0
		} else {
			op.State = "retryable"
		}
	case "rollback-failure":
		op.State = "terminal-failure"
		op.Quarantined = true
	default:
		op.State = "rolled-back"
		op.Quarantined = true
	}
	if op.State == "rolled-back" {
		current := lab.state.Records[op.Record]
		if len(current.Previous) != 0 {
			wipe(current.Value)
			current.Value = append([]byte(nil), current.Previous...)
			current.Revision++
			current.Previous = nil
			lab.state.Records[op.Record] = current
		}
		op.Checkpoints = appendUnique(op.Checkpoints, "rollback:railway")
		op.Checkpoints = appendUnique(op.Checkpoints, "rollback:vercel")
		op.Checkpoints = appendUnique(op.Checkpoints, "quarantine-new-credential")
	}
	if op.State == "rolled-back" || op.State == "terminal-failure" {
		lab.state.LeaseOwner = ""
		lab.state.LeaseBundle = ""
	}
	_ = lab.saveLocked()
	return lab.resultLocked(op.ID)
}

func synthetic(provider string) ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}
	prefix := "sk_testlab_"
	if provider == "stripe" {
		prefix = "whsec_testlab_"
	}
	return []byte(prefix + base64.RawURLEncoding.EncodeToString(raw)), nil
}
func digest(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return mac.Sum(nil)
}
func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
func appendUnique(values []string, value string) []string {
	for _, item := range values {
		if item == value {
			return values
		}
	}
	return append(values, value)
}
