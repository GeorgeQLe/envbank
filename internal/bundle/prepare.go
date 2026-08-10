package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/contract"
	"github.com/GeorgeQLe/envbank/internal/password"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/vaultobject"
)

const (
	PrepareJournalVersion = 1
	MaxImportBytes        = 1 << 20
	MaxDerivedBytes       = 1 << 20
)

// PrepareJournal is encrypted client-side state. It deliberately contains no
// values or reversible value fingerprints.
type PrepareJournal struct {
	Version        int                      `json:"version"`
	Bundle         string                   `json:"bundle"`
	ManifestDigest string                   `json:"manifest_digest"`
	Records        map[string]JournalRecord `json:"records"`
	UpdatedAt      string                   `json:"updated_at"`
}

type JournalRecord struct {
	Source         string           `json:"source"`
	Revision       int64            `json:"revision"`
	InputRevisions map[string]int64 `json:"input_revisions,omitempty"`
}

func (journal PrepareJournal) Validate() error {
	if journal.Version != PrepareJournalVersion || journal.Bundle == "" ||
		!hexDigest.MatchString(journal.ManifestDigest) || journal.Records == nil {
		return errors.New("bundle prepare journal identity is invalid")
	}
	updated, err := time.Parse(time.RFC3339, journal.UpdatedAt)
	if err != nil || updated.UTC().Format(time.RFC3339) != journal.UpdatedAt {
		return errors.New("bundle prepare journal update time is invalid")
	}
	for name, record := range journal.Records {
		if name == "" || record.Revision < 1 ||
			(record.Source != "generate" && record.Source != "import" && record.Source != "derive") {
			return errors.New("bundle prepare journal record is invalid")
		}
		for input, revision := range record.InputRevisions {
			if input == "" || revision < 1 {
				return errors.New("bundle prepare journal input revision is invalid")
			}
		}
	}
	return nil
}

type Status struct {
	Bundle         string
	ManifestDigest string
	State          string
	Records        map[string]string
}

type Preparer struct {
	API      *client.API
	VaultKey []byte
	Now      func() time.Time
	Generate func(password.Policy) (string, error)
}

// PhysicalName creates a collision-resistant, valid EnvBank record name.
func PhysicalName(bundleID, logicalName string) string {
	sum := sha256.Sum256([]byte(bundleID))
	hash := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return "ENVBANK_B1_" + hash + "_" + logicalName
}

func (p *Preparer) Status(document *contract.Document) (Status, error) {
	records, objects, err := p.load()
	if err != nil {
		return Status{}, err
	}
	return calculateStatus(document, records, objects)
}

// Prepare stores missing inputs, evaluates derived records in manifest order,
// checkpoints after every durable record, and publishes the snapshot last.
func (p *Preparer) Prepare(document *contract.Document, imports io.Reader) (Status, error) {
	if p.API == nil || len(p.VaultKey) != 32 {
		return Status{}, errors.New("bundle preparer is not unlocked")
	}
	records, objects, err := p.load()
	if err != nil {
		return Status{}, err
	}
	status, err := calculateStatus(document, records, objects)
	if err != nil || status.State == "prepared" {
		return status, err
	}

	byPhysical := make(map[string]protocol.SecretRecord, len(records))
	for _, record := range records {
		byPhysical[record.Name] = record
	}
	journal, journalRevision, err := loadJournal(document, objects)
	if err != nil {
		return Status{}, err
	}
	if journal.ManifestDigest != document.Digest {
		journal = newJournal(document, p.now())
		journal, journalRevision, err = p.storeJournal(journal, journalRevision)
		if err != nil {
			return Status{}, conflictError(err)
		}
	}

	missingImports := make([]string, 0)
	for _, name := range sortedRecordNames(document.Manifest.Records) {
		record := document.Manifest.Records[name]
		if record.Source == "import" {
			if _, exists := byPhysical[PhysicalName(document.Manifest.Bundle, name)]; !exists {
				missingImports = append(missingImports, name)
			}
		}
	}
	imported, err := readImports(imports, missingImports)
	if err != nil {
		return Status{}, err
	}
	defer wipeMap(imported)

	generate := p.Generate
	if generate == nil {
		generate = password.Generate
	}
	for _, name := range sortedRecordNames(document.Manifest.Records) {
		spec := document.Manifest.Records[name]
		if spec.Source == "derive" {
			continue
		}
		physical := PhysicalName(document.Manifest.Bundle, name)
		stored, exists := byPhysical[physical]
		if !exists {
			var value []byte
			if spec.Source == "generate" {
				policy := document.Manifest.Policies[spec.Policy]
				generated, generateErr := generate(password.Policy{
					Length: policy.Length, Lowercase: policy.Lowercase, Uppercase: policy.Uppercase,
					Digits: policy.Digits, Symbols: policy.Symbols,
				})
				if generateErr != nil {
					return Status{}, fmt.Errorf("prepare record %s: generation failed", name)
				}
				value = []byte(generated)
			} else {
				value = imported[name]
			}
			stored, err = p.putRecord(physical, value, nil)
			wipe(value)
			if err != nil {
				return Status{}, fmt.Errorf("prepare record %s: %w", name, conflictError(err))
			}
			byPhysical[physical] = stored
		}
		journal.Records[name] = JournalRecord{Source: spec.Source, Revision: stored.Revision}
		journal.UpdatedAt = p.now()
		journal, journalRevision, err = p.storeJournal(journal, journalRevision)
		if err != nil {
			return Status{}, fmt.Errorf("checkpoint record %s: %w", name, conflictError(err))
		}
	}

	for _, name := range document.Derived {
		spec := document.Manifest.Records[name]
		parsed, err := contract.ParseTemplate(spec.Template)
		if err != nil {
			return Status{}, fmt.Errorf("prepare record %s: invalid derivation", name)
		}
		inputs := make(map[string]int64, len(parsed.References))
		for _, reference := range parsed.References {
			inputs[reference] = byPhysical[PhysicalName(document.Manifest.Bundle, reference)].Revision
		}
		physical := PhysicalName(document.Manifest.Bundle, name)
		stored, exists := byPhysical[physical]
		checkpoint, checkpointed := journal.Records[name]
		current := exists && checkpointed && checkpoint.Revision == stored.Revision &&
			equalRevisions(checkpoint.InputRevisions, inputs)
		if !current {
			value, expandErr := expand(parsed, document.Manifest.Bundle, byPhysical)
			if expandErr != nil {
				return Status{}, fmt.Errorf("prepare record %s: %w", name, expandErr)
			}
			var expected *protocol.SecretRecord
			if exists && stored.Value == string(value) {
				current = true
			} else if exists {
				expected = &stored
			}
			if !current {
				stored, err = p.putRecord(physical, value, expected)
			}
			wipe(value)
			if err != nil {
				return Status{}, fmt.Errorf("prepare record %s: %w", name, conflictError(err))
			}
			byPhysical[physical] = stored
		}
		journal.Records[name] = JournalRecord{Source: spec.Source, Revision: stored.Revision, InputRevisions: inputs}
		journal.UpdatedAt = p.now()
		journal, journalRevision, err = p.storeJournal(journal, journalRevision)
		if err != nil {
			return Status{}, fmt.Errorf("checkpoint record %s: %w", name, conflictError(err))
		}
	}

	// Refetch before publishing: a source changed concurrently after our initial
	// read must make this operation fail stale instead of blessing mixed inputs.
	latest, _, err := p.load()
	if err != nil {
		return Status{}, err
	}
	latestByName := make(map[string]protocol.SecretRecord, len(latest))
	for _, record := range latest {
		latestByName[record.Name] = record
	}
	for _, name := range sortedRecordNames(document.Manifest.Records) {
		physical := PhysicalName(document.Manifest.Bundle, name)
		if latestByName[physical].Revision != byPhysical[physical].Revision {
			return Status{}, fmt.Errorf("prepare record %s: stale revision; refetch and start a new prepare operation", name)
		}
	}

	snapshot := Snapshot{
		Version: SnapshotVersion, Bundle: document.Manifest.Bundle, ManifestDigest: document.Digest,
		PhysicalToLogical:       make(map[string]string, len(document.Manifest.Records)),
		Sources:                 make(map[string]SourceStatus, len(document.Manifest.Records)),
		RecordRevisions:         make(map[string]int64, len(document.Manifest.Records)),
		PreviousRecordRevisions: make(map[string][]int64), CreatedAt: p.now(),
	}
	previousSnapshot := findSnapshot(objects, document.Manifest.Bundle)
	for _, name := range sortedRecordNames(document.Manifest.Records) {
		spec := document.Manifest.Records[name]
		physical := PhysicalName(document.Manifest.Bundle, name)
		snapshot.PhysicalToLogical[physical] = name
		snapshot.Sources[name] = SourceStatus{Source: spec.Source, Status: "ready", Sensitivity: spec.Sensitivity}
		snapshot.RecordRevisions[name] = byPhysical[physical].Revision
		if previousSnapshot != nil {
			history := append([]int64(nil), previousSnapshot.PreviousRecordRevisions[name]...)
			if previous := previousSnapshot.RecordRevisions[name]; previous > 0 &&
				previous != snapshot.RecordRevisions[name] {
				history = append(history, previous)
			}
			snapshot.PreviousRecordRevisions[name] = uniqueSortedRevisions(history,
				snapshot.RecordRevisions[name])
			if len(snapshot.PreviousRecordRevisions[name]) == 0 {
				delete(snapshot.PreviousRecordRevisions, name)
			}
		}
	}
	if err := snapshot.Validate(); err != nil {
		return Status{}, err
	}
	snapshotRevision := objectRevision(objects, vaultobject.KindBundleSnapshot, document.Manifest.Bundle)
	if _, err := p.API.PutObject(p.VaultKey, vaultobject.KindBundleSnapshot,
		document.Manifest.Bundle, snapshot, snapshotRevision); err != nil {
		return Status{}, fmt.Errorf("publish bundle snapshot: %w", conflictError(err))
	}
	published, err := p.Status(document)
	if err != nil {
		return Status{}, err
	}
	if published.State != "prepared" {
		return Status{}, errors.New("bundle changed while publishing the snapshot; refetch and start a new prepare operation")
	}
	return published, nil
}

func (p *Preparer) load() ([]protocol.SecretRecord, []vaultobject.VaultObject, error) {
	encrypted, err := p.API.ListRecords()
	if err != nil {
		return nil, nil, err
	}
	records, err := client.DecryptRecords(p.API.Config.VaultID, p.VaultKey, encrypted)
	if err != nil {
		return nil, nil, err
	}
	objects, err := p.API.ListObjects(p.VaultKey)
	return records, objects, err
}

func (p *Preparer) putRecord(name string, value []byte, existing *protocol.SecretRecord) (protocol.SecretRecord, error) {
	now := p.now()
	record := protocol.SecretRecord{Name: name, Value: string(value), CreatedAt: now, RotatedAt: now, Revision: 1}
	var expected int64
	if existing != nil {
		expected = existing.Revision
		record.CreatedAt = existing.CreatedAt
		record.Revision = expected + 1
	}
	id, blob, err := client.EncryptRecord(p.API.Config.VaultID, p.VaultKey, record)
	if err != nil {
		return protocol.SecretRecord{}, err
	}
	if _, err := p.API.PutRecord(id, protocol.PutRecordRequest{ExpectedRevision: expected, Blob: blob}); err != nil {
		return protocol.SecretRecord{}, err
	}
	return record, nil
}

func (p *Preparer) storeJournal(journal PrepareJournal, revision int64) (PrepareJournal, int64, error) {
	stored, err := p.API.PutObject(p.VaultKey, vaultobject.KindBundlePrepare,
		journal.Bundle, journal, revision)
	return journal, stored.Revision, err
}

func (p *Preparer) now() string {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	return now().UTC().Format(time.RFC3339)
}

func calculateStatus(document *contract.Document, records []protocol.SecretRecord, objects []vaultobject.VaultObject) (Status, error) {
	status := Status{Bundle: document.Manifest.Bundle, ManifestDigest: document.Digest,
		State: "prepared", Records: make(map[string]string, len(document.Manifest.Records))}
	byPhysical := make(map[string]protocol.SecretRecord, len(records))
	for _, record := range records {
		byPhysical[record.Name] = record
	}
	var snapshot *Snapshot
	for _, object := range objects {
		if object.Kind != vaultobject.KindBundleSnapshot || object.Key != document.Manifest.Bundle {
			continue
		}
		var candidate Snapshot
		if err := decodeStrict(object.Payload, &candidate); err != nil || candidate.Validate() != nil {
			return Status{}, errors.New("bundle snapshot is invalid")
		}
		snapshot = &candidate
	}
	for _, name := range sortedRecordNames(document.Manifest.Records) {
		record, exists := byPhysical[PhysicalName(document.Manifest.Bundle, name)]
		state := "prepared"
		if !exists {
			state = "missing"
			status.State = "missing"
		} else if snapshot == nil || snapshot.ManifestDigest != document.Digest ||
			snapshot.RecordRevisions[name] != record.Revision ||
			snapshot.PhysicalToLogical[record.Name] != name {
			state = "stale"
			if status.State != "missing" {
				status.State = "stale"
			}
		}
		status.Records[name] = state
	}
	for _, name := range document.Derived {
		if status.Records[name] == "missing" {
			continue
		}
		parsed, err := contract.ParseTemplate(document.Manifest.Records[name].Template)
		if err != nil {
			return Status{}, errors.New("bundle derivation is invalid")
		}
		for _, reference := range parsed.References {
			if status.Records[reference] != "prepared" {
				status.Records[name] = "stale"
				if status.State != "missing" {
					status.State = "stale"
				}
				break
			}
		}
	}
	return status, nil
}

func loadJournal(document *contract.Document, objects []vaultobject.VaultObject) (PrepareJournal, int64, error) {
	journal := newJournal(document, time.Now().UTC().Format(time.RFC3339))
	for _, object := range objects {
		if object.Kind != vaultobject.KindBundlePrepare || object.Key != document.Manifest.Bundle {
			continue
		}
		if err := decodeStrict(object.Payload, &journal); err != nil || journal.Validate() != nil ||
			journal.Bundle != document.Manifest.Bundle {
			return PrepareJournal{}, 0, errors.New("bundle prepare journal is invalid")
		}
		return journal, object.Revision, nil
	}
	return journal, 0, nil
}

func newJournal(document *contract.Document, now string) PrepareJournal {
	return PrepareJournal{Version: PrepareJournalVersion, Bundle: document.Manifest.Bundle,
		ManifestDigest: document.Digest, Records: map[string]JournalRecord{}, UpdatedAt: now}
}

func readImports(reader io.Reader, required []string) (map[string][]byte, error) {
	result := make(map[string][]byte, len(required))
	if len(required) == 0 {
		return result, nil
	}
	if reader == nil {
		return nil, errors.New("missing imported records on trusted stdin")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxImportBytes+1))
	if err != nil {
		return nil, errors.New("read trusted stdin imports")
	}
	defer wipe(raw)
	if len(raw) > MaxImportBytes {
		return nil, fmt.Errorf("trusted stdin imports exceed %d bytes", MaxImportBytes)
	}
	values, err := decodeImportObject(raw)
	if err != nil {
		return nil, errors.New("trusted stdin imports must be one JSON object of string values")
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, name := range required {
		requiredSet[name] = struct{}{}
		value, ok := values[name]
		if !ok {
			return nil, fmt.Errorf("trusted stdin is missing record %s", name)
		}
		result[name] = []byte(value)
	}
	for name := range values {
		if _, ok := requiredSet[name]; !ok {
			return nil, errors.New("trusted stdin contains an unexpected record")
		}
	}
	return result, nil
}

func decodeImportObject(raw []byte) (map[string]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("imports are not an object")
	}
	values := map[string]string{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("import key is not a string")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate import key")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		values[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("imports object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON data")
	}
	return values, nil
}

func expand(template contract.Template, bundleID string, records map[string]protocol.SecretRecord) ([]byte, error) {
	var output bytes.Buffer
	for _, node := range template.Nodes {
		part := []byte(node.Literal)
		if node.Reference != "" {
			part = []byte(records[PhysicalName(bundleID, node.Reference)].Value)
		}
		if output.Len()+len(part) > MaxDerivedBytes {
			return nil, fmt.Errorf("derived value exceeds %d bytes", MaxDerivedBytes)
		}
		_, _ = output.Write(part)
	}
	return output.Bytes(), nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func sortedRecordNames(records map[string]contract.Record) []string {
	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func objectRevision(objects []vaultobject.VaultObject, kind, key string) int64 {
	for _, object := range objects {
		if object.Kind == kind && object.Key == key {
			return object.Revision
		}
	}
	return 0
}

func findSnapshot(objects []vaultobject.VaultObject, bundleID string) *Snapshot {
	for _, object := range objects {
		if object.Kind != vaultobject.KindBundleSnapshot || object.Key != bundleID {
			continue
		}
		var snapshot Snapshot
		if decodeStrict(object.Payload, &snapshot) == nil && snapshot.Validate() == nil {
			return &snapshot
		}
	}
	return nil
}

func uniqueSortedRevisions(revisions []int64, current int64) []int64 {
	seen := make(map[int64]struct{}, len(revisions))
	result := make([]int64, 0, len(revisions))
	for _, revision := range revisions {
		if revision < 1 || revision == current {
			continue
		}
		if _, exists := seen[revision]; exists {
			continue
		}
		seen[revision] = struct{}{}
		result = append(result, revision)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func equalRevisions(left, right map[string]int64) bool {
	if len(left) != len(right) {
		return false
	}
	for name, revision := range left {
		if right[name] != revision {
			return false
		}
	}
	return true
}

func conflictError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("optimistic write failed; refetch and start a new prepare operation: %w", err)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func wipeMap(values map[string][]byte) {
	for _, value := range values {
		wipe(value)
	}
}
