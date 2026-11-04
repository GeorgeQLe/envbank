package vercel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	maxSecretBytes = 64 << 10
	maxEnvEntries  = 5000
	writeComment   = "Managed by EnvBank"
)

// Capabilities are deliberately conservative: there is no revoke path, no
// provider idempotency key, upserts are not treated as safely retryable, and
// presence is names-only metadata.
func (*Adapter) Capabilities() provider.Capabilities {
	return provider.Capabilities{Create: true, ReadMetadata: true, Update: true, Validate: true,
		SupportsMaskedPresence: true}
}

// Identity proves the credential can read the exact project and that the
// project is owned by the exact team.
func (adapter *Adapter) Identity(ctx context.Context) (provider.Identity, error) {
	if _, err := adapter.verifiedProject(ctx, "identity"); err != nil {
		return provider.Identity{}, err
	}
	return provider.Identity{Provider: ProviderName, ID: adapter.scope.TeamID + ":" + adapter.scope.ProjectID}, nil
}

// Bind proves ownership (and the custom environment, if any) and returns the
// immutable target binding for this scope.
func (adapter *Adapter) Bind(ctx context.Context) (provider.Target, error) {
	if _, err := adapter.verifiedProject(ctx, "bind"); err != nil {
		return provider.Target{}, err
	}
	return adapter.scope.Target(), nil
}

// Inspect reports names-only metadata for keys relevant to this scope. A key
// is "present" only when exactly one exact-scope, EnvBank-writable sensitive
// entry exists; duplicate, overlapping, case-colliding, non-sensitive or
// integration-managed entries are reported "unknown" and Write refuses them.
func (adapter *Adapter) Inspect(ctx context.Context, target provider.Target) (provider.MetadataState, error) {
	if !adapter.scope.matchesTarget(target) {
		return provider.MetadataState{}, safeError("inspect", "TARGET_SCOPE_MISMATCH", provider.RetryNever)
	}
	if _, err := adapter.verifiedProject(ctx, "inspect"); err != nil {
		return provider.MetadataState{}, err
	}
	entries, err := adapter.listEnv(ctx, "inspect")
	if err != nil {
		return provider.MetadataState{}, err
	}
	states := adapter.scope.keyStates(entries)
	variables := make(map[string]provider.VariableMetadata, len(states))
	for name, state := range states {
		variables[name] = provider.VariableMetadata{Presence: state.presence()}
	}
	return provider.MetadataState{Target: adapter.scope.Target(),
		Variables: map[string]map[string]provider.VariableMetadata{ServiceName: variables},
		Revision:  adapter.scope.revision(entries)}, nil
}

// Write upserts exactly one sensitive variable into exactly this scope after
// a fresh ownership and metadata check. It never retries.
func (adapter *Adapter) Write(ctx context.Context, request provider.WriteRequest) (provider.WriteEvidence, error) {
	if request.Operation != "upsert" || !adapter.scope.matchesTarget(request.Target) ||
		request.Service != ServiceName || request.ServiceID != adapter.scope.Fingerprint() {
		return provider.WriteEvidence{}, safeError("write", "INVALID_WRITE", provider.RetryNever)
	}
	if !validSecretName(request.Name) {
		return provider.WriteEvidence{}, safeError("write", "NAME_NOT_ALLOWED", provider.RetryNever)
	}
	if _, err := adapter.verifiedProject(ctx, "write"); err != nil {
		return provider.WriteEvidence{}, readFailureBeforeWrite(err)
	}
	entries, err := adapter.listEnv(ctx, "write")
	if err != nil {
		return provider.WriteEvidence{}, readFailureBeforeWrite(err)
	}
	state := adapter.scope.stateFor(entries, request.Name)
	if state.presence() == provider.PresenceUnknown {
		return provider.WriteEvidence{}, safeError("write", "AMBIGUOUS_EXISTING_ENTRIES", provider.RetryNever)
	}
	existingID := ""
	if state.presence() == provider.PresencePresent {
		existingID = state.exact[0].ID
	}
	var created createdEnv
	err = request.ViewSecret(func(value []byte) error {
		if len(value) == 0 || len(value) > maxSecretBytes || !utf8.Valid(value) {
			return safeError("write", "VALUE_NOT_ALLOWED", provider.RetryNever)
		}
		body := adapter.scope.upsertBody(request.Name, value)
		defer wipe(body)
		query := url.Values{"upsert": {"true"}}
		return adapter.send(ctx, apiCall{operation: "write", method: http.MethodPost,
			path: "/v10/projects" + pathSegment(adapter.scope.ProjectID) + "/env", query: query,
			body: body, mutation: true}, func(raw []byte) error { return decodeUpsert(raw, &created) })
	})
	if err != nil {
		return provider.WriteEvidence{}, err
	}
	if !adapter.scope.createdMatches(created, request.Name) {
		return provider.WriteEvidence{}, safeError("write", "WRITE_SCOPE_MISMATCH", provider.RetryNever)
	}
	if existingID != "" && created.ID != existingID {
		return provider.WriteEvidence{}, safeError("write", "WRITE_IDENTITY_DRIFT", provider.RetryNever)
	}
	return provider.WriteEvidence{ProviderOperationID: created.ID, CommittedAt: adapter.timestamp()}, nil
}

// Verify is always VerificationLimited: it proves names-only metadata in this
// exact scope, never the stored value.
func (adapter *Adapter) Verify(ctx context.Context, request provider.VerifyRequest) (provider.VerifyEvidence, error) {
	expected := request.ExpectedPresence
	if expected == "" {
		expected = provider.PresencePresent
	}
	if !adapter.scope.matchesTarget(request.Target) || request.Service != ServiceName ||
		request.ServiceID != adapter.scope.Fingerprint() || !envKeyPattern.MatchString(request.Name) ||
		(expected != provider.PresencePresent && expected != provider.PresenceAbsent) ||
		(request.ProviderOperationID != "" && !envVarIDPattern.MatchString(request.ProviderOperationID)) {
		return provider.VerifyEvidence{}, safeError("verify", "INVALID_VERIFY", provider.RetryNever)
	}
	if _, err := adapter.verifiedProject(ctx, "verify"); err != nil {
		return provider.VerifyEvidence{}, err
	}
	entries, err := adapter.listEnv(ctx, "verify")
	if err != nil {
		return provider.VerifyEvidence{}, err
	}
	state := adapter.scope.stateFor(entries, request.Name)
	presence, reason := state.presence(), "metadata-presence-only"
	switch {
	case presence == provider.PresenceUnknown:
		reason = "ambiguous-entries"
	case presence == provider.PresencePresent && request.ProviderOperationID != "" &&
		state.exact[0].ID != request.ProviderOperationID:
		presence, reason = provider.PresenceUnknown, "operation-id-mismatch"
	case presence != expected:
		reason = "presence-mismatch"
	}
	return provider.VerifyEvidence{Result: provider.VerificationLimited, Presence: presence,
		VerifiedAt: adapter.timestamp(), Reason: reason}, nil
}

// readFailureBeforeWrite keeps pre-write read failures non-ambiguous: no
// mutation has been sent yet.
func readFailureBeforeWrite(err error) error {
	safe := provider.SanitizeError("write", err)
	if safe.Retry == provider.RetryAmbiguous {
		safe.Retry = provider.RetrySafe
	}
	return safe
}

type projectInfo struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	AccountID          string `json:"accountId"`
	CustomEnvironments *[]struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"customEnvironments"`
	LastAliasRequest *struct {
		JobStatus string `json:"jobStatus"`
	} `json:"lastAliasRequest"`
}

// verifiedProject proves the project ID and owning team. Only the listed
// fields are decoded; other project fields (including any env data) are
// discarded with the wiped buffer.
func (adapter *Adapter) verifiedProject(ctx context.Context, operation string) (projectInfo, error) {
	var project projectInfo
	err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
		path: "/v9/projects" + pathSegment(adapter.scope.ProjectID)}, func(raw []byte) error {
		return json.Unmarshal(raw, &project)
	})
	if err != nil {
		return projectInfo{}, err
	}
	if project.ID != adapter.scope.ProjectID || project.AccountID != adapter.scope.TeamID {
		return projectInfo{}, safeError(operation, "PROJECT_OWNERSHIP_MISMATCH", provider.RetryNever)
	}
	if !projectNamePattern.MatchString(project.Name) {
		return projectInfo{}, safeError(operation, "PROJECT_METADATA_INVALID", provider.RetryNever)
	}
	if adapter.scope.Environment == EnvironmentCustom {
		matches := 0
		if project.CustomEnvironments != nil {
			for _, environment := range *project.CustomEnvironments {
				if environment.ID == adapter.scope.CustomEnvironmentID {
					matches++
					if environment.Type != EnvironmentPreview {
						return projectInfo{}, safeError(operation, "CUSTOM_ENVIRONMENT_TYPE", provider.RetryNever)
					}
				}
			}
		}
		if matches != 1 {
			return projectInfo{}, safeError(operation, "CUSTOM_ENVIRONMENT_UNVERIFIED", provider.RetryNever)
		}
	}
	return project, nil
}

type targetList []string

func (targets *targetList) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		*targets = nil
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var single string
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return err
		}
		*targets = targetList{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(trimmed, &many); err != nil {
		return err
	}
	*targets = many
	return nil
}

// envEntry deliberately has no value, vsmValue, legacyValue or content-hint
// fields: those are never decoded.
type envEntry struct {
	ID                   string      `json:"id"`
	Key                  string      `json:"key"`
	Type                 string      `json:"type"`
	Target               targetList  `json:"target"`
	GitBranch            *string     `json:"gitBranch"`
	CustomEnvironmentIDs []string    `json:"customEnvironmentIds"`
	ConfigurationID      *string     `json:"configurationId"`
	EdgeConfigID         *string     `json:"edgeConfigId"`
	EdgeConfigTokenID    *string     `json:"edgeConfigTokenId"`
	System               *bool       `json:"system"`
	Decrypted            *bool       `json:"decrypted"`
	UpdatedAt            json.Number `json:"updatedAt"`
}

func (adapter *Adapter) listEnv(ctx context.Context, operation string) ([]envEntry, error) {
	var listing struct {
		Envs       *[]envEntry `json:"envs"`
		Pagination *struct {
			Next *json.Number `json:"next"`
		} `json:"pagination"`
		HiddenProductionEnvCount *json.Number `json:"hiddenProductionEnvCount"`
	}
	// The full project list (no branch/custom filter) is fetched so entries
	// that overlap this scope are visible. decrypt=false is always explicit.
	err := adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet,
		path:  "/v10/projects" + pathSegment(adapter.scope.ProjectID) + "/env",
		query: url.Values{"decrypt": {"false"}}}, func(raw []byte) error {
		return json.Unmarshal(raw, &listing)
	})
	if err != nil {
		return nil, err
	}
	if listing.Envs == nil || len(*listing.Envs) > maxEnvEntries {
		return nil, safeError(operation, "ENV_LIST_INVALID", provider.RetryNever)
	}
	if listing.Pagination != nil && listing.Pagination.Next != nil {
		return nil, safeError(operation, "ENV_LIST_INCOMPLETE", provider.RetryNever)
	}
	if listing.HiddenProductionEnvCount != nil && listing.HiddenProductionEnvCount.String() != "0" {
		return nil, safeError(operation, "ENV_LIST_HIDDEN_ENTRIES", provider.RetryNever)
	}
	for _, entry := range *listing.Envs {
		if entry.Decrypted != nil && *entry.Decrypted {
			return nil, safeError(operation, "UNEXPECTED_DECRYPTED_RESPONSE", provider.RetryNever)
		}
	}
	return *listing.Envs, nil
}

type relation int

const (
	relationDisjoint relation = iota
	relationExact
	relationOverlap
)

// relate classifies how an upsert in this scope could interact with entry.
// Only entries proven disjoint are ignored; anything unrecognised overlaps.
func (scope Scope) relate(entry envEntry) relation {
	targets := map[string]bool{}
	for _, target := range entry.Target {
		switch target {
		case EnvironmentProduction, EnvironmentPreview, "development":
			targets[target] = true
		default:
			return relationOverlap
		}
	}
	branch := ""
	if entry.GitBranch != nil {
		branch = *entry.GitBranch
	}
	customs := entry.CustomEnvironmentIDs
	switch scope.Environment {
	case EnvironmentProduction:
		if !targets[EnvironmentProduction] {
			return relationDisjoint
		}
		if len(targets) == 1 && branch == "" && len(customs) == 0 {
			return relationExact
		}
	case EnvironmentPreview:
		if !targets[EnvironmentPreview] {
			return relationDisjoint
		}
		if len(targets) == 1 && len(customs) == 0 {
			if branch == scope.GitBranch {
				return relationExact
			}
			// A single-target preview entry for a different exact branch
			// (or all branches) is a distinct Vercel entry.
			return relationDisjoint
		}
	case EnvironmentCustom:
		found := false
		for _, custom := range customs {
			found = found || custom == scope.CustomEnvironmentID
		}
		if !found {
			return relationDisjoint
		}
		if len(customs) == 1 && len(targets) == 0 && branch == "" {
			return relationExact
		}
	}
	return relationOverlap
}

type keyState struct {
	exact   []envEntry
	overlap int
}

func (state keyState) presence() provider.Presence {
	switch {
	case state.overlap == 0 && len(state.exact) == 0:
		return provider.PresenceAbsent
	case state.overlap == 0 && len(state.exact) == 1 && writableEntry(state.exact[0]):
		return provider.PresencePresent
	default:
		return provider.PresenceUnknown
	}
}

func writableEntry(entry envEntry) bool {
	return entry.Type == "sensitive" && envVarIDPattern.MatchString(entry.ID) &&
		emptyString(entry.ConfigurationID) && emptyString(entry.EdgeConfigID) &&
		emptyString(entry.EdgeConfigTokenID) && (entry.System == nil || !*entry.System)
}

func emptyString(value *string) bool { return value == nil || *value == "" }

// keyStates groups scope-relevant entries by valid key name. Keys colliding
// case-insensitively are all treated as overlapping because Vercel's key
// matching for upserts is not documented as case-sensitive.
func (scope Scope) keyStates(entries []envEntry) map[string]keyState {
	states := map[string]keyState{}
	folded := map[string]map[string]struct{}{}
	for _, entry := range entries {
		if !envKeyPattern.MatchString(entry.Key) {
			continue
		}
		related := scope.relate(entry)
		if related == relationDisjoint {
			continue
		}
		state := states[entry.Key]
		if related == relationExact {
			state.exact = append(state.exact, entry)
		} else {
			state.overlap++
		}
		states[entry.Key] = state
		fold := strings.ToUpper(entry.Key)
		if folded[fold] == nil {
			folded[fold] = map[string]struct{}{}
		}
		folded[fold][entry.Key] = struct{}{}
	}
	for _, names := range folded {
		if len(names) < 2 {
			continue
		}
		for name := range names {
			state := states[name]
			state.overlap++
			states[name] = state
		}
	}
	return states
}

// stateFor returns the state for one exact name. Unlike a keyStates lookup it
// also treats a scope-relevant entry whose key differs only by case as an
// overlap when the requested spelling itself has no entry.
func (scope Scope) stateFor(entries []envEntry, name string) keyState {
	state := scope.keyStates(entries)[name]
	for _, entry := range entries {
		if entry.Key != name && strings.EqualFold(entry.Key, name) && scope.relate(entry) != relationDisjoint {
			state.overlap++
		}
	}
	return state
}

// revision fingerprints only non-secret metadata of scope-relevant entries so
// callers can detect drift between plan and apply.
func (scope Scope) revision(entries []envEntry) string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !envKeyPattern.MatchString(entry.Key) || scope.relate(entry) == relationDisjoint {
			continue
		}
		targets := append([]string(nil), entry.Target...)
		sort.Strings(targets)
		customs := append([]string(nil), entry.CustomEnvironmentIDs...)
		sort.Strings(customs)
		branch := ""
		if entry.GitBranch != nil {
			branch = *entry.GitBranch
		}
		line, _ := json.Marshal([]any{entry.ID, entry.Key, entry.Type, targets, branch, customs,
			entry.UpdatedAt.String(), writableEntry(entry)})
		lines = append(lines, string(line))
	}
	sort.Strings(lines)
	sum := sha256.New()
	sum.Write([]byte(scope.Fingerprint()))
	for _, line := range lines {
		sum.Write([]byte{'\n'})
		sum.Write([]byte(line))
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// upsertBody builds the single-entry JSON body into one exactly sized
// allocation so the caller can wipe every copy of the value it owns.
func (scope Scope) upsertBody(name string, value []byte) []byte {
	keyJSON, _ := json.Marshal(name)
	var scopeJSON []byte
	switch scope.Environment {
	case EnvironmentProduction:
		scopeJSON = []byte(`,"target":["production"]`)
	case EnvironmentPreview:
		scopeJSON = []byte(`,"target":["preview"]`)
		if scope.GitBranch != "" {
			branchJSON, _ := json.Marshal(scope.GitBranch)
			scopeJSON = append(append(scopeJSON, `,"gitBranch":`...), branchJSON...)
		}
	case EnvironmentCustom:
		customJSON, _ := json.Marshal([]string{scope.CustomEnvironmentID})
		scopeJSON = append([]byte(`,"customEnvironmentIds":`), customJSON...)
	}
	commentJSON, _ := json.Marshal(writeComment)
	prefix := `{"key":` + string(keyJSON) + `,"type":"sensitive"` + string(scopeJSON) +
		`,"comment":` + string(commentJSON) + `,"value":"`
	body := make([]byte, 0, len(prefix)+6*len(value)+2)
	body = append(body, prefix...)
	body = appendJSONStringContent(body, value)
	return append(body, '"', '}')
}

const hexDigits = "0123456789abcdef"

// appendJSONStringContent escapes valid UTF-8 into dst without reallocating
// when dst has capacity for the worst case (6 bytes per input byte).
func appendJSONStringContent(dst, value []byte) []byte {
	for _, character := range value {
		switch {
		case character == '"' || character == '\\':
			dst = append(dst, '\\', character)
		case character < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[character>>4], hexDigits[character&0xf])
		default:
			dst = append(dst, character)
		}
	}
	return dst
}

type createdEnv struct {
	ID                   string     `json:"id"`
	Key                  string     `json:"key"`
	Type                 string     `json:"type"`
	Target               targetList `json:"target"`
	GitBranch            *string    `json:"gitBranch"`
	CustomEnvironmentIDs []string   `json:"customEnvironmentIds"`
	ConfigurationID      *string    `json:"configurationId"`
	count                int
}

// createdField accepts Vercel's object-or-array "created" without decoding
// any value-bearing field.
type createdField struct {
	entries []createdEnv
	present bool
}

func (field *createdField) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	field.present = !bytes.Equal(trimmed, []byte("null"))
	if !field.present {
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &field.entries)
	}
	var single createdEnv
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	field.entries = []createdEnv{single}
	return nil
}

// decodeUpsert treats any failed[] entry as a definitive failure and anything
// short of exactly one created entry as unconfirmed (ambiguous). Error
// messages, codes, keys and echoed values from failed[] are never decoded.
func decodeUpsert(raw []byte, created *createdEnv) error {
	var response struct {
		Created createdField      `json:"created"`
		Failed  []json.RawMessage `json:"failed"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		for index := range response.Failed {
			wipe(response.Failed[index])
		}
		return safeError("write", "UNCONFIRMED_WRITE", provider.RetryAmbiguous)
	}
	failed := len(response.Failed)
	for index := range response.Failed {
		wipe(response.Failed[index])
	}
	if failed != 0 {
		if response.Created.present && len(response.Created.entries) != 0 {
			// Mixed outcome for a single-entry request cannot be interpreted.
			return safeError("write", "MIXED_WRITE_RESULT", provider.RetryAmbiguous)
		}
		return safeError("write", "WRITE_REJECTED", provider.RetryNever)
	}
	if len(response.Created.entries) != 1 {
		return safeError("write", "UNCONFIRMED_WRITE", provider.RetryAmbiguous)
	}
	*created = response.Created.entries[0]
	created.count = 1
	return nil
}

func (scope Scope) createdMatches(created createdEnv, name string) bool {
	if created.count != 1 || created.Key != name || created.Type != "sensitive" ||
		!envVarIDPattern.MatchString(created.ID) || !emptyString(created.ConfigurationID) {
		return false
	}
	entry := envEntry{ID: created.ID, Key: created.Key, Type: created.Type, Target: created.Target,
		GitBranch: created.GitBranch, CustomEnvironmentIDs: created.CustomEnvironmentIDs}
	return scope.relate(entry) == relationExact
}

func (adapter *Adapter) timestamp() string {
	return adapter.now().UTC().Truncate(time.Second).Format(time.RFC3339)
}
