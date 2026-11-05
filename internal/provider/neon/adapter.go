// Package neon implements EnvBank's Neon (API v2) adapter: project create
// and delete, role creation and role password reset. Connection URIs, which
// embed role passwords, flow only from bounded, wiped response buffers into
// lifecycle.SecretSink records. They never appear in return values, errors,
// String output or logs.
//
// Limitations callers must account for:
//
//   - Neon has no idempotency key for project or role creation. A create is
//     never retried; an ambiguous failure must be reconciled by listing.
//   - ResetRolePassword invalidates the role's old password as soon as Neon
//     accepts it, before the new URIs are stored. Callers must only reset a
//     role whose old password is no longer in use.
package neon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	ProviderName    = "neon"
	DefaultEndpoint = "https://console.neon.tech/api/v2"
	productionHost  = "console.neon.tech"
	apiPath         = "/api/v2"

	maxKeyBytes      = 4096
	maxResponseBytes = 1 << 20
	initialReadBytes = 16 << 10
	maxURIBytes      = 4096
	maxOperations    = 32
	requestTimeout   = 30 * time.Second

	defaultPollInterval     = time.Second
	defaultOperationTimeout = 2 * time.Minute
	maxReadAttempts         = 3
	maxLockedAttempts       = 10
)

var (
	projectIDPattern   = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+){0,7}$`)
	branchIDPattern    = regexp.MustCompile(`^br-[a-z0-9]+(?:-[a-z0-9]+){0,7}$`)
	orgIDPattern       = regexp.MustCompile(`^org-[a-z0-9]+(?:-[a-z0-9]+){0,7}$`)
	userIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	operationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	identifierPattern  = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	regionIDPattern    = regexp.MustCompile(`^(?:aws|azure|gcp)-[a-z0-9]+(?:-[a-z0-9]+){0,5}$`)
	projectNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
)

// ValidProjectID accepts Neon project IDs such as "polished-pond-123456".
func ValidProjectID(id string) bool { return len(id) <= 64 && projectIDPattern.MatchString(id) }

// ValidBranchID accepts Neon branch IDs such as "br-wispy-dew-123456".
func ValidBranchID(id string) bool { return len(id) <= 64 && branchIDPattern.MatchString(id) }

// ValidRoleName accepts lowercase Postgres identifiers that are not reserved
// by Postgres or Neon.
func ValidRoleName(name string) bool {
	if !identifierPattern.MatchString(name) {
		return false
	}
	switch {
	case strings.HasPrefix(name, "pg_"), strings.HasPrefix(name, "neon_"),
		name == "postgres", name == "cloud_admin", name == "public", name == "none":
		return false
	}
	return true
}

// ValidDatabaseName accepts lowercase Postgres identifiers, excluding the
// template and system databases.
func ValidDatabaseName(name string) bool {
	return identifierPattern.MatchString(name) && !strings.HasPrefix(name, "pg_") &&
		name != "postgres" && name != "template0" && name != "template1"
}

type Options struct {
	// Endpoint must be https://console.neon.tech/api/v2 (the default) or, for
	// tests, an http/https URL whose host is a literal loopback IP. The path
	// may be empty, "/" or "/api/v2"; requests always go to <origin>/api/v2.
	Endpoint string
	Client   *http.Client
	// OrgID, when set, binds Identify to that organization and creates
	// projects in it. Leave empty for organization API keys whose org is
	// implied, or for personal keys.
	OrgID string
}

// Adapter is safe for concurrent use. Close wipes the retained key copy.
type Adapter struct {
	mu     sync.RWMutex
	key    []byte
	base   string
	client *http.Client
	orgID  string

	pollInterval     time.Duration
	operationTimeout time.Duration
}

func New(controlKey []byte, options Options) (*Adapter, error) {
	if len(controlKey) == 0 || len(controlKey) > maxKeyBytes || bytes.IndexFunc(controlKey, func(r rune) bool {
		return r <= ' ' || r >= 0x7f
	}) >= 0 {
		return nil, errors.New("Neon API key is invalid")
	}
	if options.OrgID != "" && (len(options.OrgID) > 64 || !orgIDPattern.MatchString(options.OrgID)) {
		return nil, errors.New("Neon organization ID is invalid")
	}
	base, err := endpointBase(options.Endpoint)
	if err != nil {
		return nil, err
	}
	var clientCopy http.Client
	if options.Client != nil {
		clientCopy = *options.Client
	}
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > requestTimeout {
		clientCopy.Timeout = requestTimeout
	}
	// Never forward the bearer key to a redirect target and never attach
	// ambient cookies.
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clientCopy.Jar = nil
	return &Adapter{key: append([]byte(nil), controlKey...), base: base, client: &clientCopy,
		orgID: options.OrgID, pollInterval: defaultPollInterval, operationTimeout: defaultOperationTimeout}, nil
}

func endpointBase(endpoint string) (string, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	invalid := errors.New("Neon API endpoint is invalid")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/" && parsed.Path != apiPath && parsed.Path != apiPath+"/") {
		return "", invalid
	}
	host := parsed.Hostname()
	switch {
	case parsed.Scheme == "https" && host == productionHost && parsed.Port() == "":
		return "https://" + productionHost + apiPath, nil
	case (parsed.Scheme == "http" || parsed.Scheme == "https") && literalLoopback(host):
		return parsed.Scheme + "://" + parsed.Host + apiPath, nil
	default:
		return "", invalid
	}
}

func literalLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close wipes the adapter's key copy. Strings already handed to net/http for
// in-flight request headers cannot be wiped by Go code.
func (adapter *Adapter) Close() {
	if adapter == nil {
		return
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	wipe(adapter.key)
	adapter.key = nil
}

func (*Adapter) String() string { return "Neon adapter [credential REDACTED]" }
func (*Adapter) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "Neon adapter [credential REDACTED]")
}

// ProjectSpec is the non-secret configuration of a new project. RegionID
// (for example "aws-us-east-2") and PGVersion (14-18) are optional.
type ProjectSpec struct {
	Name      string `json:"name"`
	RegionID  string `json:"region_id,omitempty"`
	PGVersion int    `json:"pg_version,omitempty"`
}

func (spec ProjectSpec) valid() bool {
	return projectNamePattern.MatchString(spec.Name) && strings.TrimSpace(spec.Name) == spec.Name &&
		(spec.RegionID == "" || (len(spec.RegionID) <= 64 && regionIDPattern.MatchString(spec.RegionID))) &&
		(spec.PGVersion == 0 || (spec.PGVersion >= 14 && spec.PGVersion <= 18))
}

// ProjectInfo is value-free metadata about a created project: its default
// branch, owner role and database.
type ProjectInfo struct {
	ProjectID string `json:"project_id"`
	BranchID  string `json:"branch_id"`
	Role      string `json:"role"`
	Database  string `json:"database"`
}

// Identify returns the organization (when Options.OrgID is set) or the user
// that owns the API key. The ID is never a credential or display name.
func (adapter *Adapter) Identify(ctx context.Context) (provider.Identity, error) {
	const operation = "identify"
	var identity struct {
		ID string `json:"id"`
	}
	path := "/users/me"
	if adapter != nil && adapter.orgID != "" {
		path = "/organizations/" + url.PathEscape(adapter.orgID)
	}
	if err := adapter.get(ctx, operation, path, nil, func(raw []byte) error { return json.Unmarshal(raw, &identity) }); err != nil {
		return provider.Identity{}, err
	}
	if adapter.orgID != "" {
		if identity.ID != adapter.orgID {
			return provider.Identity{}, safeError(operation, "INVALID_IDENTITY", provider.RetryNever)
		}
		return provider.Identity{Provider: ProviderName, ID: "org:" + identity.ID}, nil
	}
	if !userIDPattern.MatchString(identity.ID) {
		return provider.Identity{}, safeError(operation, "INVALID_IDENTITY", provider.RetryNever)
	}
	return provider.Identity{Provider: ProviderName, ID: "user:" + identity.ID}, nil
}

type operationWire struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Status    string `json:"status"`
}

type connectionURIWire struct {
	URI        json.RawMessage `json:"connection_uri"`
	Parameters struct {
		Database string `json:"database"`
		Role     string `json:"role"`
	} `json:"connection_parameters"`
}

type createProjectResponse struct {
	Project struct {
		ID string `json:"id"`
	} `json:"project"`
	Branch struct {
		ID string `json:"id"`
	} `json:"branch"`
	ConnectionURIs []connectionURIWire `json:"connection_uris"`
	Operations     []operationWire     `json:"operations"`
}

// CreateProject creates a project and stores its owner role's pooled and
// direct connection URIs in the two sinks. When the create response carries
// no pooled URI, it is derived with GET /projects/{id}/connection_uri.
//
// On error, a non-empty ProjectInfo.ProjectID means the project exists (for
// example the response was unusable or storage failed) and the caller should
// delete it; an empty one with RetryAmbiguous means creation is unknown.
func (adapter *Adapter) CreateProject(ctx context.Context, spec ProjectSpec, pooled, direct *lifecycle.SecretSink) (ProjectInfo, error) {
	const operation = "project_create"
	if !spec.valid() || !distinctSinks(pooled, direct) {
		return ProjectInfo{}, safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	project := map[string]any{"name": spec.Name}
	if spec.RegionID != "" {
		project["region_id"] = spec.RegionID
	}
	if spec.PGVersion != 0 {
		project["pg_version"] = spec.PGVersion
	}
	if adapter != nil && adapter.orgID != "" {
		project["org_id"] = adapter.orgID
	}
	body, err := json.Marshal(map[string]any{"project": project})
	if err != nil {
		return ProjectInfo{}, safeError(operation, "REQUEST_INVALID", provider.RetryNever)
	}
	var response createProjectResponse
	defer func() {
		for index := range response.ConnectionURIs {
			wipeRaw(response.ConnectionURIs[index].URI)
		}
	}()
	err = adapter.send(ctx, apiCall{operation: operation, method: http.MethodPost, path: "/projects",
		body: body, mutation: true}, func(raw []byte) error { return json.Unmarshal(raw, &response) })
	if err != nil {
		return ProjectInfo{}, err
	}
	if !ValidProjectID(response.Project.ID) {
		return ProjectInfo{}, safeError(operation, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	info := ProjectInfo{ProjectID: response.Project.ID}
	incomplete := safeError(operation, "INVALID_RESPONSE", provider.RetryNever)
	if !ValidBranchID(response.Branch.ID) || len(response.ConnectionURIs) == 0 ||
		len(response.ConnectionURIs) > maxOperations || len(response.Operations) > maxOperations {
		return info, incomplete
	}
	info.BranchID = response.Branch.ID
	info.Role = response.ConnectionURIs[0].Parameters.Role
	info.Database = response.ConnectionURIs[0].Parameters.Database
	if !ValidRoleName(info.Role) || !ValidDatabaseName(info.Database) {
		return ProjectInfo{ProjectID: info.ProjectID}, incomplete
	}
	var directURI, pooledURI []byte
	defer func() { wipe(directURI); wipe(pooledURI) }()
	for _, entry := range response.ConnectionURIs {
		if entry.Parameters.Role != info.Role || entry.Parameters.Database != info.Database {
			continue
		}
		uri, ok := decodeJSONString(entry.URI)
		if !ok || !validPostgresURI(uri) {
			wipe(uri)
			return info, incomplete
		}
		switch {
		case poolerHost(uri) && pooledURI == nil:
			pooledURI = uri
		case !poolerHost(uri) && directURI == nil:
			directURI = uri
		default:
			wipe(uri)
		}
	}
	if directURI == nil {
		return info, incomplete
	}
	if pooledURI == nil {
		pooledURI, err = adapter.connectionURI(ctx, operation, info, true)
		if err != nil {
			return info, err
		}
	}
	if err := storeBoth(ctx, operation, pooled, pooledURI, direct, directURI); err != nil {
		return info, err
	}
	if err := adapter.waitOperations(ctx, operation, info.ProjectID, response.Operations); err != nil {
		return info, err
	}
	return info, nil
}

// ResetRolePassword resets role's password on branchID, waits (bounded) for
// the resulting operations, then fetches the role's direct and pooled
// connection URIs for database and stores them in the sinks. The old password
// is invalid as soon as Neon accepts the reset, even if a later step fails.
func (adapter *Adapter) ResetRolePassword(ctx context.Context, projectID, branchID, role, database string, pooled, direct *lifecycle.SecretSink) error {
	const operation = "role_reset_password"
	if !ValidProjectID(projectID) || !ValidBranchID(branchID) || !ValidRoleName(role) ||
		!ValidDatabaseName(database) || !distinctSinks(pooled, direct) {
		return safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	var response struct {
		Role struct {
			Name string `json:"name"`
		} `json:"role"`
		Operations []operationWire `json:"operations"`
	}
	err := adapter.sendRetryingLocked(ctx, apiCall{operation: operation, method: http.MethodPost,
		path: rolesPath(projectID, branchID) + "/" + url.PathEscape(role) + "/reset_password", mutation: true},
		func(raw []byte) error { return json.Unmarshal(raw, &response) })
	if err != nil {
		return err
	}
	if response.Role.Name != role || len(response.Operations) > maxOperations {
		return safeError(operation, "INVALID_RESPONSE", provider.RetryNever)
	}
	if err := adapter.waitOperations(ctx, operation, projectID, response.Operations); err != nil {
		return err
	}
	info := ProjectInfo{ProjectID: projectID, BranchID: branchID, Role: role, Database: database}
	directURI, err := adapter.connectionURI(ctx, operation, info, false)
	if err != nil {
		return err
	}
	defer wipe(directURI)
	pooledURI, err := adapter.connectionURI(ctx, operation, info, true)
	if err != nil {
		return err
	}
	defer wipe(pooledURI)
	return storeBoth(ctx, operation, pooled, pooledURI, direct, directURI)
}

// EnsureRole creates role on branchID if it does not exist and reports
// whether it did. The new role's password is discarded unread; call
// ResetRolePassword to obtain usable connection URIs.
func (adapter *Adapter) EnsureRole(ctx context.Context, projectID, branchID, role string) (bool, error) {
	const operation = "role_ensure"
	if !ValidProjectID(projectID) || !ValidBranchID(branchID) || !ValidRoleName(role) {
		return false, safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	exists, err := adapter.roleExists(ctx, operation, projectID, branchID, role)
	if err != nil || exists {
		return false, err
	}
	body, err := json.Marshal(map[string]any{"role": map[string]string{"name": role}})
	if err != nil {
		return false, safeError(operation, "REQUEST_INVALID", provider.RetryNever)
	}
	var response struct {
		Role struct {
			Name     string `json:"name"`
			BranchID string `json:"branch_id"`
		} `json:"role"`
		Operations []operationWire `json:"operations"`
	}
	err = adapter.sendRetryingLocked(ctx, apiCall{operation: operation, method: http.MethodPost,
		path: rolesPath(projectID, branchID), body: body, mutation: true},
		func(raw []byte) error { return json.Unmarshal(raw, &response) })
	if hasCode(err, "CONFLICT") {
		// Created concurrently; prove it exists rather than trusting the 409.
		exists, err = adapter.roleExists(ctx, operation, projectID, branchID, role)
		if err == nil && !exists {
			err = safeError(operation, "ROLE_STATE_UNKNOWN", provider.RetryNever)
		}
		return false, err
	}
	if err != nil {
		return false, err
	}
	if response.Role.Name != role || (response.Role.BranchID != "" && response.Role.BranchID != branchID) ||
		len(response.Operations) > maxOperations {
		return false, safeError(operation, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	if err := adapter.waitOperations(ctx, operation, projectID, response.Operations); err != nil {
		return true, err
	}
	return true, nil
}

// DeleteProject deletes projectID. A missing project is reported as
// NOT_FOUND so the caller can decide whether that counts as deleted.
func (adapter *Adapter) DeleteProject(ctx context.Context, projectID string) error {
	const operation = "project_delete"
	if !ValidProjectID(projectID) {
		return safeError(operation, "INVALID_REQUEST", provider.RetryNever)
	}
	var response struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}
	err := adapter.sendRetryingLocked(ctx, apiCall{operation: operation, method: http.MethodDelete,
		path: "/projects/" + url.PathEscape(projectID), mutation: true},
		func(raw []byte) error { return json.Unmarshal(raw, &response) })
	if err != nil {
		return err
	}
	if response.Project.ID != projectID {
		return safeError(operation, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	return nil
}

func rolesPath(projectID, branchID string) string {
	return "/projects/" + url.PathEscape(projectID) + "/branches/" + url.PathEscape(branchID) + "/roles"
}

func (adapter *Adapter) roleExists(ctx context.Context, operation, projectID, branchID, role string) (bool, error) {
	var response struct {
		Role struct {
			Name string `json:"name"`
		} `json:"role"`
	}
	err := adapter.get(ctx, operation, rolesPath(projectID, branchID)+"/"+url.PathEscape(role), nil,
		func(raw []byte) error { return json.Unmarshal(raw, &response) })
	if hasCode(err, "NOT_FOUND") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if response.Role.Name != role {
		return false, safeError(operation, "INVALID_RESPONSE", provider.RetryNever)
	}
	return true, nil
}

// connectionURI fetches one validated URI. The caller must wipe the result.
func (adapter *Adapter) connectionURI(ctx context.Context, operation string, info ProjectInfo, pooled bool) ([]byte, error) {
	query := url.Values{"branch_id": {info.BranchID}, "database_name": {info.Database},
		"role_name": {info.Role}, "pooled": {strconv.FormatBool(pooled)}}
	var response struct {
		URI json.RawMessage `json:"uri"`
	}
	var uri []byte
	err := adapter.get(ctx, operation, "/projects/"+url.PathEscape(info.ProjectID)+"/connection_uri", query,
		func(raw []byte) error {
			wipeRaw(response.URI)
			response.URI = nil
			if err := json.Unmarshal(raw, &response); err != nil {
				return err
			}
			defer wipeRaw(response.URI)
			decoded, ok := decodeJSONString(response.URI)
			if !ok || !validPostgresURI(decoded) || poolerHost(decoded) != pooled {
				wipe(decoded)
				return safeError(operation, "INVALID_CONNECTION_URI", provider.RetryNever)
			}
			wipe(uri)
			uri = decoded
			return nil
		})
	wipeRaw(response.URI)
	if err != nil {
		wipe(uri)
		return nil, err
	}
	return uri, nil
}

func distinctSinks(pooled, direct *lifecycle.SecretSink) bool {
	return pooled != nil && direct != nil && pooled != direct
}

func storeBoth(ctx context.Context, operation string, pooled *lifecycle.SecretSink, pooledURI []byte,
	direct *lifecycle.SecretSink, directURI []byte) error {
	if _, err := pooled.StoreBytes(ctx, pooledURI); err != nil {
		return safeError(operation, "STORE_REQUIRED", provider.RetryNever)
	}
	if _, err := direct.StoreBytes(ctx, directURI); err != nil {
		return safeError(operation, "STORE_REQUIRED", provider.RetryNever)
	}
	return nil
}

// waitOperations polls every unfinished operation until it finishes, bounded
// by the adapter's operation timeout.
func (adapter *Adapter) waitOperations(ctx context.Context, operation, projectID string, operations []operationWire) error {
	if len(operations) > maxOperations {
		return safeError(operation, "INVALID_RESPONSE", provider.RetryNever)
	}
	pending := make([]string, 0, len(operations))
	for _, item := range operations {
		if !operationIDPattern.MatchString(item.ID) || (item.ProjectID != "" && item.ProjectID != projectID) {
			return safeError(operation, "INVALID_OPERATION", provider.RetryNever)
		}
		done, err := operationDone(operation, item.Status)
		if err != nil {
			return err
		}
		if !done {
			pending = append(pending, item.ID)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, adapter.operationTimeout)
	defer cancel()
	for _, id := range pending {
		for {
			var response struct {
				Operation operationWire `json:"operation"`
			}
			err := adapter.get(waitCtx, operation, "/projects/"+url.PathEscape(projectID)+"/operations/"+url.PathEscape(id), nil,
				func(raw []byte) error { return json.Unmarshal(raw, &response) })
			if err != nil {
				if waitCtx.Err() != nil {
					return adapter.waitExpired(ctx, operation)
				}
				return err
			}
			if response.Operation.ID != id || (response.Operation.ProjectID != "" && response.Operation.ProjectID != projectID) {
				return safeError(operation, "INVALID_OPERATION", provider.RetryNever)
			}
			done, err := operationDone(operation, response.Operation.Status)
			if err != nil {
				return err
			}
			if done {
				break
			}
			if err := adapter.pause(waitCtx); err != nil {
				return adapter.waitExpired(ctx, operation)
			}
		}
	}
	return nil
}

func (adapter *Adapter) waitExpired(parent context.Context, operation string) error {
	if parent.Err() != nil {
		return safeError(operation, "CANCELLED", provider.RetrySafe)
	}
	return safeError(operation, "OPERATION_TIMEOUT", provider.RetrySafe)
}

func operationDone(operation, status string) (bool, error) {
	switch status {
	case "finished", "skipped":
		return true, nil
	case "scheduling", "running", "cancelling":
		return false, nil
	case "failed", "error", "cancelled":
		return false, safeError(operation, "OPERATION_FAILED", provider.RetryNever)
	default:
		return false, safeError(operation, "INVALID_OPERATION", provider.RetryNever)
	}
}

func (adapter *Adapter) pause(ctx context.Context) error {
	interval := adapter.pollInterval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// get retries retry-safe read failures a bounded number of times.
func (adapter *Adapter) get(ctx context.Context, operation, path string, query url.Values, decode func([]byte) error) error {
	var err error
	for attempt := 0; attempt < maxReadAttempts; attempt++ {
		if attempt > 0 {
			if adapter.pause(ctx) != nil {
				return err
			}
		}
		err = adapter.send(ctx, apiCall{operation: operation, method: http.MethodGet, path: path, query: query}, decode)
		var safe provider.Error
		if err == nil || !errors.As(err, &safe) || safe.Retry != provider.RetrySafe {
			return err
		}
	}
	return err
}

// sendRetryingLocked retries a mutation only while Neon answers 423 Locked,
// which means the project has a conflicting operation and nothing was applied.
func (adapter *Adapter) sendRetryingLocked(ctx context.Context, call apiCall, decode func([]byte) error) error {
	var err error
	for attempt := 0; attempt < maxLockedAttempts; attempt++ {
		if attempt > 0 {
			if adapter.pause(ctx) != nil {
				return err
			}
		}
		err = adapter.send(ctx, call, decode)
		if !hasCode(err, "LOCKED") {
			return err
		}
	}
	return err
}

type apiCall struct {
	operation string
	method    string
	path      string
	query     url.Values
	body      []byte
	mutation  bool
}

// send performs one request. decode sees the bounded body only for 2xx
// responses, and the buffer is wiped afterwards. Non-2xx bodies are read
// (bounded), wiped and discarded unparsed, so errors carry only status
// derived codes.
func (adapter *Adapter) send(ctx context.Context, call apiCall, decode func([]byte) error) error {
	if adapter == nil || adapter.client == nil {
		return safeError(call.operation, "NOT_CONFIGURED", provider.RetryNever)
	}
	if ctx == nil {
		return safeError(call.operation, "REQUEST_INVALID", provider.RetryNever)
	}
	adapter.mu.RLock()
	if len(adapter.key) == 0 {
		adapter.mu.RUnlock()
		return safeError(call.operation, "CLOSED", provider.RetryNever)
	}
	authorization := "Bearer " + string(adapter.key)
	adapter.mu.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	target := adapter.base + call.path
	if len(call.query) > 0 {
		target += "?" + call.query.Encode()
	}
	var reader io.Reader = http.NoBody
	if call.body != nil {
		reader = bytes.NewReader(call.body)
	}
	request, err := http.NewRequestWithContext(ctx, call.method, target, reader)
	if err != nil {
		return safeError(call.operation, "REQUEST_INVALID", provider.RetryNever)
	}
	// Mutations must never be replayed by the transport.
	request.GetBody = nil
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Accept", "application/json")
	if call.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := adapter.client.Do(request)
	if err != nil {
		return safeError(call.operation, "TRANSPORT", transportRetry(call.mutation))
	}
	defer response.Body.Close()
	raw, readErr := readBounded(response.Body, response.ContentLength)
	defer wipe(raw)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return provider.NewError(call.operation, response.StatusCode, statusCode(response.StatusCode),
			statusRetry(call.mutation, response.StatusCode))
	}
	if readErr != nil {
		return provider.NewError(call.operation, response.StatusCode, readErr.Error(), invalidRetry(call.mutation))
	}
	if decode == nil {
		return nil
	}
	if err := decode(raw); err != nil {
		var safe provider.Error
		if errors.As(err, &safe) {
			return safe
		}
		return provider.NewError(call.operation, response.StatusCode, "INVALID_RESPONSE", invalidRetry(call.mutation))
	}
	return nil
}

var (
	errTooLarge   = errors.New("RESPONSE_TOO_LARGE")
	errReadFailed = errors.New("RESPONSE_READ_FAILED")
)

// readBounded grows its own buffer, wiping every superseded allocation, so
// secret-bearing bodies are not left in unreachable copies.
func readBounded(body io.Reader, declared int64) ([]byte, error) {
	if declared > maxResponseBytes {
		return nil, errTooLarge
	}
	buffer := make([]byte, 0, initialReadBytes)
	for {
		if len(buffer) == cap(buffer) {
			if len(buffer) > maxResponseBytes {
				return buffer, errTooLarge
			}
			grown := make([]byte, len(buffer), min(2*cap(buffer), maxResponseBytes+1))
			copy(grown, buffer)
			wipe(buffer)
			buffer = grown
		}
		read, err := body.Read(buffer[len(buffer):cap(buffer)])
		buffer = buffer[:len(buffer)+read]
		if len(buffer) > maxResponseBytes {
			return buffer, errTooLarge
		}
		if err == io.EOF {
			return buffer, nil
		}
		if err != nil {
			return buffer, errReadFailed
		}
	}
}

// decodeJSONString decodes one JSON string literal into a single exactly
// bounded allocation (never reallocated) that the caller must wipe.
func decodeJSONString(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || len(raw) > 6*maxURIBytes+2 {
		return nil, false
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	fail := func() ([]byte, bool) { wipe(out[:cap(out)]); return nil, false }
	for index := 0; index < len(in); index++ {
		character := in[index]
		switch {
		case character == '"' || character < 0x20:
			return fail()
		case character != '\\':
			out = append(out, character)
			continue
		}
		index++
		if index >= len(in) {
			return fail()
		}
		switch in[index] {
		case '"', '\\', '/':
			out = append(out, in[index])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			code, ok := hex4(in, index+1)
			if !ok {
				return fail()
			}
			index += 4
			r := rune(code)
			if utf16.IsSurrogate(r) {
				if index+6 >= len(in) || in[index+1] != '\\' || in[index+2] != 'u' {
					return fail()
				}
				low, ok := hex4(in, index+3)
				if !ok {
					return fail()
				}
				index += 6
				r = utf16.DecodeRune(r, rune(low))
				if r == utf8.RuneError {
					return fail()
				}
			}
			// A \uXXXX escape (6 input bytes) never encodes to more than 4
			// bytes, and a surrogate pair (12) to exactly 4, so out cannot grow
			// past its capacity.
			out = utf8.AppendRune(out, r)
		default:
			return fail()
		}
	}
	return out, true
}

func hex4(in []byte, start int) (uint16, bool) {
	if start+4 > len(in) {
		return 0, false
	}
	var value uint16
	for _, character := range in[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

// validPostgresURI checks shape only, without allocating strings from the
// secret-bearing URI: a postgres scheme, printable ASCII, credentials and a
// host.
func validPostgresURI(uri []byte) bool {
	if len(uri) == 0 || len(uri) > maxURIBytes {
		return false
	}
	for _, character := range uri {
		if character <= ' ' || character >= 0x7f {
			return false
		}
	}
	if !bytes.HasPrefix(uri, []byte("postgresql://")) && !bytes.HasPrefix(uri, []byte("postgres://")) {
		return false
	}
	authority := uriAuthority(uri)
	at := bytes.LastIndexByte(authority, '@')
	return at > 0 && len(uriHost(uri)) > 0
}

func uriAuthority(uri []byte) []byte {
	start := bytes.Index(uri, []byte("://"))
	if start < 0 {
		return nil
	}
	rest := uri[start+3:]
	if end := bytes.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// uriHost returns the host subslice (without port) of the URI's authority.
func uriHost(uri []byte) []byte {
	authority := uriAuthority(uri)
	host := authority[bytes.LastIndexByte(authority, '@')+1:]
	if colon := bytes.LastIndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return host
}

// poolerHost reports whether the URI targets Neon's PgBouncer endpoint,
// whose hostname has a "-pooler" suffix on its first label.
func poolerHost(uri []byte) bool {
	host := uriHost(uri)
	label := host
	if dot := bytes.IndexByte(host, '.'); dot >= 0 {
		label = host[:dot]
	}
	return bytes.HasSuffix(label, []byte("-pooler"))
}

func statusCode(status int) string {
	switch {
	case status >= 300 && status <= 399:
		return "REDIRECT_REJECTED"
	case status == http.StatusBadRequest:
		return "BAD_REQUEST"
	case status == http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case status == http.StatusPaymentRequired:
		return "PAYMENT_REQUIRED"
	case status == http.StatusForbidden:
		return "FORBIDDEN"
	case status == http.StatusNotFound:
		return "NOT_FOUND"
	case status == http.StatusConflict:
		return "CONFLICT"
	case status == http.StatusUnprocessableEntity:
		return "UNPROCESSABLE"
	case status == http.StatusLocked:
		return "LOCKED"
	case status == http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case status >= 500:
		return "SERVER_ERROR"
	default:
		return "HTTP_ERROR"
	}
}

func transportRetry(mutation bool) provider.RetryClass {
	if mutation {
		return provider.RetryAmbiguous
	}
	return provider.RetrySafe
}

func invalidRetry(mutation bool) provider.RetryClass {
	if mutation {
		// A 2xx mutation response we cannot interpret may have committed.
		return provider.RetryAmbiguous
	}
	return provider.RetryNever
}

func statusRetry(mutation bool, status int) provider.RetryClass {
	switch {
	case status == http.StatusTooManyRequests || status == http.StatusLocked:
		return provider.RetrySafe
	case status == http.StatusRequestTimeout || status >= 500:
		return transportRetry(mutation)
	case status >= 300 && status <= 399 && mutation:
		return provider.RetryAmbiguous
	default:
		return provider.RetryNever
	}
}

func safeError(operation, code string, retry provider.RetryClass) error {
	return provider.NewError(operation, 0, code, retry)
}

func hasCode(err error, code string) bool {
	var safe provider.Error
	return errors.As(err, &safe) && safe.Code == code
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func wipeRaw(value json.RawMessage) { wipe(value) }
