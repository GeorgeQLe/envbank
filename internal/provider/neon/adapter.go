// Package neon implements the API-supported Neon credential lifecycle:
// Postgres role passwords (stored raw or as a connection URI) and Neon API
// keys. Neon has no idempotency header, so every mutation classifies a lost
// response as ambiguous rather than retrying it.
package neon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

const DefaultEndpoint = "https://console.neon.tech"
const maxResponseBytes = 1 << 20

// Credential types. A role password has no grace period at Neon: the old
// password stops working as soon as the reset operation finishes. Rotation
// without downtime therefore alternates between two equally privileged roles;
// Revoke on a role resets that role's password and discards the result.
const (
	TypeRolePassword = "role-password"
	TypeAPIKey       = "api-key"
)

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	roleNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,62}$`)
	hostPattern     = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)
	keyIDPattern    = regexp.MustCompile(`^[0-9]{1,19}$`)
)

type Adapter struct {
	endpoint     string
	client       *http.Client
	control      []byte
	pollInterval time.Duration
	pollTimeout  time.Duration
}

type Options struct {
	Endpoint     string
	Client       *http.Client
	PollInterval time.Duration
	PollTimeout  time.Duration
}

func New(controlCredential []byte, options Options) (*Adapter, error) {
	if len(controlCredential) == 0 || len(controlCredential) > 16<<10 || bytes.IndexFunc(controlCredential, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return nil, errors.New("Neon control credential is invalid")
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")) {
		return nil, errors.New("Neon API endpoint is invalid")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}
	copy := *client
	if copy.Timeout == 0 {
		copy.Timeout = 15 * time.Second
	}
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	adapter := &Adapter{endpoint: endpoint, client: &copy, control: append([]byte(nil), controlCredential...), pollInterval: options.PollInterval, pollTimeout: options.PollTimeout}
	if adapter.pollInterval <= 0 {
		adapter.pollInterval = time.Second
	}
	if adapter.pollTimeout <= 0 {
		adapter.pollTimeout = 90 * time.Second
	}
	return adapter, nil
}

func (adapter *Adapter) Close() {
	if adapter != nil {
		wipe(adapter.control)
		adapter.control = nil
	}
}

func (*Adapter) Capabilities() map[string]lifecycle.CredentialCapability {
	return map[string]lifecycle.CredentialCapability{TypeRolePassword: lifecycle.CapabilityAutomatic, TypeAPIKey: lifecycle.CapabilityAutomatic}
}

// Identify binds the control credential to the Neon account that owns it.
// /auth reports the account for personal, organization and project-scoped
// keys alike; /users/me is undefined for organization keys.
func (adapter *Adapter) Identify(ctx context.Context) (provider.Identity, error) {
	body, status, err := adapter.request(ctx, http.MethodGet, "/api/v2/auth", nil, "")
	if err != nil {
		return provider.Identity{}, err
	}
	defer wipe(body)
	if status != 200 {
		return provider.Identity{}, provider.NewError("identify", status, "NEON_RESPONSE", retryRead(status))
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return provider.Identity{}, provider.NewError("identify", 200, "INVALID_RESPONSE", provider.RetryNever)
	}
	account, ok := plainJSONString(fields["account_id"])
	if !ok || !idPattern.Match(account) {
		wipe(account)
		return provider.Identity{}, provider.NewError("identify", 200, "INVALID_IDENTITY", provider.RetryNever)
	}
	defer wipe(account)
	return provider.Identity{Provider: "neon", ID: string(account)}, nil
}

// Create mints a credential and streams its value into the sink. The
// idempotency key is mandatory even though Neon ignores it: it is sent as
// X-Request-ID for correlation, and it forces callers through the lifecycle
// engine's ambiguous-failure reconciliation instead of blind retries.
func (adapter *Adapter) Create(ctx context.Context, request lifecycle.CredentialRequest, sink *lifecycle.SecretSink) (lifecycle.CredentialEvidence, error) {
	if request.ProviderIdentity == "" || request.DestinationRecord == "" || sink == nil || !validIdempotencyKey(request.IdempotencyKey) {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_REQUEST", provider.RetryNever)
	}
	switch request.CredentialType {
	case TypeRolePassword:
		return adapter.createRolePassword(ctx, request, sink)
	case TypeAPIKey:
		return adapter.createAPIKey(ctx, request, sink)
	}
	return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_REQUEST", provider.RetryNever)
}

// roleScope is the immutable location of a role. It is the credential ID for
// role passwords: Neon has no identifier for an individual password.
type roleScope struct{ project, branch, role string }

func (scope roleScope) id() string {
	return "role:" + scope.project + "/" + scope.branch + "/" + scope.role
}
func (scope roleScope) path() string {
	return "/api/v2/projects/" + url.PathEscape(scope.project) + "/branches/" + url.PathEscape(scope.branch) + "/roles/" + url.PathEscape(scope.role)
}

func parseRoleScope(id string) (roleScope, bool) {
	rest, ok := strings.CutPrefix(id, "role:")
	if !ok {
		return roleScope{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || !idPattern.MatchString(parts[0]) || !idPattern.MatchString(parts[1]) || !roleNamePattern.MatchString(parts[2]) {
		return roleScope{}, false
	}
	return roleScope{project: parts[0], branch: parts[1], role: parts[2]}, true
}

func roleScopeFromParameters(parameters map[string][]string) (roleScope, bool) {
	project, branch, role := single(parameters, "project_id"), single(parameters, "branch_id"), single(parameters, "role_name")
	if !idPattern.MatchString(project) || !idPattern.MatchString(branch) || !roleNamePattern.MatchString(role) {
		return roleScope{}, false
	}
	return roleScope{project: project, branch: branch, role: role}, true
}

func (adapter *Adapter) createRolePassword(ctx context.Context, request lifecycle.CredentialRequest, sink *lifecycle.SecretSink) (lifecycle.CredentialEvidence, error) {
	scope, ok := roleScopeFromParameters(request.Parameters)
	if !ok {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_CONFIGURATION", provider.RetryNever)
	}
	database := single(request.Parameters, "database_name")
	pooled := single(request.Parameters, "pooled")
	if (len(request.Parameters["database_name"]) > 0 && !idPattern.MatchString(database)) || (pooled != "" && pooled != "true" && pooled != "false") || (pooled != "" && database == "") {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_CONFIGURATION", provider.RetryNever)
	}
	password, resetErr := adapter.resetPassword(ctx, "create", scope, request.IdempotencyKey)
	if resetErr != nil {
		return lifecycle.CredentialEvidence{}, *resetErr
	}
	defer wipe(password)
	value := password
	if database != "" {
		host, hostErr := adapter.readWriteHost(ctx, scope)
		if hostErr != nil {
			// The reset committed; the engine must reconcile, not retry.
			return lifecycle.CredentialEvidence{}, provider.NewError("create", hostErr.Status, hostErr.Code, provider.RetryAmbiguous)
		}
		if pooled == "true" {
			label, rest, _ := strings.Cut(host, ".")
			host = label + "-pooler." + rest
		}
		uri := url.URL{Scheme: "postgresql", User: url.UserPassword(scope.role, string(password)), Host: host, Path: "/" + database, RawQuery: "sslmode=require&channel_binding=require"}
		value = []byte(uri.String())
		defer wipe(value)
	}
	receipt, err := sink.StoreBytes(ctx, value)
	if err != nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 200, "STORE_REQUIRED", provider.RetryAmbiguous)
	}
	return lifecycle.CredentialEvidence{CredentialID: scope.id(), CreatedAt: time.Now().UTC().Format(time.RFC3339), Receipt: receipt}, nil
}

// resetPassword returns the new password once Neon reports every resulting
// operation finished; before that the new password is not yet accepted.
func (adapter *Adapter) resetPassword(ctx context.Context, operation string, scope roleScope, requestID string) ([]byte, *provider.Error) {
	body, status, err := adapter.request(ctx, http.MethodPost, scope.path()+"/reset_password", nil, requestID)
	if err != nil {
		return nil, asError(err)
	}
	defer wipe(body)
	if status != 200 {
		return nil, ptr(provider.NewError(operation, status, "NEON_RESPONSE", retryMutation(status)))
	}
	var response struct {
		Role       map[string]json.RawMessage `json:"role"`
		Operations []struct {
			ID string `json:"id"`
		} `json:"operations"`
	}
	if json.Unmarshal(body, &response) != nil {
		return nil, ptr(provider.NewError(operation, 200, "INVALID_RESPONSE", provider.RetryAmbiguous))
	}
	password, ok := plainJSONString(response.Role["password"])
	if !ok || len(password) < 8 {
		wipe(password)
		return nil, ptr(provider.NewError(operation, 200, "INVALID_RESPONSE", provider.RetryAmbiguous))
	}
	for _, item := range response.Operations {
		if !idPattern.MatchString(item.ID) {
			wipe(password)
			return nil, ptr(provider.NewError(operation, 200, "INVALID_RESPONSE", provider.RetryAmbiguous))
		}
		if err := adapter.awaitOperation(ctx, operation, scope.project, item.ID); err != nil {
			wipe(password)
			return nil, err
		}
	}
	return password, nil
}

func (adapter *Adapter) awaitOperation(ctx context.Context, operation, project, id string) *provider.Error {
	deadline := time.Now().Add(adapter.pollTimeout)
	path := "/api/v2/projects/" + url.PathEscape(project) + "/operations/" + url.PathEscape(id)
	for {
		body, status, err := adapter.request(ctx, http.MethodGet, path, nil, "")
		if err != nil {
			return ptr(provider.NewError(operation, 0, "OPERATION_UNKNOWN", provider.RetryAmbiguous))
		}
		if status != 200 {
			wipe(body)
			return ptr(provider.NewError(operation, status, "OPERATION_UNKNOWN", provider.RetryAmbiguous))
		}
		var response struct {
			Operation struct {
				Status string `json:"status"`
			} `json:"operation"`
		}
		parseErr := json.Unmarshal(body, &response)
		wipe(body)
		if parseErr != nil {
			return ptr(provider.NewError(operation, 200, "OPERATION_UNKNOWN", provider.RetryAmbiguous))
		}
		switch response.Operation.Status {
		case "finished", "skipped":
			return nil
		case "failed", "error", "cancelled":
			return ptr(provider.NewError(operation, 200, "OPERATION_FAILED", provider.RetryAmbiguous))
		case "scheduling", "running", "cancelling":
		default:
			return ptr(provider.NewError(operation, 200, "OPERATION_UNKNOWN", provider.RetryAmbiguous))
		}
		if time.Now().After(deadline) {
			return ptr(provider.NewError(operation, 200, "OPERATION_TIMEOUT", provider.RetryAmbiguous))
		}
		select {
		case <-ctx.Done():
			return ptr(provider.NewError(operation, 0, "OPERATION_TIMEOUT", provider.RetryAmbiguous))
		case <-time.After(adapter.pollInterval):
		}
	}
}

// readWriteHost resolves the branch's read-write compute host. Composing the
// URI locally keeps EnvBank independent of Neon's optional server-side
// password storage (connection_uri and reveal_password fail with 412 when the
// project disables it).
func (adapter *Adapter) readWriteHost(ctx context.Context, scope roleScope) (string, *provider.Error) {
	body, status, err := adapter.request(ctx, http.MethodGet, "/api/v2/projects/"+url.PathEscape(scope.project)+"/branches/"+url.PathEscape(scope.branch)+"/endpoints", nil, "")
	if err != nil {
		return "", asError(err)
	}
	defer wipe(body)
	if status != 200 {
		return "", ptr(provider.NewError("create", status, "ENDPOINT_LOOKUP", retryRead(status)))
	}
	var response struct {
		Endpoints []struct {
			Host string `json:"host"`
			Type string `json:"type"`
		} `json:"endpoints"`
	}
	if json.Unmarshal(body, &response) != nil {
		return "", ptr(provider.NewError("create", 200, "ENDPOINT_LOOKUP", provider.RetryNever))
	}
	host := ""
	for _, endpoint := range response.Endpoints {
		if endpoint.Type != "read_write" {
			continue
		}
		if host != "" || !hostPattern.MatchString(endpoint.Host) {
			return "", ptr(provider.NewError("create", 200, "ENDPOINT_AMBIGUOUS", provider.RetryNever))
		}
		host = endpoint.Host
	}
	if host == "" {
		return "", ptr(provider.NewError("create", 200, "ENDPOINT_MISSING", provider.RetryNever))
	}
	return host, nil
}

// keyScope locates an API key. Organization and project-scoped keys live under
// the organization; personal keys under the account.
type keyScope struct{ org, key string }

func (scope keyScope) id() string {
	if scope.org != "" {
		return "api-key:org:" + scope.org + ":" + scope.key
	}
	return "api-key:" + scope.key
}
func (scope keyScope) collection() string {
	if scope.org != "" {
		return "/api/v2/organizations/" + url.PathEscape(scope.org) + "/api_keys"
	}
	return "/api/v2/api_keys"
}

func parseKeyScope(id string) (keyScope, bool) {
	rest, ok := strings.CutPrefix(id, "api-key:")
	if !ok {
		return keyScope{}, false
	}
	if org, found := strings.CutPrefix(rest, "org:"); found {
		orgID, keyID, ok := strings.Cut(org, ":")
		if !ok || !idPattern.MatchString(orgID) || !keyIDPattern.MatchString(keyID) {
			return keyScope{}, false
		}
		return keyScope{org: orgID, key: keyID}, true
	}
	if !keyIDPattern.MatchString(rest) {
		return keyScope{}, false
	}
	return keyScope{key: rest}, true
}

func (adapter *Adapter) createAPIKey(ctx context.Context, request lifecycle.CredentialRequest, sink *lifecycle.SecretSink) (lifecycle.CredentialEvidence, error) {
	name := single(request.Parameters, "key_name")
	org := single(request.Parameters, "org_id")
	project := single(request.Parameters, "project_id")
	if name == "" || len(name) > 64 || strings.IndexFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 || (org != "" && !idPattern.MatchString(org)) || (project != "" && (!idPattern.MatchString(project) || org == "")) {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_CONFIGURATION", provider.RetryNever)
	}
	payload := map[string]string{"key_name": name}
	if project != "" {
		payload["project_id"] = project
	}
	encoded, _ := json.Marshal(payload)
	scope := keyScope{org: org}
	body, status, err := adapter.request(ctx, http.MethodPost, scope.collection(), bytes.NewReader(encoded), request.IdempotencyKey)
	if err != nil {
		return lifecycle.CredentialEvidence{}, err
	}
	defer wipe(body)
	if status != 200 && status != 201 {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", status, "NEON_RESPONSE", retryMutation(status))
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", status, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	id := strings.TrimSpace(string(fields["id"]))
	if !keyIDPattern.MatchString(id) {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", status, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	scope.key = id
	key, ok := plainJSONString(fields["key"])
	if !ok || len(key) < 8 {
		wipe(key)
		return lifecycle.CredentialEvidence{}, provider.NewError("create", status, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	defer wipe(key)
	receipt, err := sink.StoreBytes(ctx, key)
	if err != nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", status, "STORE_REQUIRED", provider.RetryAmbiguous)
	}
	return lifecycle.CredentialEvidence{CredentialID: scope.id(), CreatedAt: time.Now().UTC().Format(time.RFC3339), Receipt: receipt}, nil
}

// Validate confirms the credential's container still exists. Neon never
// returns a password or key value from a lookup, and presence of a role does
// not prove which password it currently accepts, so the result is limited.
func (adapter *Adapter) Validate(ctx context.Context, id string) (provider.VerifyEvidence, error) {
	if scope, ok := parseRoleScope(id); ok {
		body, status, err := adapter.request(ctx, http.MethodGet, scope.path(), nil, "")
		if err != nil {
			return provider.VerifyEvidence{}, err
		}
		wipe(body)
		switch status {
		case 200:
			return provider.VerifyEvidence{Result: provider.VerificationLimited, Presence: provider.PresencePresent, VerifiedAt: now(), Reason: "ROLE_PRESENT"}, nil
		case 404:
			return provider.VerifyEvidence{Result: provider.VerificationLimited, Presence: provider.PresenceAbsent, VerifiedAt: now(), Reason: "ROLE_ABSENT"}, nil
		}
		return provider.VerifyEvidence{}, provider.NewError("validate", status, "NEON_RESPONSE", retryRead(status))
	}
	scope, ok := parseKeyScope(id)
	if !ok {
		return provider.VerifyEvidence{}, provider.NewError("validate", 0, "INVALID_ID", provider.RetryNever)
	}
	present, err := adapter.keyListed(ctx, scope)
	if err != nil {
		return provider.VerifyEvidence{}, err
	}
	if present {
		return provider.VerifyEvidence{Result: provider.VerificationVerified, Presence: provider.PresencePresent, VerifiedAt: now()}, nil
	}
	return provider.VerifyEvidence{Result: provider.VerificationVerified, Presence: provider.PresenceAbsent, VerifiedAt: now()}, nil
}

func (adapter *Adapter) keyListed(ctx context.Context, scope keyScope) (bool, error) {
	body, status, err := adapter.request(ctx, http.MethodGet, scope.collection(), nil, "")
	if err != nil {
		return false, err
	}
	defer wipe(body)
	if status != 200 {
		return false, provider.NewError("validate", status, "NEON_RESPONSE", retryRead(status))
	}
	var keys []struct {
		ID json.Number `json:"id"`
	}
	if json.Unmarshal(body, &keys) != nil {
		return false, provider.NewError("validate", 200, "INVALID_RESPONSE", provider.RetryNever)
	}
	for _, key := range keys {
		if key.ID.String() == scope.key {
			return true, nil
		}
	}
	return false, nil
}

// Revoke invalidates a credential. For a role password the only invalidation
// Neon offers is another reset, whose new password is discarded unread.
func (adapter *Adapter) Revoke(ctx context.Context, id string) error {
	if scope, ok := parseRoleScope(id); ok {
		password, err := adapter.resetPassword(ctx, "revoke", scope, "")
		if err != nil {
			return *err
		}
		wipe(password)
		return nil
	}
	scope, ok := parseKeyScope(id)
	if !ok {
		return provider.NewError("revoke", 0, "INVALID_ID", provider.RetryNever)
	}
	body, status, err := adapter.request(ctx, http.MethodDelete, scope.collection()+"/"+scope.key, nil, "")
	if err != nil {
		return err
	}
	wipe(body)
	if status != 200 && status != 404 {
		return provider.NewError("revoke", status, "NEON_RESPONSE", retryMutation(status))
	}
	return nil
}

func (adapter *Adapter) request(ctx context.Context, method, path string, body io.Reader, requestID string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, adapter.endpoint+path, body)
	if err != nil {
		return nil, 0, provider.NewError(strings.ToLower(method), 0, "REQUEST_FAILED", provider.RetryNever)
	}
	req.Header.Set("Authorization", "Bearer "+string(adapter.control))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	response, err := adapter.client.Do(req)
	if err != nil {
		retry := provider.RetrySafe
		if method != http.MethodGet {
			retry = provider.RetryAmbiguous
		}
		return nil, 0, provider.NewError(strings.ToLower(method), 0, "TRANSPORT_FAILED", retry)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		wipe(raw)
		return nil, 0, provider.NewError(strings.ToLower(method), response.StatusCode, "RESPONSE_LIMIT", provider.RetryAmbiguous)
	}
	return raw, response.StatusCode, nil
}

func validIdempotencyKey(key string) bool {
	return len(key) > 0 && len(key) <= 255 && strings.IndexFunc(key, func(r rune) bool { return r <= ' ' || r == 0x7f }) < 0
}

func single(parameters map[string][]string, name string) string {
	if len(parameters[name]) != 1 {
		return ""
	}
	return parameters[name][0]
}

func plainJSONString(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || bytes.IndexByte(raw[1:len(raw)-1], '\\') >= 0 {
		return nil, false
	}
	return append([]byte(nil), raw[1:len(raw)-1]...), true
}

// retryRead classifies failures of GET requests, which are always safe.
func retryRead(status int) provider.RetryClass {
	if status == 423 || status == 429 || status >= 500 {
		return provider.RetrySafe
	}
	return provider.RetryNever
}

// retryMutation classifies failures of non-idempotent requests. Neon documents
// 423 and 503 as always safe to retry; any other server failure may have
// committed.
func retryMutation(status int) provider.RetryClass {
	switch {
	case status == 423 || status == 429 || status == 503:
		return provider.RetrySafe
	case status >= 500:
		return provider.RetryAmbiguous
	}
	return provider.RetryNever
}

func asError(err error) *provider.Error {
	var typed provider.Error
	if errors.As(err, &typed) {
		return &typed
	}
	return ptr(provider.NewError("request", 0, "TRANSPORT_FAILED", provider.RetryAmbiguous))
}

func ptr(err provider.Error) *provider.Error { return &err }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

var _ lifecycle.CredentialAdapter = (*Adapter)(nil)
