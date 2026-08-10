// Package railway implements EnvBank's narrowly allowlisted Railway adapter.
// It deliberately does not query Railway variables: the documented variables
// query returns values, so it is outside the names-only boundary.
package railway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	ProviderName       = "railway"
	DefaultEndpoint    = "https://backboard.railway.com/graphql/v2"
	maxResponseBytes   = 1 << 20
	maxCredentialBytes = 16 << 10
)

const identityQuery = `query EnvBankRailwayIdentity {
  projectToken { projectId environmentId }
}`

const targetQuery = `query EnvBankRailwayTarget($projectId: String!) {
  project(id: $projectId) {
    id
    name
    environments { edges { node { id name } } }
    services { edges { node { id name } } }
  }
}`

const variableUpsertMutation = `mutation EnvBankRailwayVariableUpsert($input: VariableUpsertInput!) {
  variableUpsert(input: $input)
}`

type Adapter struct {
	endpoint string
	client   *http.Client
	token    []byte
}

type Options struct {
	Endpoint string
	Client   *http.Client
}

type BindingRequest struct {
	Project       string
	ProjectID     string
	Environment   string
	EnvironmentID string
	// Services maps each exact Railway service name to an optional expected ID.
	Services map[string]string
}

func New(token []byte, options Options) (*Adapter, error) {
	if len(token) == 0 || len(token) > maxCredentialBytes || bytes.IndexFunc(token, func(r rune) bool {
		return r <= ' ' || r == 0x7f
	}) >= 0 {
		return nil, errors.New("Railway project credential is invalid")
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname()))) {
		return nil, errors.New("Railway API endpoint is invalid")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}
	clientCopy := *client
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 15 * time.Second
	}
	// Never forward a project token to a redirect target, even when a caller
	// supplied its own client policy.
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Adapter{endpoint: endpoint, client: &clientCopy, token: append([]byte(nil), token...)}, nil
}

func (adapter *Adapter) Close() {
	if adapter == nil {
		return
	}
	for index := range adapter.token {
		adapter.token[index] = 0
	}
	adapter.token = nil
}

func (*Adapter) Capabilities() provider.Capabilities {
	return provider.Capabilities{Create: true, ReadMetadata: true, Update: true, Validate: true,
		SupportsIdempotentWrite: true}
}

func (adapter *Adapter) Identity(ctx context.Context) (provider.Identity, error) {
	identity, err := adapter.identity(ctx)
	if err != nil {
		return provider.Identity{}, err
	}
	return provider.Identity{Provider: ProviderName, ID: identity.ProjectID + ":" + identity.EnvironmentID}, nil
}

// Bind resolves human-readable manifest names to the immutable IDs scoped by
// the project token. It fails closed on missing, duplicate, renamed, or
// explicitly mismatched resources.
func (adapter *Adapter) Bind(ctx context.Context, request BindingRequest) (provider.Target, error) {
	if request.Project == "" || request.Environment == "" || len(request.Services) == 0 {
		return provider.Target{}, errors.New("Railway target request is incomplete")
	}
	identity, err := adapter.identity(ctx)
	if err != nil {
		return provider.Target{}, err
	}
	if request.ProjectID != "" && request.ProjectID != identity.ProjectID ||
		request.EnvironmentID != "" && request.EnvironmentID != identity.EnvironmentID {
		return provider.Target{}, provider.NewError("identity", 0, "TARGET_ID_MISMATCH", provider.RetryNever)
	}
	project, err := adapter.project(ctx, identity.ProjectID)
	if err != nil {
		return provider.Target{}, err
	}
	if project.ID != identity.ProjectID || project.Name != request.Project {
		return provider.Target{}, provider.NewError("inspect", 0, "PROJECT_MISMATCH", provider.RetryNever)
	}
	if !exactNode(project.Environments.Edges, request.Environment, identity.EnvironmentID) {
		return provider.Target{}, provider.NewError("inspect", 0, "ENVIRONMENT_MISMATCH", provider.RetryNever)
	}
	serviceIDs, err := resolveServices(project.Services.Edges, request.Services)
	if err != nil {
		return provider.Target{}, err
	}
	return provider.Target{ProjectID: identity.ProjectID, EnvironmentID: identity.EnvironmentID,
		ServiceIDs: serviceIDs}, nil
}

// Inspect re-resolves an existing immutable binding. Variable maps are
// intentionally empty because Railway has no documented names-only variable
// query; empty means unknown, never absent.
func (adapter *Adapter) Inspect(ctx context.Context, target provider.Target) (provider.MetadataState, error) {
	identity, err := adapter.identity(ctx)
	if err != nil {
		return provider.MetadataState{}, err
	}
	if target.ProjectID != identity.ProjectID || target.EnvironmentID != identity.EnvironmentID {
		return provider.MetadataState{}, provider.NewError("inspect", 0, "IDENTITY_DRIFT", provider.RetryNever)
	}
	project, err := adapter.project(ctx, target.ProjectID)
	if err != nil {
		return provider.MetadataState{}, err
	}
	if project.ID != target.ProjectID || !nodeIDExistsExactlyOnce(project.Environments.Edges, target.EnvironmentID) {
		return provider.MetadataState{}, provider.NewError("inspect", 0, "TARGET_DRIFT", provider.RetryNever)
	}
	if _, err := resolveServices(project.Services.Edges, target.ServiceIDs); err != nil {
		return provider.MetadataState{}, err
	}
	variables := make(map[string]map[string]provider.VariableMetadata, len(target.ServiceIDs))
	for service := range target.ServiceIDs {
		variables[service] = map[string]provider.VariableMetadata{}
	}
	return provider.MetadataState{Target: cloneTarget(target), Variables: variables}, nil
}

func (adapter *Adapter) Write(ctx context.Context, request provider.WriteRequest) (provider.WriteEvidence, error) {
	if request.Operation != "upsert" || request.Target.ProjectID == "" ||
		request.Target.EnvironmentID == "" || request.ServiceID == "" || request.Name == "" ||
		request.Target.ServiceIDs[request.Service] != request.ServiceID {
		return provider.WriteEvidence{}, provider.NewError("write", 0, "INVALID_WRITE", provider.RetryNever)
	}
	var result bool
	err := request.ViewSecret(func(value []byte) error {
		input := struct {
			ProjectID     string `json:"projectId"`
			EnvironmentID string `json:"environmentId"`
			ServiceID     string `json:"serviceId"`
			Name          string `json:"name"`
			Value         string `json:"value"`
			SkipDeploys   bool   `json:"skipDeploys"`
		}{ProjectID: request.Target.ProjectID, EnvironmentID: request.Target.EnvironmentID,
			ServiceID: request.ServiceID, Name: request.Name, Value: string(value), SkipDeploys: true}
		var data struct {
			VariableUpsert bool `json:"variableUpsert"`
		}
		if err := adapter.graphql(ctx, "write", variableUpsertMutation, map[string]any{"input": input}, &data); err != nil {
			return err
		}
		result = data.VariableUpsert
		return nil
	})
	if err != nil {
		return provider.WriteEvidence{}, err
	}
	if !result {
		return provider.WriteEvidence{}, provider.NewError("write", 200, "NOT_COMMITTED", provider.RetryNever)
	}
	return provider.WriteEvidence{}, nil
}

func (*Adapter) Verify(context.Context, provider.VerifyRequest) (provider.VerifyEvidence, error) {
	return provider.VerifyEvidence{Result: provider.VerificationLimited,
		Presence: provider.PresenceUnknown, Reason: "names-only-unavailable"}, nil
}

type tokenIdentity struct {
	ProjectID     string `json:"projectId"`
	EnvironmentID string `json:"environmentId"`
}

func (adapter *Adapter) identity(ctx context.Context) (tokenIdentity, error) {
	var data struct {
		ProjectToken tokenIdentity `json:"projectToken"`
	}
	if err := adapter.graphql(ctx, "identity", identityQuery, nil, &data); err != nil {
		return tokenIdentity{}, err
	}
	if !validID(data.ProjectToken.ProjectID) || !validID(data.ProjectToken.EnvironmentID) {
		return tokenIdentity{}, provider.NewError("identity", 0, "INVALID_IDENTITY", provider.RetryNever)
	}
	return data.ProjectToken, nil
}

type node struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type edges struct {
	Edges []struct {
		Node node `json:"node"`
	} `json:"edges"`
}

type projectMetadata struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Environments edges  `json:"environments"`
	Services     edges  `json:"services"`
}

func (adapter *Adapter) project(ctx context.Context, projectID string) (projectMetadata, error) {
	var data struct {
		Project projectMetadata `json:"project"`
	}
	if err := adapter.graphql(ctx, "inspect", targetQuery, map[string]string{"projectId": projectID}, &data); err != nil {
		return projectMetadata{}, err
	}
	return data.Project, nil
}

func (adapter *Adapter) graphql(ctx context.Context, operation, query string, variables any, destination any) error {
	if adapter == nil || len(adapter.token) == 0 || adapter.client == nil {
		return provider.NewError(operation, 0, "NOT_CONFIGURED", provider.RetryNever)
	}
	body, err := json.Marshal(struct {
		Query     string `json:"query"`
		Variables any    `json:"variables,omitempty"`
	}{Query: query, Variables: variables})
	if err != nil {
		return provider.NewError(operation, 0, "ENCODE_FAILED", provider.RetryNever)
	}
	defer wipe(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adapter.endpoint, bytes.NewReader(body))
	if err != nil {
		return provider.NewError(operation, 0, "REQUEST_FAILED", provider.RetryNever)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Project-Access-Token", string(adapter.token))
	response, err := adapter.client.Do(request)
	if err != nil {
		retry := provider.RetrySafe
		if operation == "write" {
			retry = provider.RetryAmbiguous
		}
		return provider.NewError(operation, 0, "TRANSPORT", retry)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	defer wipe(raw)
	if readErr != nil || len(raw) > maxResponseBytes {
		return provider.NewError(operation, response.StatusCode, "INVALID_RESPONSE", retryForResponse(operation, response.StatusCode))
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return provider.NewError(operation, response.StatusCode, "HTTP_ERROR", retryForResponse(operation, response.StatusCode))
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Errors) != 0 || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		code := "GRAPHQL_ERROR"
		if len(envelope.Errors) != 0 {
			candidate := strings.TrimSpace(envelope.Errors[0].Extensions.Code)
			if candidate != "" && len(candidate) <= provider.MaxProviderCodeBytes && safeCode(candidate) {
				code = candidate
			}
		}
		return provider.NewError(operation, response.StatusCode, code, retryForResponse(operation, response.StatusCode))
	}
	if json.Unmarshal(envelope.Data, destination) != nil {
		return provider.NewError(operation, response.StatusCode, "INVALID_RESPONSE", retryForResponse(operation, response.StatusCode))
	}
	return nil
}

func resolveServices(values []struct {
	Node node `json:"node"`
}, expected map[string]string) (map[string]string, error) {
	byName := make(map[string][]node)
	for _, edge := range values {
		byName[edge.Node.Name] = append(byName[edge.Node.Name], edge.Node)
	}
	result := make(map[string]string, len(expected))
	seenIDs := make(map[string]struct{}, len(expected))
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		nodes := byName[name]
		if len(nodes) != 1 || !validID(nodes[0].ID) {
			return nil, provider.NewError("inspect", 0, "SERVICE_RESOLUTION", provider.RetryNever)
		}
		id := nodes[0].ID
		if expected[name] != "" && expected[name] != id {
			return nil, provider.NewError("inspect", 0, "SERVICE_ID_MISMATCH", provider.RetryNever)
		}
		if _, exists := seenIDs[id]; exists {
			return nil, provider.NewError("inspect", 0, "SERVICE_RESOLUTION", provider.RetryNever)
		}
		seenIDs[id] = struct{}{}
		result[name] = id
	}
	return result, nil
}

func exactNode(values []struct {
	Node node `json:"node"`
}, name, id string) bool {
	nameCount, idCount, exactCount := 0, 0, 0
	for _, edge := range values {
		if edge.Node.Name == name {
			nameCount++
		}
		if edge.Node.ID == id {
			idCount++
		}
		if edge.Node.Name == name && edge.Node.ID == id {
			exactCount++
		}
	}
	return nameCount == 1 && idCount == 1 && exactCount == 1
}

func nodeIDExistsExactlyOnce(values []struct {
	Node node `json:"node"`
}, id string) bool {
	count := 0
	for _, edge := range values {
		if edge.Node.ID == id {
			count++
		}
	}
	return count == 1
}

func validID(value string) bool {
	return value != "" && len(value) <= 128 && safeCode(value)
}

func safeCode(value string) bool {
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' && character != ':' &&
			(character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func retryForResponse(operation string, status int) provider.RetryClass {
	if status == http.StatusTooManyRequests {
		return provider.RetrySafe
	}
	if operation == "write" && status >= 200 && status <= 299 {
		return provider.RetryAmbiguous
	}
	if status >= 500 {
		if operation == "write" {
			return provider.RetryAmbiguous
		}
		return provider.RetrySafe
	}
	return provider.RetryNever
}

func isLoopback(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func cloneTarget(target provider.Target) provider.Target {
	result := target
	result.ServiceIDs = make(map[string]string, len(target.ServiceIDs))
	for name, id := range target.ServiceIDs {
		result.ServiceIDs[name] = id
	}
	return result
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
