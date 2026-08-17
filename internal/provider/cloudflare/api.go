package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const defaultAPIURL = "https://api.cloudflare.com/client/v4"

var (
	cloudflareID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	scriptName   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
)

type Options struct {
	APIURL     string
	HTTPClient *http.Client
	ModuleName string
	Module     []byte
}

type HTTPAPI struct {
	token      []byte
	apiURL     string
	httpClient *http.Client
	moduleName string
	module     []byte
}

func New(token []byte, options Options) (*HTTPAPI, error) {
	trimmed := bytes.TrimSpace(token)
	if len(trimmed) < 8 || len(trimmed) > 4096 || bytes.IndexAny(trimmed, "\r\n\x00") >= 0 {
		return nil, errors.New("Cloudflare API token is invalid")
	}
	apiURL := strings.TrimRight(options.APIURL, "/")
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	parsed, err := url.Parse(apiURL)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" {
		return nil, errors.New("Cloudflare API URL is invalid")
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	moduleName := options.ModuleName
	if moduleName == "" {
		moduleName = "worker.js"
	}
	if !scriptName.MatchString(strings.TrimSuffix(moduleName, ".js")) || !strings.HasSuffix(moduleName, ".js") {
		return nil, errors.New("Cloudflare Worker module name is invalid")
	}
	return &HTTPAPI{token: append([]byte(nil), trimmed...), apiURL: apiURL,
		httpClient: client, moduleName: moduleName, module: append([]byte(nil), options.Module...)}, nil
}

func (api *HTTPAPI) Close() {
	clear(api.token)
	clear(api.module)
}

func (api *HTTPAPI) Identity(ctx context.Context, accountID string) error {
	if !cloudflareID.MatchString(accountID) {
		return errors.New("Cloudflare account ID is invalid")
	}
	var response envelope[struct {
		ID string `json:"id"`
	}]
	if err := api.get(ctx, "/accounts/"+url.PathEscape(accountID), &response); err != nil {
		return err
	}
	if !response.Success || response.Result.ID != accountID {
		return errors.New("Cloudflare account identity mismatch")
	}
	return nil
}

func (api *HTTPAPI) Inspect(ctx context.Context, target Target) (Snapshot, error) {
	if err := validateCloudflareTarget(target); err != nil {
		return Snapshot{}, err
	}
	if err := api.Identity(ctx, target.AccountID); err != nil {
		return Snapshot{}, err
	}
	var zone envelope[struct {
		ID      string `json:"id"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}]
	if err := api.get(ctx, "/zones/"+url.PathEscape(target.ZoneID), &zone); err != nil {
		return Snapshot{}, err
	}
	if !zone.Success || zone.Result.ID != target.ZoneID || zone.Result.Account.ID != target.AccountID {
		return Snapshot{}, errors.New("Cloudflare zone identity mismatch")
	}
	versions, err := api.deployments(ctx, target)
	if err != nil {
		return Snapshot{}, err
	}
	if len(versions) != 1 || versions[0].Percentage != 100 || versions[0].VersionID == "" {
		return Snapshot{}, errors.New("Cloudflare Worker does not have one fully deployed version")
	}
	names, err := api.VersionBindingNames(ctx, target, versions[0].VersionID)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{AccountID: target.AccountID, ZoneID: target.ZoneID, ScriptName: target.ScriptName,
		PriorVersionID: versions[0].VersionID, BindingNames: names}, nil
}

func (api *HTTPAPI) Stage(ctx context.Context, request StageRequest) (string, error) {
	if err := validateCloudflareTarget(request.Target); err != nil {
		return "", err
	}
	if len(api.module) == 0 || request.PriorVersionID == "" || len(request.Secrets)+len(request.RemovedNames) == 0 {
		return "", errors.New("Cloudflare version stage is incomplete")
	}
	priorNames, err := api.VersionBindingNames(ctx, request.Target, request.PriorVersionID)
	if err != nil {
		return "", err
	}
	type binding map[string]string
	bindings := make([]binding, 0, len(priorNames)+len(request.Secrets))
	removed := make(map[string]struct{}, len(request.RemovedNames))
	for _, name := range request.RemovedNames {
		if !validBindingName(name) {
			return "", errors.New("Cloudflare removed binding name is invalid")
		}
		removed[name] = struct{}{}
	}
	for _, name := range priorNames {
		if _, replaced := request.Secrets[name]; replaced {
			continue
		}
		if _, deleted := removed[name]; deleted {
			continue
		}
		bindings = append(bindings, binding{"name": name, "type": "inherit", "version_id": request.PriorVersionID})
	}
	secretNames := make([]string, 0, len(request.Secrets))
	for name := range request.Secrets {
		if !validBindingName(name) {
			return "", errors.New("Cloudflare binding name is invalid")
		}
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)
	for _, name := range secretNames {
		bindings = append(bindings, binding{"name": name, "type": "secret_text", "text": string(request.Secrets[name])})
	}
	metadata, err := json.Marshal(map[string]any{
		"main_module": api.moduleName,
		"annotations": map[string]string{"workers/message": "EnvBank atomic secret stage"},
		"bindings":    bindings,
	})
	if err != nil {
		return "", errors.New("Cloudflare version metadata could not be encoded")
	}
	defer clear(metadata)
	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	metadataHeader := makeTextPart("metadata", "application/json")
	part, err := writer.CreatePart(metadataHeader)
	if err == nil {
		_, err = part.Write(metadata)
	}
	if err == nil {
		moduleHeader := makeFilePart(api.moduleName, "application/javascript+module")
		part, err = writer.CreatePart(moduleHeader)
		if err == nil {
			_, err = part.Write(api.module)
		}
	}
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return "", errors.New("Cloudflare version upload could not be assembled")
	}
	raw := multipartBody.Bytes()
	defer clear(raw)
	path := fmt.Sprintf("/accounts/%s/workers/scripts/%s/versions?bindings_inherit=strict",
		url.PathEscape(request.Target.AccountID), url.PathEscape(request.Target.ScriptName))
	var response envelope[struct {
		ID string `json:"id"`
	}]
	if err := api.request(ctx, http.MethodPost, path, writer.FormDataContentType(), raw, &response); err != nil {
		return "", err
	}
	if !response.Success || response.Result.ID == "" {
		return "", errors.New("Cloudflare did not return a staged version")
	}
	return response.Result.ID, nil
}

func (api *HTTPAPI) VersionBindingNames(ctx context.Context, target Target, versionID string) ([]string, error) {
	if err := validateCloudflareTarget(target); err != nil || !cloudflareID.MatchString(versionID) {
		return nil, errors.New("Cloudflare version identity is invalid")
	}
	var response envelope[struct {
		Resources struct {
			Bindings []struct {
				Name string `json:"name"`
			} `json:"bindings"`
		} `json:"resources"`
	}]
	path := fmt.Sprintf("/accounts/%s/workers/scripts/%s/versions/%s", url.PathEscape(target.AccountID),
		url.PathEscape(target.ScriptName), url.PathEscape(versionID))
	if err := api.get(ctx, path, &response); err != nil {
		return nil, err
	}
	if !response.Success {
		return nil, errors.New("Cloudflare version inspection failed")
	}
	names := make([]string, 0, len(response.Result.Resources.Bindings))
	seen := make(map[string]struct{}, len(response.Result.Resources.Bindings))
	for _, binding := range response.Result.Resources.Bindings {
		if !validBindingName(binding.Name) {
			return nil, errors.New("Cloudflare returned an invalid binding name")
		}
		if _, exists := seen[binding.Name]; !exists {
			seen[binding.Name] = struct{}{}
			names = append(names, binding.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (api *HTTPAPI) Deploy(ctx context.Context, target Target, versionID string, force bool) (string, error) {
	if err := validateCloudflareTarget(target); err != nil || !cloudflareID.MatchString(versionID) {
		return "", errors.New("Cloudflare deployment identity is invalid")
	}
	body, err := json.Marshal(map[string]any{"strategy": "percentage",
		"versions": []map[string]any{{"version_id": versionID, "percentage": 100}}})
	if err != nil {
		return "", errors.New("Cloudflare deployment request could not be encoded")
	}
	path := fmt.Sprintf("/accounts/%s/workers/scripts/%s/deployments", url.PathEscape(target.AccountID),
		url.PathEscape(target.ScriptName))
	if force {
		path += "?force=true"
	}
	var response envelope[struct {
		ID string `json:"id"`
	}]
	if err := api.request(ctx, http.MethodPost, path, "application/json", body, &response); err != nil {
		return "", err
	}
	if !response.Success || response.Result.ID == "" {
		return "", errors.New("Cloudflare deployment did not return an ID")
	}
	return response.Result.ID, nil
}

// DeleteVersion removes an undeployed disposable version through Cloudflare's
// Worker resource API. It must only be used after traffic has been restored to
// a different version.
func (api *HTTPAPI) DeleteVersion(ctx context.Context, target Target, versionID string) error {
	if err := validateCloudflareTarget(target); err != nil || !cloudflareID.MatchString(versionID) {
		return errors.New("Cloudflare disposable version identity is invalid")
	}
	path := fmt.Sprintf("/accounts/%s/workers/workers/%s/versions/%s",
		url.PathEscape(target.AccountID), url.PathEscape(target.ScriptName), url.PathEscape(versionID))
	var response envelope[json.RawMessage]
	if err := api.request(ctx, http.MethodDelete, path, "application/json", nil, &response); err != nil {
		return err
	}
	if !response.Success {
		return errors.New("Cloudflare disposable version deletion failed")
	}
	return nil
}

type deploymentVersion struct {
	VersionID  string  `json:"version_id"`
	Percentage float64 `json:"percentage"`
}

func (api *HTTPAPI) deployments(ctx context.Context, target Target) ([]deploymentVersion, error) {
	var response envelope[struct {
		Deployments []struct {
			Versions []deploymentVersion `json:"versions"`
		} `json:"deployments"`
	}]
	path := fmt.Sprintf("/accounts/%s/workers/scripts/%s/deployments", url.PathEscape(target.AccountID),
		url.PathEscape(target.ScriptName))
	if err := api.get(ctx, path, &response); err != nil {
		return nil, err
	}
	if !response.Success || len(response.Result.Deployments) == 0 {
		return nil, errors.New("Cloudflare Worker has no active deployment")
	}
	return response.Result.Deployments[0].Versions, nil
}

type envelope[T any] struct {
	Success bool `json:"success"`
	Result  T    `json:"result"`
}

func (api *HTTPAPI) get(ctx context.Context, path string, destination any) error {
	return api.request(ctx, http.MethodGet, path, "", nil, destination)
}

func (api *HTTPAPI) request(ctx context.Context, method, path, contentType string, body []byte, destination any) error {
	request, err := http.NewRequestWithContext(ctx, method, api.apiURL+path, bytes.NewReader(body))
	if err != nil {
		return provider.NewError("request", 0, "REQUEST_INVALID", provider.RetryNever)
	}
	request.Header.Set("Authorization", "Bearer "+string(api.token))
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := api.httpClient.Do(request)
	if err != nil {
		return provider.NewError("request", 0, "TRANSPORT", provider.RetrySafe)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if readErr != nil {
		return provider.NewError("response", response.StatusCode, "READ", provider.RetrySafe)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		retry := provider.RetryNever
		if response.StatusCode == 408 || response.StatusCode == 429 || response.StatusCode >= 500 {
			retry = provider.RetrySafe
		}
		return provider.NewError("response", response.StatusCode, "CF_API", retry)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return provider.NewError("response", response.StatusCode, "INVALID_JSON", provider.RetryAmbiguous)
	}
	return nil
}

func validateCloudflareTarget(target Target) error {
	if !cloudflareID.MatchString(target.AccountID) || !cloudflareID.MatchString(target.ZoneID) ||
		!scriptName.MatchString(target.ScriptName) {
		return errors.New("Cloudflare account, zone, or script identity is invalid")
	}
	return nil
}

func validBindingName(name string) bool {
	if name == "" || len(name) > 128 || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	for _, current := range name {
		if current != '_' && (current < 'A' || current > 'Z') && (current < '0' || current > '9') {
			return false
		}
	}
	return true
}

func makeTextPart(name, contentType string) textproto.MIMEHeader {
	return textproto.MIMEHeader{"Content-Disposition": {fmt.Sprintf(`form-data; name=%q`, name)}, "Content-Type": {contentType}}
}

func makeFilePart(name, contentType string) textproto.MIMEHeader {
	return textproto.MIMEHeader{"Content-Disposition": {fmt.Sprintf(`form-data; name=%q; filename=%q`, name, name)},
		"Content-Type": {contentType}}
}
