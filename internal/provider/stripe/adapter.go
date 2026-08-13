// Package stripe implements the API-supported webhook credential lifecycle.
package stripe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GeorgeQLe/envbank/internal/lifecycle"
	"github.com/GeorgeQLe/envbank/internal/provider"
)

const DefaultEndpoint = "https://api.stripe.com"
const maxResponseBytes = 1 << 20

type Adapter struct {
	endpoint string
	client   *http.Client
	control  []byte
}
type Options struct {
	Endpoint string
	Client   *http.Client
}

func New(controlCredential []byte, options Options) (*Adapter, error) {
	if len(controlCredential) == 0 || len(controlCredential) > 16<<10 || bytes.IndexFunc(controlCredential, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return nil, errors.New("Stripe control credential is invalid")
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")) {
		return nil, errors.New("Stripe API endpoint is invalid")
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
	return &Adapter{endpoint: endpoint, client: &copy, control: append([]byte(nil), controlCredential...)}, nil
}
func (adapter *Adapter) Close() {
	if adapter != nil {
		for i := range adapter.control {
			adapter.control[i] = 0
		}
		adapter.control = nil
	}
}
func (*Adapter) Capabilities() map[string]lifecycle.CredentialCapability {
	return map[string]lifecycle.CredentialCapability{"webhook-signing-secret": lifecycle.CapabilityAutomatic, "secret-key": lifecycle.CapabilityInteractive, "restricted-key": lifecycle.CapabilityInteractive}
}

func (adapter *Adapter) Identify(ctx context.Context) (provider.Identity, error) {
	body, status, err := adapter.request(ctx, http.MethodGet, "/v1/account", nil, "")
	if err != nil {
		return provider.Identity{}, err
	}
	defer wipe(body)
	if status != 200 {
		return provider.Identity{}, provider.NewError("identify", status, "STRIPE_RESPONSE", retry(status))
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return provider.Identity{}, provider.NewError("identify", 200, "INVALID_RESPONSE", provider.RetryNever)
	}
	id, ok := plainJSONString(fields["id"])
	if !ok || !strings.HasPrefix(string(id), "acct_") {
		wipe(id)
		return provider.Identity{}, provider.NewError("identify", 200, "INVALID_IDENTITY", provider.RetryNever)
	}
	defer wipe(id)
	return provider.Identity{Provider: "stripe", ID: string(id)}, nil
}

func (adapter *Adapter) Create(ctx context.Context, request lifecycle.CredentialRequest, sink *lifecycle.SecretSink) (lifecycle.CredentialEvidence, error) {
	if request.CredentialType != "webhook-signing-secret" || request.ProviderIdentity == "" || request.DestinationRecord == "" || sink == nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_REQUEST", provider.RetryNever)
	}
	values := url.Values{}
	urls := request.Parameters["url"]
	events := request.Parameters["enabled_events"]
	if len(urls) != 1 || len(events) == 0 {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_CONFIGURATION", provider.RetryNever)
	}
	parsed, err := url.Parse(urls[0])
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_CONFIGURATION", provider.RetryNever)
	}
	values.Set("url", urls[0])
	for _, event := range events {
		if event == "" {
			return lifecycle.CredentialEvidence{}, provider.NewError("create", 0, "INVALID_CONFIGURATION", provider.RetryNever)
		}
		values.Add("enabled_events[]", event)
	}
	body, status, err := adapter.request(ctx, http.MethodPost, "/v1/webhook_endpoints", strings.NewReader(values.Encode()), request.IdempotencyKey)
	if err != nil {
		return lifecycle.CredentialEvidence{}, err
	}
	defer wipe(body)
	if status != 200 {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", status, "STRIPE_RESPONSE", retry(status))
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 200, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	id, ok := plainJSONString(fields["id"])
	if !ok || !strings.HasPrefix(string(id), "we_") {
		wipe(id)
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 200, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	defer wipe(id)
	secret, ok := plainJSONString(fields["secret"])
	if !ok || !bytes.HasPrefix(secret, []byte("whsec_")) {
		wipe(secret)
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 200, "INVALID_RESPONSE", provider.RetryAmbiguous)
	}
	defer wipe(secret)
	receipt, err := sink.StoreBytes(ctx, secret)
	if err != nil {
		return lifecycle.CredentialEvidence{}, provider.NewError("create", 200, "STORE_REQUIRED", provider.RetryAmbiguous)
	}
	return lifecycle.CredentialEvidence{CredentialID: string(id), CreatedAt: time.Now().UTC().Format(time.RFC3339), Receipt: receipt}, nil
}

func (adapter *Adapter) Validate(ctx context.Context, id string) (provider.VerifyEvidence, error) {
	if !strings.HasPrefix(id, "we_") {
		return provider.VerifyEvidence{}, provider.NewError("validate", 0, "INVALID_ID", provider.RetryNever)
	}
	body, status, err := adapter.request(ctx, http.MethodGet, "/v1/webhook_endpoints/"+url.PathEscape(id), nil, "")
	if err != nil {
		return provider.VerifyEvidence{}, err
	}
	defer wipe(body)
	if status != 200 {
		return provider.VerifyEvidence{}, provider.NewError("validate", status, "STRIPE_RESPONSE", retry(status))
	}
	return provider.VerifyEvidence{Result: provider.VerificationVerified, Presence: provider.PresencePresent, VerifiedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}
func (adapter *Adapter) Revoke(ctx context.Context, id string) error {
	if !strings.HasPrefix(id, "we_") {
		return provider.NewError("revoke", 0, "INVALID_ID", provider.RetryNever)
	}
	body, status, err := adapter.request(ctx, http.MethodDelete, "/v1/webhook_endpoints/"+url.PathEscape(id), nil, "")
	if err != nil {
		return err
	}
	defer wipe(body)
	if status != 200 {
		return provider.NewError("revoke", status, "STRIPE_RESPONSE", retry(status))
	}
	return nil
}

func (adapter *Adapter) request(ctx context.Context, method, path string, body io.Reader, idempotency string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, adapter.endpoint+path, body)
	if err != nil {
		return nil, 0, provider.NewError(strings.ToLower(method), 0, "REQUEST_FAILED", provider.RetryNever)
	}
	req.Header.Set("Authorization", "Bearer "+string(adapter.control))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	response, err := adapter.client.Do(req)
	if err != nil {
		return nil, 0, provider.NewError(strings.ToLower(method), 0, "TRANSPORT_FAILED", provider.RetrySafe)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		wipe(raw)
		return nil, 0, provider.NewError(strings.ToLower(method), response.StatusCode, "RESPONSE_LIMIT", provider.RetryAmbiguous)
	}
	return raw, response.StatusCode, nil
}
func plainJSONString(raw []byte) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' || bytes.IndexByte(raw[1:len(raw)-1], '\\') >= 0 {
		return nil, false
	}
	return append([]byte(nil), raw[1:len(raw)-1]...), true
}
func retry(status int) provider.RetryClass {
	if status == 429 || status >= 500 {
		return provider.RetrySafe
	}
	return provider.RetryNever
}
func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
