package stripe

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

// WebhookEndpoint is an endpoint's non-secret configuration.
type WebhookEndpoint struct {
	ID         string
	URL        string
	Events     []string
	Status     string // "enabled" or "disabled"
	APIVersion string // "" when the endpoint uses the account default (null)
}

const maxEndpointEvents = 256

// Endpoint reads a webhook endpoint's ID, URL, enabled events, status and
// API version. Only those
// fields are decoded; the response buffer is wiped. (Stripe returns the
// signing secret only on create, but nothing else is decoded regardless.)
func (adapter *Adapter) Endpoint(ctx context.Context, id string) (WebhookEndpoint, error) {
	if !strings.HasPrefix(id, "we_") {
		return WebhookEndpoint{}, provider.NewError("endpoint", 0, "INVALID_ID", provider.RetryNever)
	}
	body, status, err := adapter.request(ctx, http.MethodGet, "/v1/webhook_endpoints/"+url.PathEscape(id), nil, "")
	if err != nil {
		return WebhookEndpoint{}, err
	}
	defer wipe(body)
	if status != 200 {
		return WebhookEndpoint{}, provider.NewError("endpoint", status, "STRIPE_RESPONSE", retry(status))
	}
	var wire struct {
		ID            string   `json:"id"`
		URL           string   `json:"url"`
		EnabledEvents []string `json:"enabled_events"`
		Status        string   `json:"status"`
		APIVersion    *string  `json:"api_version"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if dec.Decode(&wire) != nil || wire.ID != id || wire.URL == "" || len(wire.EnabledEvents) == 0 || len(wire.EnabledEvents) > maxEndpointEvents ||
		(wire.Status != "enabled" && wire.Status != "disabled") || (wire.APIVersion != nil && (*wire.APIVersion == "" || len(*wire.APIVersion) > 64)) {
		return WebhookEndpoint{}, provider.NewError("endpoint", 200, "INVALID_RESPONSE", provider.RetryNever)
	}
	ep := WebhookEndpoint{ID: wire.ID, URL: wire.URL, Events: wire.EnabledEvents, Status: wire.Status}
	if wire.APIVersion != nil {
		ep.APIVersion = *wire.APIVersion
	}
	return ep, nil
}
