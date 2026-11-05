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
	ID     string
	URL    string
	Events []string
}

const maxEndpointEvents = 256

// Endpoint reads a webhook endpoint's ID, URL and enabled events. Only those
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
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if dec.Decode(&wire) != nil || wire.ID != id || wire.URL == "" || len(wire.EnabledEvents) == 0 || len(wire.EnabledEvents) > maxEndpointEvents {
		return WebhookEndpoint{}, provider.NewError("endpoint", 200, "INVALID_RESPONSE", provider.RetryNever)
	}
	return WebhookEndpoint{ID: wire.ID, URL: wire.URL, Events: wire.EnabledEvents}, nil
}
