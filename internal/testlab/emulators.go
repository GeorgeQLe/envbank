package testlab

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// providerEmulators are loopback-only protocol fakes. Their addresses and
// control plane never cross MCP; production code has no import path to them.
type providerEmulators struct{ Stripe, Clerk, Vercel, Railway *httptest.Server }

func startProviderEmulators() (*providerEmulators, error) {
	type stripeCredential struct {
		value     []byte
		delivered bool
	}
	stripeState := struct {
		sync.Mutex
		idempotent map[string]stripeCredential
	}{idempotent: map[string]stripeCredential{}}
	stripe := newLoopbackServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/account":
			json.NewEncoder(writer).Encode(map[string]string{"id": "acct_testlab"})
		case request.Method == http.MethodPost && request.URL.Path == "/v1/webhook_endpoints":
			key := request.Header.Get("Idempotency-Key")
			if key == "" {
				http.Error(writer, `{"error":"idempotency required"}`, 400)
				return
			}
			stripeState.Lock()
			credential, exists := stripeState.idempotent[key]
			if !exists {
				credential.value, _ = synthetic("stripe")
			}
			response := map[string]string{"id": "we_testlab"}
			if !credential.delivered {
				response["secret"] = string(credential.value)
				credential.delivered = true
			}
			stripeState.idempotent[key] = credential
			stripeState.Unlock()
			json.NewEncoder(writer).Encode(response)
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/webhook_endpoints/"):
			json.NewEncoder(writer).Encode(map[string]bool{"deleted": true})
		default:
			http.Error(writer, `{"error":"unsupported"}`, 404)
		}
	}))
	clerk := newLoopbackServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/applications/app":
			json.NewEncoder(writer).Encode(map[string]string{"id": "app_testlab"})
		case "/dashboard/apps/app/keys":
			io.WriteString(writer, `{"key_id":"key_testlab","value":"••••••••"}`)
		default:
			http.Error(writer, `{"error":"unsupported"}`, 404)
		}
	}))
	vercel := newLoopbackServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/env") {
			http.Error(writer, `{"error":"write-only"}`, 405)
			return
		}
		if request.Method == http.MethodPost || request.Method == http.MethodPatch {
			json.NewEncoder(writer).Encode(map[string]string{"id": "deployment_testlab", "status": "READY"})
			return
		}
		json.NewEncoder(writer).Encode(map[string]string{"id": "project_testlab"})
	}))
	railway := newLoopbackServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		raw, _ := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		query := string(raw)
		if strings.Contains(query, "variables") && !strings.Contains(query, "variableUpsert") {
			http.Error(writer, `{"errors":[{"message":"value queries prohibited"}]}`, 400)
			return
		}
		json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"project": map[string]string{"id": "railway-project"}, "status": "SUCCESS"}})
	}))
	return &providerEmulators{Stripe: stripe, Clerk: clerk, Vercel: vercel, Railway: railway}, nil
}

func newLoopbackServer(handler http.Handler) *httptest.Server {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		// Some hermetic runners prohibit sockets entirely. The in-process
		// emulator state remains usable by the workflow in that environment.
		return nil
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Listener = listener
	server.Start()
	return server
}
func (emulators *providerEmulators) Close() {
	for _, server := range []*httptest.Server{emulators.Stripe, emulators.Clerk, emulators.Vercel, emulators.Railway} {
		if server != nil {
			server.Close()
		}
	}
}
