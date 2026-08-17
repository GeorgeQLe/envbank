package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHTTPAPIStagesOneUndeployedVersionWithInheritedBindings(t *testing.T) {
	posts := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer token-SENTINEL" {
			t.Fatal("Cloudflare request omitted API token")
		}
		if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/versions/prior_version") {
			return cloudflareResponse(`{"success":true,"result":{"resources":{"bindings":[{"name":"D1"},{"name":"SECRET_ONE"}]}}}`), nil
		}
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/versions") ||
			request.URL.Query().Get("bindings_inherit") != "strict" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.String())
		}
		posts++
		mediaType := request.Header.Get("Content-Type")
		boundary := strings.TrimPrefix(mediaType, "multipart/form-data; boundary=")
		reader := multipart.NewReader(request.Body, boundary)
		parts := map[string][]byte{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			parts[part.FormName()], _ = io.ReadAll(part)
		}
		var metadata struct {
			Bindings []map[string]string `json:"bindings"`
		}
		if err := json.Unmarshal(parts["metadata"], &metadata); err != nil {
			t.Fatal(err)
		}
		if string(parts["worker.js"]) != "export default { fetch() {} }" || len(metadata.Bindings) != 3 {
			t.Fatalf("unexpected staged content: module=%q bindings=%#v", parts["worker.js"], metadata.Bindings)
		}
		if metadata.Bindings[0]["name"] != "D1" || metadata.Bindings[0]["type"] != "inherit" ||
			metadata.Bindings[0]["version_id"] != "prior_version" ||
			metadata.Bindings[1]["name"] != "SECRET_ONE" || metadata.Bindings[1]["text"] != "first" ||
			metadata.Bindings[2]["name"] != "SECRET_TWO" || metadata.Bindings[2]["text"] != "second" {
			t.Fatalf("atomic binding metadata = %#v", metadata.Bindings)
		}
		return cloudflareResponse(`{"success":true,"result":{"id":"staged_version"}}`), nil
	})
	api, err := New([]byte("token-SENTINEL"), Options{APIURL: "https://cloudflare.invalid/client/v4",
		HTTPClient: &http.Client{Transport: transport}, Module: []byte("export default { fetch() {} }")})
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	version, err := api.Stage(context.Background(), StageRequest{Target: Target{
		AccountID: "account", ZoneID: "zone", ScriptName: "siftcut-staging"},
		PriorVersionID: "prior_version", Secrets: map[string][]byte{
			"SECRET_TWO": []byte("second"), "SECRET_ONE": []byte("first"),
		}})
	if err != nil {
		t.Fatal(err)
	}
	if version != "staged_version" || posts != 1 {
		t.Fatalf("version=%q posts=%d", version, posts)
	}
}

func cloudflareResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
		Body: io.NopCloser(bytes.NewBufferString(body))}
}
