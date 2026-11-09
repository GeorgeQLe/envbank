package vercelworkflow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type noReadBody struct{ reads, closes int }

func (b *noReadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *noReadBody) Close() error             { b.closes++; return nil }

func TestScopedHealthCredentialNeverUsesURLCookiesOrResponseBody(t *testing.T) {
	scope := vercel.Scope{TeamID: "team_fixture", ProjectID: "prj_fixture", Environment: "preview", GitBranch: "acceptance"}
	deployment := vercel.Deployment{ID: "dpl_health", ProjectID: scope.ProjectID, TeamID: scope.TeamID, Environment: scope.Environment, GitBranch: scope.GitBranch, URL: "fixture.vercel.app", ReadyState: "READY"}
	body := &noReadBody{}
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "fixture.vercel.app" || r.URL.RawQuery != "" || r.Header.Get("x-vercel-protection-bypass") != "fake-health-credential" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unsafe health request")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://elsewhere.invalid/"}}, Body: body, Request: r}, nil
	})}
	probe, closeProbe, e := newHealthProbe(scope, []byte("fake-health-credential"), client)
	if e != nil {
		t.Fatal(e)
	}
	ok, e := probe(context.Background(), deployment, "/health")
	if e != nil || ok || calls != 1 || body.reads != 0 || body.closes != 1 {
		t.Fatal("health followed redirect, read body or accepted redirect")
	}
	deployment.ProjectID = "prj_other"
	_, e = probe(context.Background(), deployment, "/health")
	if e == nil || calls != 1 {
		t.Fatal("health credential crossed project scope")
	}
	deployment.ProjectID = scope.ProjectID
	deployment.URL = "elsewhere.invalid"
	_, e = probe(context.Background(), deployment, "/health")
	if e == nil || calls != 1 {
		t.Fatal("health credential crossed host boundary")
	}
	closeProbe()
	deployment.URL = "fixture.vercel.app"
	if _, e = probe(context.Background(), deployment, "/health"); e == nil {
		t.Fatal("closed health probe released credential")
	}
}

func TestHealthErrorsAndInvalidPathsDoNotEchoValues(t *testing.T) {
	scope := vercel.Scope{TeamID: "team_fixture", ProjectID: "prj_fixture", Environment: "production"}
	d := vercel.Deployment{TeamID: scope.TeamID, ProjectID: scope.ProjectID, Environment: scope.Environment, URL: "fixture.vercel.app"}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(privateFixture) })}
	probe, closeProbe, e := newHealthProbe(scope, nil, client)
	if e != nil {
		t.Fatal(e)
	}
	defer closeProbe()
	_, e = probe(context.Background(), d, "/health")
	if e == nil || strings.Contains(e.Error(), privateFixture) {
		t.Fatal("transport error escaped health boundary")
	}
	for _, path := range []string{"//foreign.invalid", "/health?token=x", "/health#fragment", "https://elsewhere.invalid", "/%3Ftoken"} {
		if ValidHealthPath(path) {
			t.Fatal("unsafe health path accepted")
		}
	}
}
