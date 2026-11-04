package vercelworkflow

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider/vercel"
)

var healthHost = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.vercel\.app$`)

// ProbeHealth never forwards the Vercel API credential or reads a health body.
// Deployment protection/authentication failures stay failures; they are not
// silently bypassed or treated as successful acceptance.
func ProbeHealth(ctx context.Context, deployment vercel.Deployment, path string) (bool, error) {
	return probeHealth(ctx, deployment, path, nil, &http.Client{})
}

// NewHealthProbe optionally uses an owner-imported project automation bypass
// credential. It is bound to the exact approved project/environment/branch,
// sent only as a header, never a URL, and never becomes a browser cookie.
func NewHealthProbe(scope vercel.Scope, token []byte) (func(context.Context, vercel.Deployment, string) (bool, error), func(), error) {
	return newHealthProbe(scope, token, &http.Client{})
}
func newHealthProbe(scope vercel.Scope, token []byte, client *http.Client) (func(context.Context, vercel.Deployment, string) (bool, error), func(), error) {
	if scope.Validate() != nil || len(token) > 4096 {
		return nil, nil, errors.New("health credential binding invalid")
	}
	for _, c := range token {
		if c <= ' ' || c >= 0x7f {
			return nil, nil, errors.New("health credential binding invalid")
		}
	}
	credential := append([]byte(nil), token...)
	var mu sync.RWMutex
	closed := false
	closeProbe := func() {
		mu.Lock()
		defer mu.Unlock()
		for i := range credential {
			credential[i] = 0
		}
		credential = nil
		closed = true
	}
	probe := func(ctx context.Context, d vercel.Deployment, path string) (bool, error) {
		if d.ProjectID != scope.ProjectID || d.TeamID != scope.TeamID || d.Environment != scope.Environment || scope.GitBranch != "" && d.GitBranch != scope.GitBranch {
			return false, errors.New("health deployment scope changed")
		}
		mu.RLock()
		if closed {
			mu.RUnlock()
			return false, errors.New("health probe closed")
		}
		value := append([]byte(nil), credential...)
		mu.RUnlock()
		defer func() {
			for i := range value {
				value[i] = 0
			}
		}()
		return probeHealth(ctx, d, path, value, client)
	}
	return probe, closeProbe, nil
}

func probeHealth(ctx context.Context, deployment vercel.Deployment, path string, token []byte, supplied *http.Client) (bool, error) {
	if !ValidHealthPath(path) {
		return false, errors.New("health path invalid")
	}
	host := strings.TrimPrefix(deployment.URL, "https://")
	if !healthHost.MatchString(host) {
		return false, errors.New("health deployment URL invalid")
	}
	u := url.URL{Scheme: "https", Host: host, Path: path}
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return false, errors.New("health request invalid")
	}
	if len(token) > 0 {
		request.Header.Set("x-vercel-protection-bypass", string(token))
	}
	client := *supplied
	client.Timeout = 10 * time.Second
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := client.Do(request)
	if e != nil {
		return false, errors.New("health request failed")
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK, nil
}
