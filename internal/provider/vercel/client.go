package vercel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/GeorgeQLe/envbank/internal/provider"
)

const (
	DefaultEndpoint = "https://api.vercel.com"
	productionHost  = "api.vercel.com"

	maxTokenBytes    = 4096
	maxResponseBytes = 4 << 20
	initialReadBytes = 32 << 10
	requestTimeout   = 30 * time.Second
)

// Options configures transport only. Endpoint must be https://api.vercel.com
// (the default) or, for tests, an http/https URL whose host is a literal
// loopback IP address.
type Options struct {
	Endpoint string
	Client   *http.Client
	Now      func() time.Time
}

// Adapter is safe for concurrent use. Close wipes the retained token copy.
type Adapter struct {
	mu     sync.RWMutex
	token  []byte
	scope  Scope
	base   string
	client *http.Client
	now    func() time.Time
}

var _ provider.Adapter = (*Adapter)(nil)

func New(token []byte, scope Scope, options Options) (*Adapter, error) {
	if len(token) == 0 || len(token) > maxTokenBytes || bytes.IndexFunc(token, func(r rune) bool {
		return r <= ' ' || r >= 0x7f
	}) >= 0 {
		return nil, errors.New("Vercel access token is invalid")
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	base, err := endpointBase(options.Endpoint)
	if err != nil {
		return nil, err
	}
	var clientCopy http.Client
	if options.Client != nil {
		clientCopy = *options.Client
	}
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > requestTimeout {
		clientCopy.Timeout = requestTimeout
	}
	// Never forward the bearer token to a redirect target, regardless of the
	// supplied client's policy, and never attach ambient cookies.
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clientCopy.Jar = nil
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Adapter{token: append([]byte(nil), token...), scope: scope, base: base,
		client: &clientCopy, now: now}, nil
}

func endpointBase(endpoint string) (string, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	invalid := errors.New("Vercel API endpoint is invalid")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", invalid
	}
	host := parsed.Hostname()
	switch {
	case parsed.Scheme == "https" && host == productionHost && parsed.Port() == "":
		return "https://" + productionHost, nil
	case (parsed.Scheme == "http" || parsed.Scheme == "https") && literalLoopback(host):
		return parsed.Scheme + "://" + parsed.Host, nil
	default:
		return "", invalid
	}
}

func literalLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close wipes the adapter's token copy. Strings already handed to net/http
// for in-flight request headers cannot be wiped by Go code.
func (adapter *Adapter) Close() {
	if adapter == nil {
		return
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	wipe(adapter.token)
	adapter.token = nil
}

// Scope returns the adapter's immutable scope.
func (adapter *Adapter) Scope() Scope { return adapter.scope }

type apiCall struct {
	operation string
	method    string
	path      string
	query     url.Values
	body      []byte
	mutation  bool
	attempted *bool
}

// send performs one request without retries. decode sees the bounded body
// only for 2xx responses; the buffer is wiped afterwards. Non-2xx bodies are
// read (bounded), wiped and discarded unparsed, so errors carry only status
// derived codes.
func (adapter *Adapter) send(ctx context.Context, call apiCall, decode func([]byte) error) error {
	if adapter == nil || adapter.client == nil {
		return provider.NewError(call.operation, 0, "NOT_CONFIGURED", provider.RetryNever)
	}
	adapter.mu.RLock()
	if len(adapter.token) == 0 {
		adapter.mu.RUnlock()
		return provider.NewError(call.operation, 0, "CLOSED", provider.RetryNever)
	}
	authorization := "Bearer " + string(adapter.token)
	adapter.mu.RUnlock()

	query := url.Values{}
	for key, values := range call.query {
		query[key] = append([]string(nil), values...)
	}
	query.Set("teamId", adapter.scope.TeamID)
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var reader io.Reader = http.NoBody
	if call.body != nil {
		reader = bytes.NewReader(call.body)
	}
	request, err := http.NewRequestWithContext(ctx, call.method, adapter.base+call.path+"?"+query.Encode(), reader)
	if err != nil {
		return provider.NewError(call.operation, 0, "REQUEST_INVALID", provider.RetryNever)
	}
	// Mutations must never be replayed by the transport.
	request.GetBody = nil
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Accept", "application/json")
	if call.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if call.mutation {
		check, ok := ctx.Value(mutationAuthorityKey{}).(func(context.Context) error)
		if !ok || check == nil || check(ctx) != nil {
			return provider.NewError(call.operation, 0, "AUTHORIZATION_DENIED", provider.RetrySafe)
		}
		if call.attempted != nil {
			*call.attempted = true
		}
	}
	response, err := adapter.client.Do(request)
	if err != nil {
		return provider.NewError(call.operation, 0, "TRANSPORT", transportRetry(call.mutation))
	}
	defer response.Body.Close()
	raw, readErr := readBounded(response.Body, response.ContentLength)
	defer wipe(raw)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return provider.NewError(call.operation, response.StatusCode, statusCode(response.StatusCode),
			statusRetry(call.mutation, response.StatusCode))
	}
	if readErr != nil {
		return provider.NewError(call.operation, response.StatusCode, readErr.Error(), invalidRetry(call.mutation))
	}
	if decode == nil {
		return nil
	}
	if err := decode(raw); err != nil {
		var safe provider.Error
		if errors.As(err, &safe) {
			return safe
		}
		return provider.NewError(call.operation, response.StatusCode, "INVALID_RESPONSE", invalidRetry(call.mutation))
	}
	return nil
}

var (
	errTooLarge   = errors.New("RESPONSE_TOO_LARGE")
	errReadFailed = errors.New("RESPONSE_READ_FAILED")
)

// readBounded grows its own buffer, wiping every superseded allocation, so
// potentially secret-bearing bodies are not left in unreachable copies.
func readBounded(body io.Reader, declared int64) ([]byte, error) {
	if declared > maxResponseBytes {
		return nil, errTooLarge
	}
	buffer := make([]byte, 0, initialReadBytes)
	for {
		if len(buffer) == cap(buffer) {
			if len(buffer) > maxResponseBytes {
				return buffer, errTooLarge
			}
			grown := make([]byte, len(buffer), min(2*cap(buffer), maxResponseBytes+1))
			copy(grown, buffer)
			wipe(buffer)
			buffer = grown
		}
		read, err := body.Read(buffer[len(buffer):cap(buffer)])
		buffer = buffer[:len(buffer)+read]
		if len(buffer) > maxResponseBytes {
			return buffer, errTooLarge
		}
		if err == io.EOF {
			return buffer, nil
		}
		if err != nil {
			return buffer, errReadFailed
		}
	}
}

func statusCode(status int) string {
	switch {
	case status >= 300 && status <= 399:
		return "REDIRECT_REJECTED"
	case status == http.StatusBadRequest:
		return "BAD_REQUEST"
	case status == http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case status == http.StatusPaymentRequired:
		return "PAYMENT_REQUIRED"
	case status == http.StatusForbidden:
		return "FORBIDDEN"
	case status == http.StatusNotFound:
		return "NOT_FOUND"
	case status == http.StatusConflict:
		return "CONFLICT"
	case status == http.StatusGone:
		return "GONE"
	case status == http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case status >= 500:
		return "SERVER_ERROR"
	default:
		return "HTTP_ERROR"
	}
}

func transportRetry(mutation bool) provider.RetryClass {
	if mutation {
		return provider.RetryAmbiguous
	}
	return provider.RetrySafe
}

func invalidRetry(mutation bool) provider.RetryClass {
	if mutation {
		// A 2xx mutation response we cannot interpret may have committed.
		return provider.RetryAmbiguous
	}
	return provider.RetryNever
}

func statusRetry(mutation bool, status int) provider.RetryClass {
	switch {
	case status == http.StatusTooManyRequests:
		return provider.RetrySafe
	case status == http.StatusRequestTimeout || status >= 500:
		return transportRetry(mutation)
	case status >= 300 && status <= 399 && mutation:
		return provider.RetryAmbiguous
	default:
		return provider.RetryNever
	}
}

func safeError(operation, code string, retry provider.RetryClass) error {
	return provider.NewError(operation, 0, code, retry)
}

func pathSegment(value string) string {
	return "/" + url.PathEscape(value)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
