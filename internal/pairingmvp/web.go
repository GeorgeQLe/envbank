package pairingmvp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/GeorgeQLe/invisible-envs-bank/internal/secure"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	sessionCookie       = "envbank_pairing_lab"
	controllerBodyLimit = 64 << 10
)

type Controller struct {
	lab     *Lab
	host    string
	origin  string
	session string
	csrf    string
}

type UIServer struct {
	URL      string
	HTTP     *http.Server
	Listener net.Listener
}

func StartUI(lab *Lab) (*UIServer, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	host := listener.Addr().String()
	controller, err := NewController(lab, host)
	if err != nil {
		listener.Close()
		return nil, err
	}
	httpServer := &http.Server{Handler: controller, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10}
	result := &UIServer{URL: "http://" + host, HTTP: httpServer, Listener: listener}
	go func() { _ = httpServer.Serve(listener) }()
	return result, nil
}

func NewController(lab *Lab, host string) (*Controller, error) {
	if lab == nil {
		return nil, errors.New("lab is required")
	}
	parsedHost, _, err := net.SplitHostPort(host)
	if err != nil || net.ParseIP(parsedHost) == nil || !net.ParseIP(parsedHost).IsLoopback() {
		return nil, errors.New("pairing UI must bind to a loopback address")
	}
	sessionBytes, err := secure.RandomBytes(24)
	if err != nil {
		return nil, err
	}
	csrfBytes, err := secure.RandomBytes(24)
	if err != nil {
		return nil, err
	}
	return &Controller{lab: lab, host: host, origin: "http://" + host,
		session: secure.Encode(sessionBytes), csrf: secure.Encode(csrfBytes)}, nil
}

func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.Host != c.host {
		writeControllerError(w, http.StatusBadRequest, "invalid Host header")
		return
	}
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		writeControllerError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		c.serveIndex(w, r)
		return
	}
	if !c.validSession(r) {
		writeControllerError(w, http.StatusUnauthorized, "invalid lab session")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/state":
		writeControllerJSON(w, http.StatusOK, c.lab.State())
	case r.Method == http.MethodGet && r.URL.Path == "/api/qr":
		c.serveQR(w)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/"):
		c.mutate(w, r)
	default:
		writeControllerError(w, http.StatusNotFound, "not found")
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func (c *Controller) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != c.origin {
		writeControllerError(w, http.StatusForbidden, "foreign Origin")
		return
	}
	nonceBytes, err := secure.RandomBytes(18)
	if err != nil {
		writeControllerError(w, 500, "randomness unavailable")
		return
	}
	nonce := secure.Encode(nonceBytes)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+
		"'; style-src 'nonce-"+nonce+"'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: c.session, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
	output := bytes.ReplaceAll([]byte(indexHTML), []byte("__CSP_NONCE__"), []byte(nonce))
	output = bytes.ReplaceAll(output, []byte("__CSRF_TOKEN__"), []byte(c.csrf))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output)
}

func (c *Controller) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	return err == nil && cookie.Value == c.session
}

func (c *Controller) mutate(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != c.origin {
		writeControllerError(w, http.StatusForbidden, "invalid Origin")
		return
	}
	if r.Header.Get("X-CSRF-Token") != c.csrf {
		writeControllerError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeControllerError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var state State
	var err error
	switch r.URL.Path {
	case "/api/request":
		var input struct {
			Name string `json:"name"`
		}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Request(input.Name)
		} else {
			return
		}
	case "/api/import":
		var input struct {
			Payload string `json:"payload"`
		}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Import(input.Payload)
		} else {
			return
		}
	case "/api/approve":
		var input struct {
			Fingerprint string `json:"fingerprint"`
		}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Approve(input.Fingerprint)
		} else {
			return
		}
	case "/api/reject":
		var input struct{}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Reject()
		} else {
			return
		}
	case "/api/cancel":
		var input struct{}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Cancel()
		} else {
			return
		}
	case "/api/refresh":
		var input struct{}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Refresh()
		} else {
			return
		}
	case "/api/accept":
		var input struct{}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Accept()
		} else {
			return
		}
	case "/api/reset":
		var input struct{}
		if decodeControllerJSON(w, r, &input) {
			state, err = c.lab.Reset()
		} else {
			return
		}
	default:
		writeControllerError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) {
			writeControllerError(w, statusErr.Status, statusErr.Message)
		} else {
			writeControllerError(w, http.StatusInternalServerError, "lab operation failed")
		}
		return
	}
	writeControllerJSON(w, http.StatusOK, state)
}

func decodeControllerJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, controllerBodyLimit+1))
	if err != nil || len(raw) > controllerBodyLimit {
		writeControllerError(w, http.StatusBadRequest, "request body is too large")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeControllerError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeControllerError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (c *Controller) serveQR(w http.ResponseWriter) {
	state := c.lab.State()
	if state.PairingPayload == "" {
		writeControllerError(w, http.StatusConflict, "no pairing payload is available")
		return
	}
	png, err := qrcode.Encode(state.PairingPayload, qrcode.Medium, 320)
	if err != nil {
		writeControllerError(w, 500, "could not encode QR")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}

func writeControllerJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeControllerError(w http.ResponseWriter, status int, message string) {
	writeControllerJSON(w, status, map[string]string{"error": message})
}

func (u *UIServer) Close() error {
	if u == nil || u.HTTP == nil {
		return nil
	}
	return u.HTTP.Close()
}

func (u *UIServer) String() string { return fmt.Sprintf("pairing UI at %s", u.URL) }
