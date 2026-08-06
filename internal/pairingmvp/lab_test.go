package pairingmvp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/GeorgeQLe/envbank/internal/client"
	"github.com/GeorgeQLe/envbank/internal/protocol"
	"github.com/GeorgeQLe/envbank/internal/secure"
)

func TestLabEndToEndAndStateConflicts(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	if _, err := lab.Accept(); statusOf(err) != http.StatusConflict {
		t.Fatalf("out-of-order accept: %v", err)
	}
	requested, err := lab.Request("Synthetic phone")
	if err != nil {
		t.Fatal(err)
	}
	if requested.PairingPayload == "" || strings.Contains(requested.PairingPayload, requested.Server+"?") {
		t.Fatal("bad payload")
	}
	if _, err := lab.Request("duplicate"); statusOf(err) != http.StatusConflict {
		t.Fatalf("duplicate request: %v", err)
	}
	decoded, err := DecodePayload(requested.PairingPayload)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Payload){
		func(p *Payload) { p.Server = "http://127.0.0.1:1" },
		func(p *Payload) { p.VaultID = strings.Repeat("z", 24) },
		func(p *Payload) { p.DeviceID = strings.Repeat("y", 24) },
		func(p *Payload) { p.Fingerprint = "0000000000000000" },
		func(p *Payload) { p.CreatedAt = "2020-01-01T00:00:00Z" },
	} {
		tampered := decoded
		mutate(&tampered)
		encoded, err := EncodePayload(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lab.Import(encoded); statusOf(err) != http.StatusBadRequest {
			t.Fatalf("accepted substituted payload: %#v, %v", tampered, err)
		}
		if lab.State().Phase != PhaseRequested {
			t.Fatal("rejection changed state")
		}
	}
	if _, err := lab.Import(requested.PairingPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := lab.Approve("0000000000000000"); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("mismatch: %v", err)
	}
	approved, err := lab.Approve(strings.ReplaceAll(requested.Fingerprint, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Phase != PhaseApproved {
		t.Fatalf("phase %s", approved.Phase)
	}
	accepted, err := lab.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Phase != PhaseAccepted || !accepted.SameVaultKey {
		t.Fatalf("not accepted: %#v", accepted)
	}
	if _, err := lab.Accept(); statusOf(err) != http.StatusConflict {
		t.Fatalf("replayed accept: %v", err)
	}
}

func TestStateAndPageDoNotExposeKeyMaterial(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	state, err := lab.Request("privacy")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	page := []byte(indexHTML)
	for name, secret := range map[string]string{
		"vault key":             secure.Encode(lab.vaultKey),
		"approved signing key":  lab.approvedKeys.Secrets.SigningPrivate,
		"approved wrapping key": lab.approvedKeys.Secrets.WrappingPrivate,
		"new signing key":       lab.newKeys.Secrets.SigningPrivate,
		"new wrapping key":      lab.newKeys.Secrets.WrappingPrivate,
	} {
		if secret == "" {
			t.Fatalf("empty fixture %s", name)
		}
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(page, []byte(secret)) {
			t.Fatalf("%s exposed", name)
		}
	}
}

func TestLabCancelRejectAndFailedCancellationConfirmation(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		lab, err := NewLab()
		if err != nil {
			t.Fatal(err)
		}
		defer lab.Close()
		requested, err := lab.Request("cancel")
		if err != nil {
			t.Fatal(err)
		}
		cancelled, err := lab.Cancel()
		if err != nil || cancelled.Phase != PhaseCancelled ||
			cancelled.InvitationState != protocol.InvitationCancelled {
			t.Fatalf("cancelled state = %#v, %v", cancelled, err)
		}
		if _, err := lab.Import(requested.PairingPayload); statusOf(err) != http.StatusConflict {
			t.Fatalf("terminal import = %v", err)
		}
		reset, err := lab.Reset()
		if err != nil || reset.Phase != PhaseIdle {
			t.Fatalf("reset = %#v, %v", reset, err)
		}
	})
	t.Run("reject", func(t *testing.T) {
		lab, err := NewLab()
		if err != nil {
			t.Fatal(err)
		}
		defer lab.Close()
		requested, _ := lab.Request("reject")
		if _, err := lab.Import(requested.PairingPayload); err != nil {
			t.Fatal(err)
		}
		rejected, err := lab.Reject()
		if err != nil || rejected.Phase != PhaseRejected ||
			rejected.InvitationState != protocol.InvitationRejected {
			t.Fatalf("rejected state = %#v, %v", rejected, err)
		}
	})
	t.Run("failed cancellation is not claimed", func(t *testing.T) {
		lab, err := NewLab()
		if err != nil {
			t.Fatal(err)
		}
		defer lab.Close()
		requested, _ := lab.Request("approval wins")
		envelope, err := secure.WrapVaultKey(lab.vaultKey, lab.pending.Device.WrappingPublic,
			lab.vaultID, lab.pending.Device.ID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = lab.approvedAPI.ApproveInvitation(lab.pending.Device.ID,
			protocol.InvitationApproval{Version: lab.pending.Version,
				DeviceID: lab.pending.Device.ID, Fingerprint: lab.pending.Device.Fingerprint,
				Envelope: envelope})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lab.Cancel(); err == nil {
			t.Fatal("cancellation reported success after approval committed")
		}
		state := lab.State()
		if state.Phase != PhaseApproved || state.InvitationState != protocol.InvitationApproved ||
			state.PairingPayload != requested.PairingPayload {
			t.Fatalf("failed cancellation state = %#v", state)
		}
	})
	if !strings.Contains(indexHTML, "Authoritative expiry") ||
		!strings.Contains(indexHTML, "Attempts remaining") ||
		!strings.Contains(indexHTML, "/api/cancel") ||
		!strings.Contains(indexHTML, "/api/reject") {
		t.Fatal("invitation controls or server-authoritative status missing from lab page")
	}
}

func TestConcurrentApprovalHasOneWinner(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	keys, err := secure.NewDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.NewAPI(lab.serverURL).CreateInvitation(lab.vaultID, protocol.InvitationRequest{
		Version: protocol.InvitationProtocolVersion, Name: "race",
		SigningPublic: keys.SigningPublic, WrappingPublic: keys.WrappingPublic})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secure.WrapVaultKey(lab.vaultKey, keys.WrappingPublic, lab.vaultID, status.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := lab.approvedAPI.ApproveInvitation(status.Device.ID, protocol.InvitationApproval{
				Version: status.Version, DeviceID: status.Device.ID,
				Fingerprint: status.Device.Fingerprint, Envelope: envelope,
			})
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("approval winners = %d, want 1", wins)
	}
	devices, err := lab.approvedAPI.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("active devices = %d, want 2", len(devices))
	}
}

func TestConcurrentEnrollmentIdentitiesAndEvents(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	const count = 100
	ids := make(chan string, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, err := secure.NewDeviceKeys()
			if err != nil {
				errs <- err
				return
			}
			status, err := client.NewAPI(lab.serverURL).CreateInvitation(lab.vaultID,
				protocol.InvitationRequest{Version: protocol.InvitationProtocolVersion,
					Name: "concurrent", SigningPublic: keys.SigningPublic,
					WrappingPublic: keys.WrappingPublic})
			if err != nil {
				errs <- err
				return
			}
			ids <- status.Device.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	unique := map[string]bool{}
	for id := range ids {
		unique[id] = true
	}
	if len(unique) != count {
		t.Fatalf("unique IDs = %d, want %d", len(unique), count)
	}
	invitations, err := lab.approvedAPI.ListInvitations()
	if err != nil {
		t.Fatal(err)
	}
	if len(invitations) != count {
		t.Fatalf("invitations = %d, want %d", len(invitations), count)
	}
	events, err := lab.approvedAPI.ListAccessEvents(500, "")
	if err != nil {
		t.Fatal(err)
	}
	succeeded := 0
	for _, event := range events.Events {
		if event.Operation == "invitation_creation" && event.Outcome == "succeeded" {
			succeeded++
		}
	}
	if succeeded != count {
		t.Fatalf("persisted invitation events = %d, want %d", succeeded, count)
	}
}

func TestOneHundredResetPairAcceptCycles(t *testing.T) {
	if testing.Short() {
		t.Skip("stress cycle")
	}
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	for i := 0; i < 100; i++ {
		s, err := lab.Request("cycle")
		if err != nil {
			t.Fatalf("cycle %d request: %v", i, err)
		}
		if _, err := lab.Import(s.PairingPayload); err != nil {
			t.Fatalf("cycle %d import: %v", i, err)
		}
		if _, err := lab.Approve(strings.ReplaceAll(s.Fingerprint, " ", "")); err != nil {
			t.Fatalf("cycle %d approve: %v", i, err)
		}
		accepted, err := lab.Accept()
		if err != nil || !accepted.SameVaultKey {
			t.Fatalf("cycle %d accept: %v", i, err)
		}
		reset, err := lab.Reset()
		if err != nil || reset.Phase != PhaseIdle || reset.PairingPayload != "" || reset.SameVaultKey {
			t.Fatalf("cycle %d leaked state: %#v, %v", i, reset, err)
		}
	}
}

func TestControllerSecurityHeadersAndGuards(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	c, err := NewController(lab, "127.0.0.1:9444")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9444/", nil)
	request.Host = "attacker.example"
	response := httptest.NewRecorder()
	c.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("host status %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9444/", nil)
	response = httptest.NewRecorder()
	c.ServeHTTP(response, request)
	if response.Code != 200 || !strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing CSP")
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS enabled")
	}
	cookie := response.Result().Cookies()[0]
	post := func(origin, csrf, contentType string, body []byte) int {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9444/api/request", bytes.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		return w.Code
	}
	if got := post("http://evil.example", c.csrf, "application/json", []byte(`{"name":"x"}`)); got != 403 {
		t.Fatalf("foreign origin = %d", got)
	}
	if got := post(c.origin, "wrong", "application/json", []byte(`{"name":"x"}`)); got != 403 {
		t.Fatalf("csrf = %d", got)
	}
	if got := post(c.origin, c.csrf, "text/plain", []byte(`{"name":"x"}`)); got != 415 {
		t.Fatalf("content type = %d", got)
	}
	oversized := append([]byte(`{"name":"`), bytes.Repeat([]byte("x"), controllerBodyLimit)...)
	if got := post(c.origin, c.csrf, "application/json", oversized); got != 400 {
		t.Fatalf("oversize = %d", got)
	}
}

func TestHTTPWalkthrough(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	ui, err := StartUI(lab)
	if err != nil {
		t.Fatal(err)
	}
	defer ui.Close()
	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar}
	index, err := httpClient.Get(ui.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(index.Body)
	index.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	marker := `const csrf="`
	start := strings.Index(string(page), marker)
	if start < 0 {
		t.Fatal("CSRF token missing from page")
	}
	start += len(marker)
	end := strings.Index(string(page[start:]), `"`)
	if end < 0 {
		t.Fatal("CSRF token is not terminated")
	}
	csrf := string(page[start : start+end])
	post := func(path string, input any, output *State) int {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, ui.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", ui.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		response, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if output != nil && response.StatusCode == 200 {
			if err := json.NewDecoder(response.Body).Decode(output); err != nil {
				t.Fatal(err)
			}
		} else {
			_, _ = io.Copy(io.Discard, response.Body)
		}
		return response.StatusCode
	}
	stateResponse, err := httpClient.Get(ui.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	if stateResponse.StatusCode != 200 {
		t.Fatalf("state status %d", stateResponse.StatusCode)
	}
	stateResponse.Body.Close()
	var state State
	if got := post("/api/request", map[string]string{"name": "Browser lab phone"}, &state); got != 200 {
		t.Fatalf("request status %d", got)
	}
	if state.Phase != PhaseRequested || state.PairingPayload == "" {
		t.Fatalf("request state %#v", state)
	}
	qr, err := httpClient.Get(ui.URL + "/api/qr")
	if err != nil {
		t.Fatal(err)
	}
	if qr.StatusCode != 200 || qr.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("QR response %d %q", qr.StatusCode, qr.Header.Get("Content-Type"))
	}
	qr.Body.Close()
	if got := post("/api/import", map[string]string{"payload": state.PairingPayload}, &state); got != 200 || state.Phase != PhaseImported {
		t.Fatalf("import status %d, state %#v", got, state)
	}
	if got := post("/api/approve", map[string]string{"fingerprint": "0000000000000000"}, nil); got != 400 {
		t.Fatalf("mismatch status %d", got)
	}
	if got := post("/api/approve", map[string]string{"fingerprint": strings.ReplaceAll(state.Fingerprint, " ", "")}, &state); got != 200 || state.Phase != PhaseApproved {
		t.Fatalf("approve status %d, state %#v", got, state)
	}
	if got := post("/api/accept", struct{}{}, &state); got != 200 || state.Phase != PhaseAccepted || !state.SameVaultKey {
		t.Fatalf("accept status %d, state %#v", got, state)
	}
	if got := post("/api/accept", struct{}{}, nil); got != 409 {
		t.Fatalf("replay status %d", got)
	}
	if got := post("/api/reset", struct{}{}, &state); got != 200 || state.Phase != PhaseIdle {
		t.Fatalf("reset status %d, state %#v", got, state)
	}
}

func TestNewControllerRejectsNonLoopback(t *testing.T) {
	lab, err := NewLab()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	if _, err := NewController(lab, "0.0.0.0:8080"); err == nil {
		t.Fatal("accepted wildcard bind")
	}
}

func statusOf(err error) int {
	var target *StatusError
	if err != nil && errorsAs(err, &target) {
		return target.Status
	}
	return 0
}

// Kept tiny so fuzzing state-machine input does not require starting services.
func errorsAs(err error, target **StatusError) bool {
	if value, ok := err.(*StatusError); ok {
		*target = value
		return true
	}
	return false
}

func FuzzControllerJSON(f *testing.F) {
	f.Add([]byte(`{"name":"phone"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > controllerBodyLimit {
			raw = raw[:controllerBodyLimit]
		}
		request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
		response := httptest.NewRecorder()
		var destination struct {
			Name string `json:"name"`
		}
		_ = decodeControllerJSON(response, request, &destination)
		_, _ = json.Marshal(destination)
	})
}

func FuzzStateMachineActions(f *testing.F) {
	f.Add("idle", "request")
	f.Add("accepted", "approve")
	f.Fuzz(func(t *testing.T, phase, action string) {
		if len(phase) > 32 || len(action) > 32 {
			return
		}
		_ = actionAllowed(Phase(phase), action)
	})
}
