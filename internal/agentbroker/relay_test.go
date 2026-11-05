package agentbroker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRelay struct {
	mu        sync.Mutex
	peers     []RelayPeer
	value     []byte
	waitErr   error
	beginErr  error
	began     []string
	cancelled int
	block     chan struct{}
}

type fakeRelaySession struct{ r *fakeRelay }

func (r *fakeRelay) Peers(context.Context) ([]RelayPeer, error) { return r.peers, nil }
func (r *fakeRelay) Begin(_ context.Context, sender RelayPeer, name, reason string) (RelaySession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.beginErr != nil {
		return nil, r.beginErr
	}
	r.began = append(r.began, sender.ID+"/"+name)
	return fakeRelaySession{r}, nil
}
func (s fakeRelaySession) SAS() string        { return "123 456" }
func (s fakeRelaySession) Expires() time.Time { return time.Now().Add(5 * time.Minute) }
func (s fakeRelaySession) Cancel()            { s.r.mu.Lock(); s.r.cancelled++; s.r.mu.Unlock() }
func (s fakeRelaySession) Wait(ctx context.Context) ([]byte, error) {
	if s.r.block != nil {
		select {
		case <-s.r.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.r.waitErr != nil {
		return nil, s.r.waitErr
	}
	return append([]byte(nil), s.r.value...), nil
}

type fakeRelayPrompter struct {
	fakePrompter
	choose   int
	chooseOK bool
	confirm  bool
	shown    []RelayPrompt
	asked    []RelayPrompt
}

func (p *fakeRelayPrompter) ChooseRelaySender(_ context.Context, r RelayPrompt, peers []RelayPeer) (int, bool, error) {
	return p.choose, p.chooseOK, nil
}
func (p *fakeRelayPrompter) ShowRelayCode(r RelayPrompt) { p.shown = append(p.shown, r) }
func (p *fakeRelayPrompter) ConfirmRelay(_ context.Context, r RelayPrompt) (bool, error) {
	p.asked = append(p.asked, r)
	return p.confirm, nil
}

func newRelayBroker(t *testing.T, vault Vault, relay Relay, p Prompter) *Broker {
	t.Helper()
	b, err := New(Options{Vault: vault, Relay: relay, Prompter: p, Runner: ExecRunner{}, Path: "/usr/bin:/bin"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func relayReq(name string) Request {
	return Request{V: ProtocolVersion, Op: OpRelayRequest, Name: name, Reason: "deploy"}
}

func TestRelayRequestStoresOnlyAfterOwnerConfirmsAndReturnsNoValue(t *testing.T) {
	value := randomValue(t)
	vault := &fakeVault{values: map[string]string{}}
	relay := &fakeRelay{peers: []RelayPeer{{ID: "phone-id", Name: "phone", Fingerprint: "00112233aabbccdd"}}, value: []byte(value)}
	p := &fakeRelayPrompter{chooseOK: true, confirm: true}
	resp := newRelayBroker(t, vault, relay, p).Handle(context.Background(), relayReq("DEPLOY_TOKEN"))
	noValue(t, value, resp)
	if !resp.OK || resp.State != StateStored || vault.values["DEPLOY_TOKEN"] != value {
		t.Fatalf("resp %+v", resp)
	}
	if len(p.shown) != 1 || p.shown[0].SAS != "123 456" || p.shown[0].Sender.ID != "phone-id" || len(p.asked) != 1 {
		t.Fatalf("owner was not shown the code and asked: %+v %+v", p.shown, p.asked)
	}
	if len(relay.began) != 1 || relay.began[0] != "phone-id/DEPLOY_TOKEN" {
		t.Fatalf("began %v", relay.began)
	}
	for _, note := range p.notes {
		if strings.Contains(note, value) {
			t.Fatal("value in owner notification")
		}
	}
}

func TestRelayRequestOutcomesAreValueFree(t *testing.T) {
	value := randomValue(t)
	peers := []RelayPeer{{ID: "phone-id", Name: "phone", Fingerprint: "00112233aabbccdd"}}
	cases := []struct {
		name    string
		relay   *fakeRelay
		p       *fakeRelayPrompter
		state   string
		code    string
		cancels int
	}{
		{"owner declines device choice", &fakeRelay{peers: peers, value: []byte(value)}, &fakeRelayPrompter{chooseOK: false, confirm: true}, StateDenied, "", 0},
		{"owner declines storing", &fakeRelay{peers: peers, value: []byte(value)}, &fakeRelayPrompter{chooseOK: true}, StateDenied, "", 0},
		{"expired", &fakeRelay{peers: peers, waitErr: ErrRelayExpired}, &fakeRelayPrompter{chooseOK: true, confirm: true}, StateExpired, "", 0},
		{"verification failed", &fakeRelay{peers: peers, waitErr: errors.New("RELAY_AUTHENTICATION_FAILED " + value)}, &fakeRelayPrompter{chooseOK: true, confirm: true}, StateDenied, "", 1},
		{"no other device", &fakeRelay{}, &fakeRelayPrompter{chooseOK: true, confirm: true}, StateDenied, "", 0},
		{"short value", &fakeRelay{peers: peers, value: []byte("short")}, &fakeRelayPrompter{chooseOK: true, confirm: true}, StateDenied, "", 0},
		{"out-of-range choice", &fakeRelay{peers: peers, value: []byte(value)}, &fakeRelayPrompter{choose: 3, chooseOK: true, confirm: true}, StateDenied, "", 0},
		{"create failed", &fakeRelay{peers: peers, beginErr: errors.New("server returned 429 " + value)}, &fakeRelayPrompter{chooseOK: true, confirm: true}, "", CodeRelayFailed, 0},
	}
	for _, c := range cases {
		vault := &fakeVault{values: map[string]string{}}
		resp := newRelayBroker(t, vault, c.relay, c.p).Handle(context.Background(), relayReq("DEPLOY_TOKEN"))
		noValue(t, value, resp)
		for _, note := range c.p.notes {
			if strings.Contains(note, value) {
				t.Fatalf("%s: value in owner notification", c.name)
			}
		}
		if resp.State != c.state || resp.Code != c.code || vault.stored != 0 || c.relay.cancelled != c.cancels {
			t.Fatalf("%s: resp %+v stored=%d cancelled=%d", c.name, resp, vault.stored, c.relay.cancelled)
		}
	}
}

func TestRelayRequestValidationAndAvailability(t *testing.T) {
	vault := &fakeVault{values: map[string]string{}}
	relay := &fakeRelay{peers: []RelayPeer{{ID: "p"}}}
	p := &fakeRelayPrompter{chooseOK: true, confirm: true}
	b := newRelayBroker(t, vault, relay, p)
	for _, req := range []Request{
		relayReq("bad-name"),
		{V: ProtocolVersion, Op: OpRelayRequest, Name: "OK", Reason: strings.Repeat("r", Limits.ReasonBytes+1)},
		{V: ProtocolVersion, Op: OpRelayRequest, Name: "OK", Argv: []string{"x"}},
		{V: ProtocolVersion, Op: OpRelayRequest, Name: "OK", Reason: "\xff"},
	} {
		if resp := b.Handle(context.Background(), req); resp.Code != CodeInvalidRequest {
			t.Fatalf("accepted %+v: %+v", req, resp)
		}
	}
	if resp := newRelayBroker(t, vault, nil, p).Handle(context.Background(), relayReq("OK")); resp.Code != CodeRelayDisabled {
		t.Fatalf("relay without a relay backend: %+v", resp)
	}
	// A prompter without the relay owner channel cannot be used.
	if resp := newRelayBroker(t, vault, relay, &fakePrompter{}).Handle(context.Background(), relayReq("OK")); resp.Code != CodeRelayDisabled {
		t.Fatalf("relay without a relay prompter: %+v", resp)
	}
}

func TestRelayRequestCancelledByAgentWithdrawsRequest(t *testing.T) {
	value := randomValue(t)
	vault := &fakeVault{values: map[string]string{}}
	relay := &fakeRelay{peers: []RelayPeer{{ID: "p"}}, value: []byte(value), block: make(chan struct{})}
	p := &fakeRelayPrompter{chooseOK: true, confirm: true}
	b := newRelayBroker(t, vault, relay, p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Response)
	go func() { done <- b.Handle(ctx, relayReq("OK_NAME")) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	resp := <-done
	if resp.State != StateDenied || vault.stored != 0 || relay.cancelled != 1 {
		t.Fatalf("resp %+v stored=%d cancelled=%d", resp, vault.stored, relay.cancelled)
	}
}

func TestTerminalRelayPromptsSanitizeDeviceNamesAndRequireExplicitAnswers(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	var out bytes.Buffer
	p := &TerminalPrompter{In: r, Out: &out}
	peers := []RelayPeer{{ID: "a", Name: "phone\x1b]0;evil\x07", Fingerprint: "0011"}, {ID: "b", Name: "tablet", Fingerprint: "2233"}}
	prompt := RelayPrompt{Name: "API_KEY", Reason: "need \x1b[31mred", Replaces: true}
	_, _ = w.Write([]byte("2\n"))
	if i, ok, err := p.ChooseRelaySender(context.Background(), prompt, peers); err != nil || !ok || i != 1 {
		t.Fatalf("choice %d %v %v", i, ok, err)
	}
	_, _ = w.Write([]byte("\n"))
	if _, ok, _ := p.ChooseRelaySender(context.Background(), prompt, peers); ok {
		t.Fatal("empty answer chose a device")
	}
	_, _ = w.Write([]byte("9\n"))
	if _, ok, _ := p.ChooseRelaySender(context.Background(), prompt, peers); ok {
		t.Fatal("out-of-range answer chose a device")
	}
	prompt.Sender, prompt.SAS, prompt.Expires = peers[0], "123 456", time.Now()
	p.ShowRelayCode(prompt)
	_, _ = w.Write([]byte("\n"))
	if ok, _ := p.ConfirmRelay(context.Background(), prompt); ok {
		t.Fatal("empty answer stored")
	}
	_, _ = w.Write([]byte("yes\n"))
	if ok, _ := p.ConfirmRelay(context.Background(), prompt); !ok {
		t.Fatal("yes not accepted")
	}
	text := out.String()
	if strings.Contains(text, "\x1b]0;") || strings.Contains(text, "\x1b[31m") || !strings.Contains(text, "123 456") ||
		!strings.Contains(text, "REPLACE") {
		t.Fatalf("prompt output:\n%q", text)
	}
}
