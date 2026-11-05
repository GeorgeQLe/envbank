package ownerinput

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeorgeQLe/envbank/internal/authz"
)

func TestRealXPCToMissingServiceFailsFastAndClosed(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	p := &XPCProvider{Service: "dev.georgele.envbank.test.absent." + strings.Repeat("x", 4), TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	ch := &AgentChannel{Provider: p, Confirm: func(Identity, string) bool { t.Fatal("owner asked to confirm with no service"); return false }}
	start := time.Now()
	err := ch.Open(context.Background())
	if err == nil || p.Pinned() || time.Since(start) > 20*time.Second {
		t.Fatalf("missing service: %v after %v", err, time.Since(start))
	}
}

// openWith pairs a fresh provider over conn through the channel's Open.
func openWith(t *testing.T, conn *fakeConn, confirm func(Identity, string) bool) (*XPCProvider, *AgentChannel, error) {
	t.Helper()
	old := agentDial
	agentDial = func(string, string) (agentConn, error) { return conn, nil }
	t.Cleanup(func() { agentDial = old })
	p := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	ch := &AgentChannel{Provider: p, Confirm: confirm}
	return p, ch, ch.Open(context.Background())
}

func fakeXPC(t *testing.T, handle func(req string, msg xpcMessage) xpcReply) *[]string {
	t.Helper()
	var reqs []string
	old := xpcSend
	xpcSend = func(_ string, req string, msg xpcMessage, _ time.Duration) (xpcReply, error) {
		reqs = append(reqs, req)
		return handle(req, msg), nil
	}
	t.Cleanup(func() { xpcSend = old })
	return &reqs
}

func TestXPCPairPinsCDHashIntoRequirementAndValidatesReplies(t *testing.T) {
	cd := strings.Repeat("ab", 20)
	secret := []byte("owner typed passphrase")
	mode := "ok"
	reqs := fakeXPC(t, func(req string, msg xpcMessage) xpcReply {
		r := xpcReply{Version: XPCVersion, Nonce: msg.strings["nonce"]}
		switch mode {
		case "ok":
			r.Outcome, r.Value, r.HasValue = "entered", append([]byte(nil), secret...), true
		case "nonce":
			r.Outcome, r.Nonce, r.Value, r.HasValue = "entered", strings.Repeat("0", 32), secret, true
		case "version":
			r.Version, r.Outcome = "other", "entered"
		case "unknown":
			r.Outcome, r.UnknownKeys = "cancelled", true
		case "value-on-decline":
			r.Outcome, r.Value, r.HasValue = "declined", secret, true
		case "short":
			r.Outcome, r.Value, r.HasValue = "entered", []byte("short"), true
		case "cancelled":
			r.Outcome = "cancelled"
		}
		return r
	})
	unpaired := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	if _, _, err := unpaired.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil {
		t.Fatal("entry before pairing")
	}
	base, _ := unpaired.Requirement()
	for _, want := range []string{`leaf[subject.OU] = "NC56VXK48K"`, `identifier "dev.georgele.chromux.owner-input"`, "1.2.840.113635.100.6.1.13", `get-task-allow"] exists)`} {
		if !strings.Contains(base, want) {
			t.Fatalf("requirement missing %q: %s", want, base)
		}
	}
	var shown string
	conn := newFakeConn()
	conn.cdhash = cd
	p, _, err := openWith(t, conn, func(id Identity, code string) bool { shown = code; return id.CDHash == cd })
	if err != nil || len(shown) != 6 || conn.pairings[0]["pairing_code"] != shown || conn.pairings[0]["kind"] != "pairing" {
		t.Fatal(err)
	}
	pinned, _ := p.Requirement()
	if !strings.HasSuffix(pinned, ` and cdhash H"`+cd+`"`) {
		t.Fatalf("cdhash not pinned into the requirement: %s", pinned)
	}
	v, outcome, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil)
	if err != nil || outcome != "entered" || string(v) != string(secret) || !strings.Contains((*reqs)[len(*reqs)-1], `cdhash H"`) {
		t.Fatalf("entry: %v %q", err, outcome)
	}
	for _, m := range []string{"nonce", "version", "unknown", "value-on-decline", "short"} {
		mode = m
		if v, _, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil || v != nil {
			t.Fatalf("%s accepted", m)
		}
	}
	mode = "cancelled"
	if v, outcome, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err != nil || outcome != "cancelled" || v != nil {
		t.Fatal("cancel not reported as cancel")
	}
}

// Pairing needs BOTH confirmations: the service's "confirmed" (the owner's
// Touch ID in Chromux) and the owner's Touch ID in the broker terminal, which
// is asked only after the service confirmed. Anything else pins nothing.
func TestXPCPairingNeedsHostConfirmationAndOwnerTouchID(t *testing.T) {
	for name, c := range map[string]struct {
		outcome, cd string
		extra       []xpcField
		confirm     bool
		askOwner    bool
	}{
		"displayed only": {outcome: "displayed", cd: strings.Repeat("ab", 20), confirm: true},
		"declined":       {outcome: "declined", cd: strings.Repeat("ab", 20), confirm: true},
		"bad hash":       {outcome: OutcomeConfirmed, cd: "zz", confirm: true},
		"owner no":       {outcome: OutcomeConfirmed, cd: strings.Repeat("ab", 20), confirm: false, askOwner: true},
		"value":          {outcome: OutcomeConfirmed, cd: strings.Repeat("ab", 20), extra: []xpcField{{'X', "value", ""}}, confirm: true},
		"unknown key":    {outcome: OutcomeConfirmed, cd: strings.Repeat("ab", 20), extra: []xpcField{{'S', "kind", "pairing"}}, confirm: true},
		"wrong type":     {outcome: OutcomeConfirmed, cd: strings.Repeat("ab", 20), extra: []xpcField{{'S', "provider", "x"}}, confirm: true},
	} {
		conn := newFakeConn()
		conn.pairOutcome, conn.cdhash, conn.extra = c.outcome, c.cd, c.extra
		asked := false
		p, _, err := openWith(t, conn, func(Identity, string) bool { asked = true; return c.confirm })
		if err == nil || p.Pinned() {
			t.Fatalf("%s: paired", name)
		}
		if asked != c.askOwner {
			t.Fatalf("%s: owner asked %v", name, asked)
		}
		if req, _ := p.Requirement(); strings.Contains(req, "cdhash") {
			t.Fatalf("%s: pinned anyway", name)
		}
		if conn.hellos != 0 || !conn.closed {
			t.Fatalf("%s: unpaired connection kept or registered", name)
		}
	}
	// A nonce mismatch is a protocol error.
	conn := newFakeConn()
	conn.extra = nil
	old := agentDial
	agentDial = func(string, string) (agentConn, error) { return nonceSwap{conn}, nil }
	defer func() { agentDial = old }()
	p := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	if err := (&AgentChannel{Provider: p, Confirm: func(Identity, string) bool { return true }}).Open(context.Background()); err == nil || p.Pinned() {
		t.Fatal("nonce mismatch paired")
	}
}

type nonceSwap struct{ *fakeConn }

func (n nonceSwap) Request(f []xpcField, d time.Duration) ([]xpcField, error) {
	r, err := n.fakeConn.Request(f, d)
	for i := range r {
		if r[i].Key == "nonce" {
			r[i].Value = strings.Repeat("0", 32)
		}
	}
	return r, err
}

// broker_hello goes only on the connection that completed a confirmed
// pairing, and every new connection pairs first. A different service build
// on a later pairing is refused.
func TestHelloOnlyAfterConfirmedPairingOnTheSameConnection(t *testing.T) {
	first, second, third := newFakeConn(), newFakeConn(), newFakeConn()
	third.cdhash = strings.Repeat("cd", 20)
	conns := []*fakeConn{first, second, third}
	var mu sync.Mutex
	n := 0
	dialled := func() int { mu.Lock(); defer mu.Unlock(); return n }
	old := agentDial
	agentDial = func(string, string) (agentConn, error) {
		mu.Lock()
		defer mu.Unlock()
		if n >= len(conns) {
			return nil, errors.New(CodeUnavailable)
		}
		n++
		return conns[n-1], nil
	}
	defer func() { agentDial = old }()
	p := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	ch := &AgentChannel{Provider: p, Handler: handlerFunc(func(context.Context, authz.Session, []byte) []byte { return []byte(`{"v":1,"ok":true}`) }),
		Confirm: func(Identity, string) bool { return true }}
	if err := ch.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first.hellos != 0 {
		t.Fatal("Open registered before Run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ch.Run(ctx) }()
	first.send(1, validFields())
	first.wait(t, 1)
	first.events <- agentEvent{Kind: evInvalid}
	second.send(2, validFields())
	second.wait(t, 2)
	second.events <- agentEvent{Kind: evInvalid}
	for deadline := time.Now().Add(10 * time.Second); dialled() < 3 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	for i, c := range []*fakeConn{first, second} {
		if seq := strings.Join(c.sequence(), ","); seq != "pair,hello" || c.helloUnpaired {
			t.Fatalf("connection %d: %s", i, seq)
		}
	}
	if seq := strings.Join(third.sequence(), ","); seq != "pair" || third.hellos != 0 {
		t.Fatalf("a different service build registered: %s", seq)
	}
}

// Pairings declined again and again stop the channel instead of prompting
// the owner forever.
func TestRepeatedPairingRefusalsStopTheChannel(t *testing.T) {
	var conns []*fakeConn
	old := agentDial
	agentDial = func(string, string) (agentConn, error) {
		c := newFakeConn()
		c.pairOutcome = "declined"
		conns = append(conns, c)
		return c, nil
	}
	defer func() { agentDial = old }()
	p := pinnedProvider()
	ch := &AgentChannel{Provider: p, Handler: handlerFunc(nil), Confirm: func(Identity, string) bool { return true }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := ch.Run(ctx); err == nil || err.Error() != CodeNotPaired || len(conns) != maxPairRefusals {
		t.Fatalf("run: %v after %d pairings", err, len(conns))
	}
	for _, c := range conns {
		if c.hellos != 0 {
			t.Fatal("hello on a declined pairing")
		}
	}
}
