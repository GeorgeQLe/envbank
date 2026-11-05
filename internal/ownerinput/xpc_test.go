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

// entryReply builds a reply to an entry message.
func entryReply(m map[string]string, outcome string, value []byte, extra ...xpcField) xpcRawReply {
	r := xpcRawReply{Fields: []xpcField{{'S', "v", XPCVersion}, {'S', "nonce", m["nonce"]}, {'S', "outcome", outcome},
		{'S', "service_cdhash", strings.Repeat("ab", 20)}}}
	if value != nil {
		r.Fields = append(r.Fields, xpcField{'X', "value", ""})
		r.Value, r.HasValue = append([]byte(nil), value...), true
	}
	r.Fields = append(r.Fields, extra...)
	return r
}

// Entry goes only over the paired agent-channel connection (never a fresh
// one), only while it holds a confirmed pairing, and every reply is checked
// strictly.
func TestEntryUsesOnlyThePairedConnectionAndChecksReplies(t *testing.T) {
	secret := []byte("owner typed passphrase")
	mode := "ok"
	conn := newFakeConn()
	conn.entry = func(m map[string]string) xpcRawReply {
		switch mode {
		case "ok":
			return entryReply(m, "entered", secret)
		case "nonce":
			m["nonce"] = strings.Repeat("0", 32)
			return entryReply(m, "entered", secret)
		case "version":
			r := entryReply(m, "entered", secret)
			r.Fields[0].Value = "other"
			return r
		case "unknown":
			return entryReply(m, "cancelled", nil, xpcField{'S', "route_id", "1"})
		case "value-on-decline":
			return entryReply(m, "declined", secret)
		case "value-not-flagged":
			r := entryReply(m, "entered", nil)
			r.Value, r.HasValue = secret, true
			return r
		case "short":
			return entryReply(m, "entered", []byte("short"))
		case "other-build":
			r := entryReply(m, "entered", secret)
			r.Fields[3].Value = strings.Repeat("cd", 20)
			return r
		case "cancelled":
			return entryReply(m, "cancelled", nil)
		}
		return entryReply(m, "bogus", nil)
	}
	var dials int
	old := agentDial
	agentDial = func(string, string) (agentConn, error) { dials++; return conn, nil }
	t.Cleanup(func() { agentDial = old })
	p := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	ch := &AgentChannel{Provider: p, Confirm: func(Identity, string) bool { return true }}
	if _, _, err := ch.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil || err.Error() != CodeNotPaired || len(conn.entries) != 0 {
		t.Fatalf("entry before pairing: %v", err)
	}
	base, _ := p.Requirement()
	for _, want := range []string{`leaf[subject.OU] = "NC56VXK48K"`, `identifier "dev.georgele.chromux.owner-input"`, "1.2.840.113635.100.6.1.13", `get-task-allow"] exists)`} {
		if !strings.Contains(base, want) {
			t.Fatalf("requirement missing %q: %s", want, base)
		}
	}
	if err := ch.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pinned, _ := p.Requirement(); !strings.HasSuffix(pinned, ` and cdhash H"`+strings.Repeat("ab", 20)+`"`) {
		t.Fatalf("cdhash not pinned into the requirement: %s", pinned)
	}
	var code string
	v, outcome, err := ch.Entry(context.Background(), PurposeNewVault, "t\u202e", "d", "", 12, 1024, true, func(c string) { code = c })
	if err != nil || outcome != "entered" || string(v) != string(secret) || dials != 1 || len(code) != 9 {
		t.Fatalf("entry: %v %q dials=%d", err, outcome, dials)
	}
	sent := map[string]xpcField{}
	for _, f := range conn.entries[0] {
		sent[f.Key] = f
	}
	if sent["kind"].Value != "entry" || sent["min_bytes"] != (xpcField{'I', "min_bytes", "12"}) || sent["confirm"] != (xpcField{'B', "confirm", "1"}) || strings.ContainsRune(sent["title"].Value, '\u202e') {
		t.Fatalf("entry message %+v", sent)
	}
	for _, m := range []string{"nonce", "version", "unknown", "value-on-decline", "value-not-flagged", "short", "other-build", "bogus"} {
		mode = m
		if v, _, err := ch.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil || v != nil {
			t.Fatalf("%s accepted", m)
		}
	}
	mode = "cancelled"
	if v, outcome, err := ch.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err != nil || outcome != "cancelled" || v != nil {
		t.Fatal("cancel not reported as cancel")
	}
	// A pairing lost (service restart) or a closed connection: fail fast.
	ch.setConn(conn, false)
	n := len(conn.entries)
	if _, _, err := ch.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil || len(conn.entries) != n {
		t.Fatal("entry sent on a connection without a confirmed pairing")
	}
	ch.setConn(nil, false)
	if _, _, err := ch.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil || dials != 1 {
		t.Fatal("entry without a connection, or a fresh connection dialled")
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

func (n nonceSwap) Request(f []xpcField, d time.Duration) (xpcRawReply, error) {
	r, err := n.fakeConn.Request(f, d)
	for i := range r.Fields {
		if r.Fields[i].Key == "nonce" {
			r.Fields[i].Value = strings.Repeat("0", 32)
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
