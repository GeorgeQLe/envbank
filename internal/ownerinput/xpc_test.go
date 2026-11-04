package ownerinput

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRealXPCToMissingServiceFailsFastAndClosed(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	p := &XPCProvider{Service: "dev.georgele.envbank.test.absent." + strings.Repeat("x", 4), TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	start := time.Now()
	err := p.Pair(context.Background(), func(Identity, string) bool { t.Fatal("owner asked to confirm with no service"); return false })
	if err == nil || time.Since(start) > 20*time.Second {
		t.Fatalf("missing service: %v after %v", err, time.Since(start))
	}
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
		if msg.strings["kind"] == "pairing" {
			r.Outcome, r.ServiceCDHash = "displayed", cd
			return r
		}
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
	p := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
	if _, _, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil {
		t.Fatal("entry before pairing")
	}
	base, _ := p.Requirement()
	for _, want := range []string{`leaf[subject.OU] = "NC56VXK48K"`, `identifier "dev.georgele.chromux.owner-input"`, "1.2.840.113635.100.6.1.13", `get-task-allow"] exists)`} {
		if !strings.Contains(base, want) {
			t.Fatalf("requirement missing %q: %s", want, base)
		}
	}
	var shown string
	if err := p.Pair(context.Background(), func(id Identity, code string) bool { shown = code; return id.CDHash == cd }); err != nil || len(shown) != 6 {
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

func TestXPCPairRefusesBadServiceHashOrOwnerNo(t *testing.T) {
	for name, c := range map[string]struct {
		cd      string
		confirm bool
	}{"bad-hash": {"zz", true}, "owner-no": {strings.Repeat("ab", 20), false}} {
		fakeXPC(t, func(_ string, msg xpcMessage) xpcReply {
			return xpcReply{Version: XPCVersion, Nonce: msg.strings["nonce"], Outcome: "displayed", ServiceCDHash: c.cd}
		})
		p := &XPCProvider{Service: BrokerServiceName, TeamID: "NC56VXK48K", Identifier: ServiceIdentifier}
		if err := p.Pair(context.Background(), func(Identity, string) bool { return c.confirm }); err == nil {
			t.Fatalf("%s: paired", name)
		}
		if req, _ := p.Requirement(); strings.Contains(req, "cdhash") {
			t.Fatalf("%s: pinned anyway", name)
		}
	}
}
