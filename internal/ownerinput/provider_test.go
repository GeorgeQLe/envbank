package ownerinput

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeProvider struct {
	t      *testing.T
	sock   string
	answer func(req map[string]any) string // returns the raw response line
}

func startFake(t *testing.T, answer func(map[string]any) string) *fakeProvider {
	t.Helper()
	dir, _ := os.MkdirTemp("", "oip")
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeProvider{t: t, sock: filepath.Join(dir, "p.sock"), answer: answer}
	l, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadBytes('\n')
				var req map[string]any
				if json.Unmarshal(line, &req) != nil || req == nil {
					return // the client refused before sending (e.g. an unverified peer)
				}
				_, _ = c.Write([]byte(f.answer(req) + "\n"))
			}()
		}
	}()
	return f
}

func withIdentity(t *testing.T, id *Identity) {
	t.Helper()
	old := verifyPeer
	verifyPeer = func(*net.UnixConn, string) (Identity, error) { return *id, nil }
	t.Cleanup(func() { verifyPeer = old })
}

func resp(req map[string]any, outcome, value string, extra string) string {
	r := `{"v":"envbank.owner-input/v1","nonce":"` + req["nonce"].(string) + `","outcome":"` + outcome + `"`
	if value != "" {
		r += `,"value":"` + value + `"`
	}
	return r + extra + "}"
}

func TestPairPinsBuildAndEntryReturnsValueOnlyWhenEntered(t *testing.T) {
	id := &Identity{TeamID: "NC56VXK48K", Identifier: "party.gblock.chromux.v2.desktop", CDHash: strings.Repeat("ab", 20), HardenedRuntime: true}
	withIdentity(t, id)
	secret := "correct horse battery staple"
	var shownCode string
	f := startFake(t, func(req map[string]any) string {
		if c, ok := req["pairing_code"].(string); ok {
			shownCode = c
			return resp(req, "displayed", "", `,"provider":{"qualified":false}`)
		}
		return resp(req, "entered", base64.StdEncoding.EncodeToString([]byte(secret)), "")
	})
	p := &Provider{Socket: f.sock, TeamID: id.TeamID, Identifier: id.Identifier}
	if _, _, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil {
		t.Fatal("entry before pairing")
	}
	var confirmedCode string
	if err := p.Pair(context.Background(), func(got Identity, code string) bool { confirmedCode = code; return got.CDHash == id.CDHash }); err != nil {
		t.Fatal(err)
	}
	if confirmedCode == "" || confirmedCode != shownCode {
		t.Fatal("owner was not shown the code the provider displayed")
	}
	var code string
	v, outcome, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, func(c string) { code = c })
	if err != nil || outcome != "entered" || string(v) != secret || len(code) != 9 {
		t.Fatalf("entry: %q %v %q", outcome, err, code)
	}
	// A different build of the same team/identifier is refused for the rest of the session.
	id.CDHash = strings.Repeat("cd", 20)
	if _, _, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil); err == nil || err.Error() != CodePeerUnverified {
		t.Fatalf("other build accepted: %v", err)
	}
}

func TestMalformedOrMismatchedResponsesAreRefused(t *testing.T) {
	id := &Identity{TeamID: "NC56VXK48K", Identifier: "party.gblock.chromux.v2.desktop", CDHash: strings.Repeat("ab", 20), HardenedRuntime: true}
	withIdentity(t, id)
	value := base64.StdEncoding.EncodeToString([]byte("a value long enough"))
	for name, answer := range map[string]func(map[string]any) string{
		"wrong nonce": func(r map[string]any) string {
			r["nonce"] = strings.Repeat("0", 32)
			return resp(r, "entered", value, "")
		},
		"unknown field":     func(r map[string]any) string { return resp(r, "entered", value, `,"extra":1`) },
		"value on declined": func(r map[string]any) string { return resp(r, "declined", value, "") },
		"too short": func(r map[string]any) string {
			return resp(r, "entered", base64.StdEncoding.EncodeToString([]byte("short")), "")
		},
		"bad base64":      func(r map[string]any) string { return resp(r, "entered", "!!!", "") },
		"unknown outcome": func(r map[string]any) string { return resp(r, "maybe", "", "") },
		"wrong version": func(r map[string]any) string {
			return strings.Replace(resp(r, "entered", value, ""), "owner-input/v1", "owner-input/v9", 1)
		},
	} {
		{
			pairing := true
			f := startFake(t, func(r map[string]any) string {
				if _, ok := r["pairing_code"]; ok && pairing {
					return resp(r, "displayed", "", "")
				}
				return answer(r)
			})
			p := &Provider{Socket: f.sock, TeamID: id.TeamID, Identifier: id.Identifier}
			if err := p.Pair(context.Background(), func(Identity, string) bool { return true }); err != nil {
				t.Fatal(err)
			}
			pairing = false
			v, _, err := p.Entry(context.Background(), PurposeNewVault, "t", "d", "", 12, 1024, true, nil)
			if err == nil || v != nil {
				t.Fatalf("%s: accepted", name)
			}
			if strings.Contains(err.Error(), "a value long enough") {
				t.Fatalf("%s: value echoed in error", name)
			}
		}
	}
	// Unpinned or malformed identity config never dials.
	if _, _, err := (&Provider{Socket: "/nonexistent", TeamID: "x", Identifier: "y"}).dial(context.Background()); err == nil {
		t.Fatal("dialed without a valid pin")
	}
}

func TestDisplayTextIsStrippedOfControlAndBidi(t *testing.T) {
	got := clipRunes("ok\x1b[2J‮evil\nline", 300)
	if strings.ContainsAny(got, "\x1b‮\n") {
		t.Fatalf("%q", got)
	}
}
