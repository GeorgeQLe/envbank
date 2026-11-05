//go:build darwin && cgo

package ownerinput

import (
	"encoding/json"
	"testing"
	"time"
)

// The C glue flattens top-level strings, integers and bools, renders
// dictionaries (with arrays, integers, bools and escaped strings) as JSON,
// and marks other types.
func TestCFlattenRecordsTypesAndRendersDictionaries(t *testing.T) {
	fields, overflow := flattenSelfTest()
	if overflow {
		t.Fatal("overflow")
	}
	got := map[string]xpcField{}
	for _, f := range fields {
		got[f.Key] = f
	}
	for key, want := range map[string]xpcField{
		"v": {'S', "v", XPCVersion}, "route_id": {'U', "route_id", "18446744073709551615"},
		"n": {'I', "n", "-5"}, "b": {'B', "b", "1"}, "blob": {'X', "blob", ""},
	} {
		if got[key] != want {
			t.Fatalf("%s: %+v", key, got[key])
		}
	}
	var req map[string]any
	if got["request"].Type != 'D' || json.Unmarshal([]byte(got["request"].Value), &req) != nil ||
		req["op"] != "run" || req["always"] != true || req["timeout_seconds"] != float64(30) || req["secrets"].([]any)[0] != "API_KEY" {
		t.Fatalf("request JSON: %+v", got["request"])
	}
	s, err := parseSession([]byte(got["session"].Value))
	if got["session"].Type != 'D' || err == nil {
		// The self-test label contains a newline: valid JSON, refused label.
		t.Fatalf("session: %+v %v %+v", got["session"], err, s)
	}
	var sess map[string]string
	if json.Unmarshal([]byte(got["session"].Value), &sess) != nil || sess["label"] != "Say \"hi\"\n" {
		t.Fatalf("string escaping: %q", got["session"].Value)
	}
	if _, _, _, _, ok := parseAgentRequest(agentEvent{Kind: evMessage, Fields: fields}); ok {
		t.Fatal("self-test message accepted")
	}
}

// The reply builder produces exactly the nested dictionary the instructions
// describe.
func TestCReplyBuilderNestsDictionariesAndArrays(t *testing.T) {
	f := agentReply(9, true, []byte(`{"v":1,"ok":true,"names":["A","B"],"grants":[{"secrets":[],"scope":"setup","expires_at":"2026-11-04T13:00:00Z"}],"exit_code":0}`))
	js := buildSelfTest(f)
	var got map[string]any
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatalf("%v: %s", err, js)
	}
	resp := got["response"].(map[string]any)
	g := resp["grants"].([]any)[0].(map[string]any)
	if len(got) != 3 || got["v"] != XPCVersion || got["route_id"] != float64(9) || resp["ok"] != true || len(resp["names"].([]any)) != 2 ||
		g["scope"] != "setup" || len(g["secrets"].([]any)) != 0 || resp["exit_code"] != float64(0) {
		t.Fatalf("built %s", js)
	}
}

// Dialling an absent service fails closed and quickly (no real service is
// contacted: the name is a test name nobody registers).
func TestRealAgentDialToMissingServiceFailsClosed(t *testing.T) {
	conn, err := dialAgentXPC("dev.georgele.envbank.test.absent.agent", `anchor apple generic and identifier "dev.georgele.envbank.test.absent.agent"`)
	if err != nil {
		return // refused up front: also closed
	}
	defer conn.Close()
	start := time.Now()
	outcome, err := conn.Hello(5 * time.Second)
	if err == nil && outcome == OutcomeRegistered {
		t.Fatal("registered with an absent service")
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("hello took %v", time.Since(start))
	}
	if ev := conn.Next(2 * time.Second); ev.Kind == evMessage {
		conn.Reply(ev.Msg, agentReply(0, false, refusal("X")))
		t.Fatal("message from an absent service")
	}
}
