package approval

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanStripsControlAndBidiAndBounds(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                    "plain",
		"a\x1b[2Jb":                "a?[2Jb",
		"evil\u202egnp.exe":        "evil?gnp.exe",
		"line1\nline2\r\n\tline3":  "line1 line2 line3",
		"   lead":                  "lead",
		"zero\u200bwidth":          "zero?width",
		"bad\xffutf8":              "bad?utf8",
		"sep\u2028arator":          "sep arator",
		"many        spaces  here": "many spaces here",
	} {
		if got := Clean(in, 80); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Clean(strings.Repeat("x", 100), 10); got != strings.Repeat("x", 10)+"…" {
		t.Fatalf("clip: %q", got)
	}
}

func TestReasonIsBoundedOnARuneBoundary(t *testing.T) {
	r := Reason("grant %s", strings.Repeat("é", 2*MaxReasonBytes))
	if len(r) > MaxReasonBytes+len("…") || !utf8.ValidString(r) || !strings.HasSuffix(r, "…") {
		t.Fatalf("unbounded or invalid reason (%d bytes)", len(r))
	}
	if got := Quote("a\x07b", 80); got != "“a?b”" {
		t.Fatalf("quote: %q", got)
	}
}

func TestOutcomeStrings(t *testing.T) {
	if Approved.String() != "approved" || Denied.String() != "denied" || Unavailable.String() != "unavailable" || Outcome(9).String() != "denied" {
		t.Fatal("outcome strings")
	}
}

// LocalAuth must never approve a cancelled request or an empty reason, and
// checking availability must not prompt (canEvaluatePolicy only).
func TestLocalAuthRefusesWithoutPrompting(t *testing.T) {
	l := LocalAuth{}
	_ = l.Available()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l.Approve(ctx, "approve something") == Approved {
		t.Fatal("cancelled request approved")
	}
	if l.Approve(context.Background(), "") == Approved {
		t.Fatal("empty reason approved")
	}
}
