package agentbroker

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Redactor replaces every injected value, and the forms a program is most
// likely to print it in, before output is returned to an agent. Matching is
// span-based over the ORIGINAL output, so overlapping secrets cannot leave
// fragments. It cannot catch values a program transforms in other ways
// (reversed, encrypted, hashed, Unicode-renormalized, sent over the network);
// the approval prompt documents that residual risk.
type Redactor struct {
	needles []needle
}

type needle struct {
	text  []byte
	label string
}

// minNeedle avoids replacing short fragments that collide with ordinary output.
const minNeedle = 8

// NewRedactor builds needles for each named value.
func NewRedactor(values map[string]string) *Redactor {
	seen := map[string]bool{}
	r := &Redactor{}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, variant := range variants(values[name]) {
			if len(variant) < minNeedle || seen[variant] {
				continue
			}
			seen[variant] = true
			r.needles = append(r.needles, needle{text: []byte(variant), label: "[REDACTED:" + name + "]"})
		}
	}
	sort.SliceStable(r.needles, func(i, j int) bool { return len(r.needles[i].text) > len(r.needles[j].text) })
	return r
}

func encodings(value string) []string {
	raw := []byte(value)
	quoted, _ := json.Marshal(value)
	return []string{
		value,
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
		hex.EncodeToString(raw),
		strings.ToUpper(hex.EncodeToString(raw)),
		url.QueryEscape(value),
		url.PathEscape(value),
		strings.Trim(string(quoted), `"`),
	}
}

func variants(value string) []string {
	forms := []string{value}
	if trimmed := strings.TrimSpace(value); trimmed != value {
		forms = append(forms, trimmed)
	}
	// Multi-line values: either line ending, and each line on its own (programs
	// often print a PEM or JSON blob line by line).
	if strings.ContainsAny(value, "\r\n") {
		lf := strings.ReplaceAll(value, "\r\n", "\n")
		forms = append(forms, lf, strings.ReplaceAll(lf, "\n", "\r\n"))
		for _, line := range strings.Split(lf, "\n") {
			forms = append(forms, strings.TrimRight(line, "\r"), strings.TrimSpace(line))
		}
	}
	var out []string
	for _, f := range forms {
		out = append(out, encodings(f)...)
	}
	return out
}

// Redact returns the redacted output and the number of replaced spans. When
// `cut` is true the buffer was truncated at capture, so a trailing fragment
// (of any length) that begins a needle is also removed.
func (r *Redactor) Redact(out []byte, cut bool) ([]byte, int) {
	type span struct {
		start, end int
		label      string
	}
	var spans []span
	for _, n := range r.needles {
		for from := 0; from < len(out); {
			i := bytes.Index(out[from:], n.text)
			if i < 0 {
				break
			}
			spans = append(spans, span{from + i, from + i + len(n.text), n.label})
			from += i + 1 // overlapping occurrences too
		}
	}
	if cut {
		for _, n := range r.needles {
			for k := min(len(n.text)-1, len(out)); k >= 1; k-- {
				if bytes.Equal(out[len(out)-k:], n.text[:k]) {
					spans = append(spans, span{len(out) - k, len(out), n.label})
					break
				}
			}
		}
	}
	if len(spans) == 0 {
		return out, 0
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b bytes.Buffer
	pos, count := 0, 0
	for i := 0; i < len(spans); {
		start, end, label := spans[i].start, spans[i].end, spans[i].label
		j := i + 1
		for ; j < len(spans) && spans[j].start < end; j++ { // merge overlaps
			end = max(end, spans[j].end)
		}
		b.Write(out[pos:start])
		b.WriteString(label)
		pos, count, i = end, count+1, j
	}
	b.Write(out[pos:])
	return b.Bytes(), count
}
