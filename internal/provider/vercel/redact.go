package vercel

import "fmt"

// Never format a retained control credential through a diagnostic accidentally.
func (*Adapter) String() string { return "Vercel adapter [credential REDACTED]" }
func (*Adapter) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "Vercel adapter [credential REDACTED]")
}

// ValidSecretName is shared with planning so invalid/client-exposed bindings
// are refused before a private record is loaded, not only at the HTTP write.
func ValidSecretName(name string) bool { return validSecretName(name) }
