#!/bin/sh
# check-sign-target.sh BINARY
#
# Signing guard: run on every binary before it is code signed. It fails
# (non-zero) unless BINARY is a Go binary whose build information shows no
# envbank_testapprover build tag. A test-approver build answers approvals
# from a file, so it must never carry a production (or any) signature.
#
# GO may name the go command (default: go).
set -eu

fail() {
	echo "check-sign-target: REFUSED: $*" >&2
	exit 1
}

[ "$#" -eq 1 ] || fail "usage: check-sign-target.sh BINARY"
binary=$1
[ -f "$binary" ] || fail "$binary is not a file"

# Fail closed: no readable build information means nothing is proven.
info=$("${GO:-go}" version -m "$binary" 2>/dev/null) || fail "no Go build information in $binary"
printf '%s\n' "$info" | grep -Eq '^[[:space:]]+path[[:space:]]' || fail "no Go build information in $binary"

# Any -tags build setting naming the test-approver tag refuses, whatever
# other tags are present.
if printf '%s\n' "$info" | grep -E '^[[:space:]]+build[[:space:]]+-tags=' | grep -q 'envbank_testapprover'; then
	fail "$binary was built with the envbank_testapprover tag (test-only build; never sign it)"
fi

echo "check-sign-target: ok: $binary has no test-approver build tag"
