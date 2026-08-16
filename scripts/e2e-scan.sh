#!/usr/bin/env bash

# Quietly search files or directories without making ripgrep a prerequisite.
# Callers report only fixed failure text so matched plaintext is never echoed.
e2e_scan_extended() {
	local pattern=$1
	shift
	if command -v rg >/dev/null 2>&1; then
		rg -a -q -- "$pattern" "$@"
	else
		grep -a -E -R -q -- "$pattern" "$@"
	fi
}
