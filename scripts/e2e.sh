#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
KEEP_ARTIFACTS=${KEEP_ARTIFACTS:-0}
MARKER_PATTERN='whsec_testlab_[A-Za-z0-9_-]{20}|sk_testlab_[A-Za-z0-9_-]{20}|ENVBANK_E2E_SECRET_DO_NOT_LEAK'
E2E_DIR=
WEBSITE_PID=

fail() {
	printf 'e2e: FAIL: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	local status=$?
	trap - EXIT
	if [[ -n "${WEBSITE_PID:-}" ]]; then kill "$WEBSITE_PID" 2>/dev/null || true; wait "$WEBSITE_PID" 2>/dev/null || true; fi
	if [[ -n "${E2E_DIR:-}" && -d "$E2E_DIR" ]]; then
		if [[ "$KEEP_ARTIFACTS" == 1 ]]; then
			if rg -a -q "$MARKER_PATTERN" "$E2E_DIR"/*.out "$E2E_DIR"/*.err 2>/dev/null; then
				printf 'e2e: refusing to retain artifacts that contain a synthetic marker\n' >&2
				rm -rf -- "$E2E_DIR"
			else
				printf 'e2e: sanitized artifacts retained at %s\n' "$E2E_DIR" >&2
			fi
		elif [[ "$(basename "$E2E_DIR")" == envbank-e2e.* ]]; then
			rm -rf -- "$E2E_DIR"
		fi
	fi
	exit "$status"
}
trap cleanup EXIT

case "$KEEP_ARTIFACTS" in
0 | 1) ;;
*) fail "KEEP_ARTIFACTS must be 0 or 1" ;;
esac

E2E_DIR=$(mktemp -d "${TMPDIR:-/tmp}/envbank-e2e.XXXXXX")
chmod 700 "$E2E_DIR"
umask 077
export GOCACHE="$E2E_DIR/go-cache"

run_logged() {
	local name=$1
	shift
	printf 'e2e: RUN %s\n' "$name"
	if ! "$@" >"$E2E_DIR/$name.out" 2>"$E2E_DIR/$name.err"; then
		if rg -a -q "$MARKER_PATTERN" "$E2E_DIR/$name.out" "$E2E_DIR/$name.err" 2>/dev/null; then
			printf 'e2e: %s failed; diagnostics withheld: synthetic marker detected\n' "$name" >&2
		else
			local stream
			for stream in out err; do
				if [[ -s "$E2E_DIR/$name.$stream" ]]; then
					printf 'e2e: sanitized diagnostics (%s.%s, first 8192 bytes)\n' "$name" "$stream" >&2
					head -c 8192 "$E2E_DIR/$name.$stream" >&2 || true
					printf '\n' >&2
				fi
			done
		fi
		return 1
	fi
	printf 'e2e: PASS %s\n' "$name"
}

select_loopback_port() {
	node -e 'const net=require("node:net"); const server=net.createServer(); server.once("error",()=>process.exit(1)); server.listen(0,"127.0.0.1",()=>{process.stdout.write(String(server.address().port)); server.close();});'
}

cd "$REPO_DIR"
run_logged go go test ./...
run_logged testlab ./scripts/testlab-matrix.sh
run_logged recovery env KEEP_ARTIFACTS=0 ./scripts/recovery-drill.sh
run_logged extension node --test extension/test/core.test.js extension/test/content.test.js

if [[ ! -d website/node_modules ]]; then
	fail "website/node_modules is missing; run 'npm ci --prefix website' once (the gate itself is network-free)"
fi
run_logged website-lint npm --prefix website run lint
run_logged website-typecheck npm --prefix website run typecheck
run_logged website-build npm --prefix website run build

WEBSITE_PORT=$(select_loopback_port)
npm --prefix website run start -- --hostname 127.0.0.1 --port "$WEBSITE_PORT" >"$E2E_DIR/website-server.out" 2>"$E2E_DIR/website-server.err" &
WEBSITE_PID=$!
for ((attempt = 0; attempt < 100; attempt++)); do
	if ! kill -0 "$WEBSITE_PID" 2>/dev/null; then fail "website server exited"; fi
	if curl -fsS "http://127.0.0.1:$WEBSITE_PORT/" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
run_logged website-smoke node website/scripts/smoke.mjs "http://127.0.0.1:$WEBSITE_PORT"
kill "$WEBSITE_PID" 2>/dev/null || true
wait "$WEBSITE_PID" 2>/dev/null || true
WEBSITE_PID=

# These are the production-shaped synthetic credential prefixes. Scan every
# observable artifact after all child processes have stopped.
if rg -a -q "$MARKER_PATTERN" \
	"$E2E_DIR"/*.out "$E2E_DIR"/*.err; then
	fail "synthetic plaintext marker appeared in observable artifacts"
fi
printf 'e2e: PASS plaintext-leakage-scan\n'
printf 'e2e: RESULT=PASS\n'
