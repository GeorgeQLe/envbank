#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
# shellcheck source=scripts/e2e-scan.sh
source "$SCRIPT_DIR/e2e-scan.sh"
BROWSER_DIR=$REPO_DIR/e2e/browser
KEEP_ARTIFACTS=${KEEP_ARTIFACTS:-0}
REAL_HOME=$HOME
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/envbank-browser-e2e.XXXXXX")
cleanup() {
	local status=$?
	trap - EXIT
	if [[ "$KEEP_ARTIFACTS" == 1 ]] && ! e2e_scan_extended 'ENVBANK_E2E_SECRET_DO_NOT_LEAK' "$WORK_DIR/output.log" "$WORK_DIR/error.log" "$WORK_DIR/artifacts" 2>/dev/null; then
		printf 'e2e-browser: sanitized artifacts retained at %s\n' "$WORK_DIR"
	else
		if [[ "$KEEP_ARTIFACTS" == 1 ]]; then printf 'e2e-browser: refusing to retain artifacts containing the synthetic marker\n' >&2; fi
		rm -rf -- "$WORK_DIR"
	fi
	exit "$status"
}
trap cleanup EXIT
export GOCACHE="$WORK_DIR/go-cache"

[[ -d "$BROWSER_DIR/node_modules" ]] || { printf 'e2e-browser: dependencies missing; run npm ci --prefix e2e/browser\n' >&2; exit 1; }
mkdir "$WORK_DIR/home" "$WORK_DIR/profile" "$WORK_DIR/artifacts"
chmod 700 "$WORK_DIR/home" "$WORK_DIR/profile" "$WORK_DIR/artifacts"
go build -o "$WORK_DIR/envbank-e2e-nativehost" ./e2e/browser/nativehost
chmod 700 "$WORK_DIR/envbank-e2e-nativehost"
if [[ "$(uname -s)" == Darwin ]]; then DEFAULT_BROWSER_CACHE="$REAL_HOME/Library/Caches/ms-playwright"; else DEFAULT_BROWSER_CACHE="$REAL_HOME/.cache/ms-playwright"; fi
PLAYWRIGHT_BROWSERS_PATH=${PLAYWRIGHT_BROWSERS_PATH:-$DEFAULT_BROWSER_CACHE} HOME="$WORK_DIR/home" npm --prefix "$BROWSER_DIR" test -- "$REPO_DIR" "$WORK_DIR/profile" "$WORK_DIR/envbank-e2e-nativehost" "$WORK_DIR/artifacts" >"$WORK_DIR/output.log" 2>"$WORK_DIR/error.log"
if e2e_scan_extended 'ENVBANK_E2E_SECRET_DO_NOT_LEAK' "$WORK_DIR/output.log" "$WORK_DIR/error.log" "$WORK_DIR/artifacts"; then
	printf 'e2e-browser: FAIL plaintext marker in observable artifacts\n' >&2; exit 1
fi
printf 'e2e-browser: RESULT=PASS\n'
