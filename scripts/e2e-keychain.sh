#!/usr/bin/env bash

set -Eeuo pipefail

[[ "$(uname -s)" == Darwin ]] || { printf 'e2e-keychain: FAIL reason=MACOS_REQUIRED\n' >&2; exit 1; }
[[ -t 0 && -t 1 ]] || { printf 'e2e-keychain: FAIL reason=INTERACTIVE_TTY_REQUIRED\n' >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
RUN_DIR=
SERVICE_PID=
FIXTURE_PID=
BROWSER_PID=
INSTALLED=0
BIN=
PROFILE=

fail() {
	printf 'e2e-keychain: FAIL reason=%s\n' "$1" >&2
	exit 1
}

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	for pid in "${BROWSER_PID:-}" "${FIXTURE_PID:-}" "${SERVICE_PID:-}"; do
		if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
	done
	if [[ "$INSTALLED" == 1 && -x "${BIN:-}" ]]; then
		"$BIN" browser-uninstall --browser chrome-for-testing --profile-dir "$PROFILE" --delete-keychain >/dev/null 2>&1 || status=1
	fi
	if [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" && "$(basename "$RUN_DIR")" == envbank-keychain-e2e.* ]]; then
		rm -rf -- "$RUN_DIR"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

confirm() {
	local field=$1 prompt=$2 answer
	read -r -p "$prompt [y/N] " answer
	[[ "$answer" == y || "$answer" == Y ]] || { printf 'e2e-keychain: FAIL field=%s\n' "$field" >&2; exit 1; }
	printf 'e2e-keychain: PASS field=%s\n' "$field"
}

select_loopback_port() {
	python3 -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()'
}

cd "$REPO_DIR"
printf '%s\n' 'e2e-keychain: APPROVAL CHECK — choose Allow Once on the first macOS Keychain prompt (never Always Allow).'
ENVBANK_KEYCHAIN_INTEGRATION=1 go test ./internal/keychain -run '^TestSystemStoreIntegration$' -count=1
printf '%s\n' 'e2e-keychain: DENIAL CHECK — choose Deny on the next macOS Keychain prompt (do not approve it).'
ENVBANK_KEYCHAIN_EXPECT_CANCEL=1 go test ./internal/keychain -run '^TestSystemStoreCancellation$' -count=1

[[ -d e2e/browser/node_modules/playwright ]] || fail PLAYWRIGHT_NOT_INSTALLED
BROWSER=$(node -e "const {chromium}=require('./e2e/browser/node_modules/playwright'); process.stdout.write(chromium.executablePath())")
[[ -x "$BROWSER" ]] || fail HEADED_CHROME_FOR_TESTING_UNAVAILABLE
command -v python3 >/dev/null || fail PYTHON3_REQUIRED

LOCATOR=
HOST=

RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/envbank-keychain-e2e.XXXXXX")
chmod 700 "$RUN_DIR"
umask 077
BIN="$RUN_DIR/envbank"
CONFIG="$RUN_DIR/device.json"
PASSPHRASE="$RUN_DIR/passphrase.input"
SECRET="$RUN_DIR/record.input"
DB="$RUN_DIR/server.db"
PROFILE="$RUN_DIR/chrome-profile"
MANIFEST="$PROFILE/NativeMessagingHosts/com.envbank.native.json"
mkdir -p "$PROFILE"
[[ ! -e "$MANIFEST" ]] || fail EXISTING_NATIVE_HOST_MANIFEST

/usr/bin/uuidgen | awk '{print "envbank-keychain-passphrase-" tolower($0)}' >"$PASSPHRASE"
/usr/bin/uuidgen | awk '{print "envbank-keychain-browser-secret-" tolower($0)}' >"$SECRET"
chmod 600 "$PASSPHRASE" "$SECRET"

PORT=$(select_loopback_port) || fail LOOPBACK_PORT_UNAVAILABLE
URL="http://127.0.0.1:$PORT"

go build -o "$BIN" ./cmd/envbank
"$BIN" serve --listen "127.0.0.1:$PORT" --database "$DB" >"$RUN_DIR/service.out" 2>"$RUN_DIR/service.err" &
SERVICE_PID=$!
for ((attempt = 0; attempt < 100; attempt++)); do
	if curl -fsS "$URL/healthz" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsS "$URL/healthz" >/dev/null || fail SERVICE_UNHEALTHY

"$BIN" init --server "$URL" --vault keychain-acceptance --device release-mac \
	--config "$CONFIG" --passphrase-file "$PASSPHRASE" >/dev/null
"$BIN" set --config "$CONFIG" --passphrase-file "$PASSPHRASE" \
	ENVBANK_KEYCHAIN_BROWSER_SENTINEL <"$SECRET" >/dev/null
"$BIN" keychain-store --config "$CONFIG" --passphrase-file "$PASSPHRASE" >/dev/null
"$BIN" browser-install --browser chrome-for-testing --profile-dir "$PROFILE" --config "$CONFIG" >/dev/null
INSTALLED=1
HOST=$(node -e 'const fs=require("node:fs"); const manifest=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(manifest.path)' "$MANIFEST")
LOCATOR="$(dirname "$HOST")/native-config"
[[ -x "$HOST" && -f "$LOCATOR" ]] || fail NATIVE_HOST_SUPPORT_INCOMPLETE

FIXTURE_PORT=$(select_loopback_port) || fail FIXTURE_PORT_UNAVAILABLE
python3 -m http.server "$FIXTURE_PORT" --bind 127.0.0.1 --directory extension \
	>"$RUN_DIR/fixture.out" 2>"$RUN_DIR/fixture.err" &
FIXTURE_PID=$!
FIXTURE_URL="http://127.0.0.1:$FIXTURE_PORT"

# Replace the original authorization with the actual fixture origin.
"$BIN" browser-allow --config "$CONFIG" --passphrase-file "$PASSPHRASE" \
	ENVBANK_KEYCHAIN_BROWSER_SENTINEL "$FIXTURE_URL" >/dev/null

"$BROWSER" --user-data-dir="$PROFILE" --no-first-run --no-default-browser-check \
	--password-store=basic --use-mock-keychain \
	--load-extension="$REPO_DIR/extension" "$FIXTURE_URL/test/fixture.html" \
	>"$RUN_DIR/browser.out" 2>"$RUN_DIR/browser.err" &
BROWSER_PID=$!

printf '%s\n' 'In the disposable Chrome for Testing window:'
printf '%s\n' '  1. Open the Extensions menu, then EnvBank Fill.'
printf '%s\n' '  2. APPROVAL CHECK — on the Keychain prompt choose Allow Once (never Always Allow).'
printf '%s\n' '  3. Choose ENVBANK_KEYCHAIN_BROWSER_SENTINEL, then click the Text field within 30 seconds.'
confirm CHROME_REAL_FILL 'Did the Text field fill after approval?'

printf '%s\n' '  4. Open EnvBank Fill and click Lock.'
printf '%s\n' '  5. DENIAL CHECK — reopen EnvBank Fill and choose Deny (do not approve).'
printf '%s\n' '  6. Confirm the Password field remains empty.'
confirm TOUCH_ID_CANCEL 'Did denial leave the Password field empty?'
confirm KEYCHAIN_LOCKED_UNAVAILABLE 'Did the denied/unavailable Keychain state fail closed without revealing a value?'

kill "$BROWSER_PID" 2>/dev/null || true
wait "$BROWSER_PID" 2>/dev/null || true
BROWSER_PID=

SCAN_PATHS=("$PROFILE" "$DB" "$CONFIG" "$RUN_DIR"/*.out "$RUN_DIR"/*.err)
for sidecar in "$DB-wal" "$DB-shm"; do
	if [[ -e "$sidecar" ]]; then SCAN_PATHS+=("$sidecar"); fi
done
LEAK_FOUND=0
if command -v rg >/dev/null 2>&1; then
	if rg -a -l -f "$SECRET" "${SCAN_PATHS[@]}" \
		--glob '!record.input' --glob '!passphrase.input' >"$RUN_DIR/leaks.out"; then LEAK_FOUND=1; fi
else
	if grep -a -E -R -l -f "$SECRET" --exclude=record.input --exclude=passphrase.input \
		"${SCAN_PATHS[@]}" >"$RUN_DIR/leaks.out"; then LEAK_FOUND=1; fi
fi
((LEAK_FOUND == 0)) || fail PLAINTEXT_PERSISTED
printf 'e2e-keychain: PASS field=PLAINTEXT_PERSISTENCE_SCAN\n'

"$BIN" browser-uninstall --browser chrome-for-testing --profile-dir "$PROFILE" --delete-keychain >/dev/null
INSTALLED=0
[[ ! -e "$MANIFEST" && ! -e "$LOCATOR" && ! -e "$HOST" ]] || fail CLEANUP_INCOMPLETE
printf 'e2e-keychain: PASS field=CLEANUP\n'
printf 'e2e-keychain: RESULT=PASS\n'
