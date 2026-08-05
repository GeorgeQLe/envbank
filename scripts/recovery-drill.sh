#!/usr/bin/env bash

set -Eeuo pipefail

readonly EXPECTED_SCHEMA_VERSION=3
readonly DEFAULT_PORT=17337
readonly SQLITE_BIN=/usr/bin/sqlite3
readonly CURL_BIN=/usr/bin/curl

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
PORT=${ENVBANK_PORT:-$DEFAULT_PORT}
KEEP_ARTIFACTS=${KEEP_ARTIFACTS:-0}
ENVBANK_BIN=${ENVBANK_BIN:-}
DRILL_DIR=
SERVICE_PID=

usage() {
	cat <<'EOF'
Usage: scripts/recovery-drill.sh [--port PORT] [--keep-artifacts]

Environment overrides:
  ENVBANK_BIN     Existing EnvBank binary (default: build a disposable binary)
  ENVBANK_PORT    Loopback port (default: 17337)
  KEEP_ARTIFACTS  Set to 1 to retain the temporary drill directory
EOF
}

fail() {
	printf 'recovery-drill: FAIL: %s\n' "$*" >&2
	exit 1
}

stop_service() {
	if [[ -n "${SERVICE_PID:-}" ]]; then
		kill "$SERVICE_PID" 2>/dev/null || true
		wait "$SERVICE_PID" 2>/dev/null || true
		SERVICE_PID=
	fi
}

cleanup() {
	local status=$?
	trap - EXIT
	stop_service
	if [[ -n "${DRILL_DIR:-}" && -d "$DRILL_DIR" ]]; then
		if [[ "$KEEP_ARTIFACTS" == 1 ]]; then
			printf 'recovery-drill: artifacts retained at %s\n' "$DRILL_DIR" >&2
		elif [[ "$(basename "$DRILL_DIR")" == envbank-recovery-drill.* ]]; then
			rm -rf -- "$DRILL_DIR"
		else
			printf 'recovery-drill: refusing to remove unexpected path %s\n' "$DRILL_DIR" >&2
		fi
	fi
	exit "$status"
}

handle_signal() {
	local signal=$1
	trap - "$signal"
	if [[ "$signal" == INT ]]; then
		exit 130
	fi
	exit 143
}

trap cleanup EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

while (($# > 0)); do
	case "$1" in
	--port)
		(($# >= 2)) || fail "--port requires a value"
		PORT=$2
		shift 2
		;;
	--keep-artifacts)
		KEEP_ARTIFACTS=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		fail "unknown argument: $1"
		;;
	esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] || fail "port must be numeric"
((PORT >= 1 && PORT <= 65535)) || fail "port must be between 1 and 65535"
case "$KEEP_ARTIFACTS" in
0 | 1) ;;
true | TRUE | yes | YES) KEEP_ARTIFACTS=1 ;;
false | FALSE | no | NO) KEEP_ARTIFACTS=0 ;;
*) fail "KEEP_ARTIFACTS must be 0, 1, true, false, yes, or no" ;;
esac

[[ -x "$SQLITE_BIN" ]] || fail "$SQLITE_BIN is required"
[[ -x "$CURL_BIN" ]] || fail "$CURL_BIN is required"
command -v awk >/dev/null || fail "awk is required"
command -v grep >/dev/null || fail "grep is required"
command -v mktemp >/dev/null || fail "mktemp is required"

TMP_BASE=${TMPDIR:-/tmp}
TMP_BASE=${TMP_BASE%/}
DRILL_DIR=$(mktemp -d "$TMP_BASE/envbank-recovery-drill.XXXXXX")
chmod 700 "$DRILL_DIR"
umask 077

DB=$DRILL_DIR/server.db
BACKUP=$DRILL_DIR/server.backup.db
QUARANTINE=$DRILL_DIR/live-quarantine
URL=http://127.0.0.1:$PORT
A_CFG=$DRILL_DIR/device-a.json
B_CFG=$DRILL_DIR/device-b.json
A_PASS=$DRILL_DIR/device-a.pass
B_PASS=$DRILL_DIR/device-b.pass
SERVICE_LOG=$DRILL_DIR/service.log

if [[ -n "$ENVBANK_BIN" ]]; then
	[[ -x "$ENVBANK_BIN" ]] || fail "ENVBANK_BIN is not executable: $ENVBANK_BIN"
	BIN=$ENVBANK_BIN
else
	BIN=$DRILL_DIR/envbank
	(
		cd "$REPO_DIR"
		go build -o "$BIN" ./cmd/envbank
	)
fi

printf '%s\n' 'dummy-recovery-drill-passphrase-a' >"$A_PASS"
printf '%s\n' 'dummy-recovery-drill-passphrase-b' >"$B_PASS"
chmod 600 "$A_PASS" "$B_PASS"

wait_for_health() {
	local attempt
	for ((attempt = 0; attempt < 100; attempt++)); do
		if ! kill -0 "$SERVICE_PID" 2>/dev/null; then
			return 1
		fi
		if "$CURL_BIN" -fsS "$URL/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

start_service() {
	local log_path=$1
	"$BIN" serve --listen "127.0.0.1:$PORT" --database "$DB" >"$log_path" 2>&1 &
	SERVICE_PID=$!
	if ! wait_for_health; then
		fail "service did not become healthy; inspect $log_path with KEEP_ARTIFACTS=1"
	fi
}

file_mode() {
	local path=$1
	if stat -f '%Lp' "$path" >/dev/null 2>&1; then
		stat -f '%Lp' "$path"
	else
		stat -c '%a' "$path"
	fi
}

sha256_file() {
	local path=$1
	if command -v shasum >/dev/null; then
		shasum -a 256 "$path" | awk '{print $1}'
	elif command -v sha256sum >/dev/null; then
		sha256sum "$path" | awk '{print $1}'
	else
		fail "shasum or sha256sum is required"
	fi
}

validate_candidate() {
	local path=$1
	local quick_check
	local version
	quick_check=$("$SQLITE_BIN" "$path" 'PRAGMA quick_check;' 2>/dev/null) || return 1
	[[ "$quick_check" == ok ]] || return 1
	version=$("$SQLITE_BIN" "$path" 'PRAGMA user_version;' 2>/dev/null) || return 1
	[[ "$version" == "$EXPECTED_SCHEMA_VERSION" ]]
}

assert_device_states() {
	local output=$1
	printf '%s\n' "$output" |
		awk -F '\t' '
			$2 == "primary" && $4 == "active" { primary = 1 }
			$2 == "secondary" && $4 == "revoked" { secondary = 1 }
			END { exit !(primary && secondary) }
		' || fail "expected active primary and revoked secondary device"
}

expect_denied() {
	local output_path=$1
	local error_path=$2
	shift 2
	if "$@" >"$output_path" 2>"$error_path"; then
		fail "revoked device was unexpectedly authorized"
	fi
	grep -q 'server returned 401' "$error_path" ||
		fail "revoked-device rejection was not an authentication denial"
}

start_service "$SERVICE_LOG"

"$BIN" init \
	--server "$URL" \
	--vault recovery-drill \
	--device primary \
	--config "$A_CFG" \
	--passphrase-file "$A_PASS" \
	>"$DRILL_DIR/init.out"

VAULT_ID=$("$SQLITE_BIN" "$DB" 'SELECT id FROM vaults LIMIT 1;')
[[ -n "$VAULT_ID" ]] || fail "vault was not created"

"$BIN" enroll-request \
	--server "$URL" \
	--vault-id "$VAULT_ID" \
	--device secondary \
	--config "$B_CFG" \
	--passphrase-file "$B_PASS" \
	>"$DRILL_DIR/enroll-request.out"

ENROLL_LINE=$(
	"$BIN" enroll-list --config "$A_CFG" --passphrase-file "$A_PASS" |
		awk '$4 == "pending" { print; exit }'
)
DEVICE_B_ID=$(printf '%s\n' "$ENROLL_LINE" | awk '{print $1}')
DEVICE_B_FP=$(printf '%s\n' "$ENROLL_LINE" | awk '{print $3}')
[[ -n "$DEVICE_B_ID" && -n "$DEVICE_B_FP" ]] || fail "pending enrollment was not found"

"$BIN" enroll-approve \
	--fingerprint "$DEVICE_B_FP" \
	--config "$A_CFG" \
	--passphrase-file "$A_PASS" \
	"$DEVICE_B_ID" >/dev/null
"$BIN" enroll-accept --config "$B_CFG" --passphrase-file "$B_PASS" >/dev/null

printf '%s\n' 'dummy-pre-backup-value' |
	"$BIN" set --config "$A_CFG" --passphrase-file "$A_PASS" PRE_BACKUP_SENTINEL >/dev/null
PRE_VALUE=$(
	"$BIN" get --config "$B_CFG" --passphrase-file "$B_PASS" PRE_BACKUP_SENTINEL
)
[[ "$PRE_VALUE" == dummy-pre-backup-value ]] || fail "pre-backup sentinel did not decrypt"
unset PRE_VALUE

"$BIN" device-revoke \
	--fingerprint "$DEVICE_B_FP" \
	--config "$A_CFG" \
	--passphrase-file "$A_PASS" \
	"$DEVICE_B_ID" >/dev/null

expect_denied "$DRILL_DIR/revoked.out" "$DRILL_DIR/revoked.err" \
	"$BIN" list --config "$B_CFG" --passphrase-file "$B_PASS"

"$BIN" event-list --limit 100 --config "$A_CFG" --passphrase-file "$A_PASS" \
	>"$DRILL_DIR/events-before.out"
[[ -s "$DRILL_DIR/events-before.out" ]] || fail "access history was empty"
DEVICE_STATE=$("$BIN" device-list --config "$A_CFG" --passphrase-file "$A_PASS")
assert_device_states "$DEVICE_STATE"

"$SQLITE_BIN" "$DB" ".timeout 5000" ".backup '$BACKUP'"
chmod 600 "$BACKUP"
BACKUP_EPOCH=$(date +%s)
BACKUP_SHA=$(sha256_file "$BACKUP")
BACKUP_CHECK=$("$SQLITE_BIN" "$BACKUP" 'PRAGMA quick_check;')
BACKUP_VERSION=$("$SQLITE_BIN" "$BACKUP" 'PRAGMA user_version;')
[[ "$BACKUP_CHECK" == ok ]] || fail "backup quick_check failed"
[[ "$BACKUP_VERSION" == "$EXPECTED_SCHEMA_VERSION" ]] ||
	fail "backup schema version was $BACKUP_VERSION, expected $EXPECTED_SCHEMA_VERSION"
[[ "$(file_mode "$BACKUP")" == 600 ]] || fail "backup permissions were not 0600"

cp "$BACKUP" "$DRILL_DIR/truncated.db"
truncate -s 4096 "$DRILL_DIR/truncated.db"
if validate_candidate "$DRILL_DIR/truncated.db"; then
	fail "truncated backup passed pre-start validation"
fi

cp "$BACKUP" "$DRILL_DIR/future.db"
"$SQLITE_BIN" "$DRILL_DIR/future.db" 'PRAGMA user_version = 999;'
if validate_candidate "$DRILL_DIR/future.db"; then
	fail "future schema passed pre-start validation"
fi

printf '%s\n' 'dummy-post-backup-value' |
	"$BIN" set --config "$A_CFG" --passphrase-file "$A_PASS" POST_BACKUP_MARKER >/dev/null
POST_LIVE=$(
	"$BIN" get --config "$A_CFG" --passphrase-file "$A_PASS" POST_BACKUP_MARKER
)
[[ "$POST_LIVE" == dummy-post-backup-value ]] || fail "post-backup marker was not committed"
unset POST_LIVE

RESTORE_START_EPOCH=$(date +%s)
stop_service
mkdir "$QUARANTINE"
for original in "$DB" "$DB-wal" "$DB-shm"; do
	if [[ -e "$original" ]]; then
		mv "$original" "$QUARANTINE/"
	fi
done

validate_candidate "$BACKUP" || fail "backup failed validation immediately before restore"
cp "$BACKUP" "$DB"
chmod 600 "$DB"
start_service "$DRILL_DIR/restored-service.log"
RPO_WINDOW_SECONDS=$((RESTORE_START_EPOCH - BACKUP_EPOCH))

[[ "$(file_mode "$DB")" == 600 ]] || fail "restored database permissions were not 0600"
RESTORED_PRE=$(
	"$BIN" get --config "$A_CFG" --passphrase-file "$A_PASS" PRE_BACKUP_SENTINEL
)
[[ "$RESTORED_PRE" == dummy-pre-backup-value ]] || fail "restored sentinel did not decrypt"
unset RESTORED_PRE

if "$BIN" get --config "$A_CFG" --passphrase-file "$A_PASS" POST_BACKUP_MARKER \
	>"$DRILL_DIR/post-marker.out" 2>"$DRILL_DIR/post-marker.err"; then
	fail "post-backup marker was unexpectedly present after restore"
fi
grep -q 'secret not found' "$DRILL_DIR/post-marker.err" ||
	fail "post-backup marker absence was not confirmed"

RESTORED_DEVICES=$("$BIN" device-list --config "$A_CFG" --passphrase-file "$A_PASS")
assert_device_states "$RESTORED_DEVICES"
expect_denied "$DRILL_DIR/revoked-restored.out" "$DRILL_DIR/revoked-restored.err" \
	"$BIN" event-list --limit 10 --config "$B_CFG" --passphrase-file "$B_PASS"

"$BIN" event-list --limit 100 --config "$A_CFG" --passphrase-file "$A_PASS" \
	>"$DRILL_DIR/events-restored-1.out"
EVENTS_ONE=$(wc -l <"$DRILL_DIR/events-restored-1.out" | tr -d ' ')
"$BIN" device-list --config "$A_CFG" --passphrase-file "$A_PASS" >/dev/null
"$BIN" event-list --limit 100 --config "$A_CFG" --passphrase-file "$A_PASS" \
	>"$DRILL_DIR/events-restored-2.out"
EVENTS_TWO=$(wc -l <"$DRILL_DIR/events-restored-2.out" | tr -d ' ')
((EVENTS_TWO > EVENTS_ONE)) || fail "access history did not continue recording"

printf '%s\n' 'dummy-post-restore-value' |
	"$BIN" set --config "$A_CFG" --passphrase-file "$A_PASS" POST_RESTORE_SENTINEL >/dev/null
POST_RESTORE_NOW=$(
	"$BIN" get --config "$A_CFG" --passphrase-file "$A_PASS" POST_RESTORE_SENTINEL
)
[[ "$POST_RESTORE_NOW" == dummy-post-restore-value ]] ||
	fail "post-restore write did not decrypt"
unset POST_RESTORE_NOW

stop_service
start_service "$DRILL_DIR/restarted-service.log"
POST_RESTART=$(
	"$BIN" get --config "$A_CFG" --passphrase-file "$A_PASS" POST_RESTORE_SENTINEL
)
[[ "$POST_RESTART" == dummy-post-restore-value ]] ||
	fail "post-restore write did not survive restart"
unset POST_RESTART

FINAL_CHECK=$("$SQLITE_BIN" "$DB" 'PRAGMA quick_check;')
FINAL_VERSION=$("$SQLITE_BIN" "$DB" 'PRAGMA user_version;')
FINAL_DB_MODE=$(file_mode "$DB")
FINAL_BACKUP_MODE=$(file_mode "$BACKUP")
[[ "$FINAL_CHECK" == ok ]] || fail "final database quick_check failed"
[[ "$FINAL_VERSION" == "$EXPECTED_SCHEMA_VERSION" ]] || fail "final schema version changed"
[[ "$FINAL_DB_MODE" == 600 ]] || fail "final database permissions were not 0600"
[[ "$FINAL_BACKUP_MODE" == 600 ]] || fail "final backup permissions were not 0600"
RESTORE_VERIFIED_EPOCH=$(date +%s)
RTO_SECONDS=$((RESTORE_VERIFIED_EPOCH - RESTORE_START_EPOCH))
stop_service

cat >"$DRILL_DIR/evidence.txt" <<EOF
RESULT=PASS
BACKUP_SHA256=$BACKUP_SHA
BACKUP_QUICK_CHECK=$BACKUP_CHECK
FINAL_QUICK_CHECK=$FINAL_CHECK
SCHEMA_VERSION=$FINAL_VERSION
BACKUP_MODE=$FINAL_BACKUP_MODE
RESTORED_DB_MODE=$FINAL_DB_MODE
PRE_BACKUP_SENTINEL=DECRYPTED
POST_BACKUP_MARKER=ABSENT
DEVICE_STATES=PRESERVED
REVOKED_DEVICE=DENIED
ACCESS_HISTORY=READABLE_AND_GROWING
POST_RESTORE_WRITE=PERSISTED_AFTER_RESTART
TRUNCATED_BACKUP=REJECTED
FUTURE_SCHEMA=REJECTED
RPO_WINDOW_SECONDS=$RPO_WINDOW_SECONDS
RTO_SECONDS=$RTO_SECONDS
EOF

cat "$DRILL_DIR/evidence.txt"
