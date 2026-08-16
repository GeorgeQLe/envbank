#!/usr/bin/env bash

set -Eeuo pipefail
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/envbank-testlab-matrix.XXXXXX")
trap 'rm -rf -- "$WORK_DIR"' EXIT
export GOCACHE="$WORK_DIR/go-cache"
go build -o "$WORK_DIR/envbank-testlab" ./cmd/envbank-testlab

"$WORK_DIR/envbank-testlab" serve --state-dir "$WORK_DIR/state" >"$WORK_DIR/first.out" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"envbank_workflow_start","arguments":{"provider":"stripe"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"envbank_test_clock_advance","arguments":{"duration":"30s"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"envbank_workflow_resume","arguments":{"operation_id":"op-000001"}}}
EOF

"$WORK_DIR/envbank-testlab" serve --state-dir "$WORK_DIR/state" >"$WORK_DIR/second.out" <<'EOF'
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"envbank_test_clock_advance","arguments":{"duration":"15m"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"envbank_workflow_resume","arguments":{"operation_id":"op-000001"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"envbank_test_assert_secret_flow","arguments":{"operation_id":"op-000001","vercel_project_id":"vercel-project","railway_project_id":"railway-project"}}}
EOF

rg -q '\\"stage\\":\\"grace-period\\"' "$WORK_DIR/first.out"
rg -q '\\"stage\\":\\"complete\\"' "$WORK_DIR/second.out"
rg -q '\\"all_match\\":true' "$WORK_DIR/second.out"
if rg -a -n 'whsec_testlab_[A-Za-z0-9_-]{20}|sk_testlab_[A-Za-z0-9_-]{20}' \
	"$WORK_DIR/first.out" "$WORK_DIR/second.out" "$WORK_DIR/state"; then
	printf 'testlab-matrix: FAIL plaintext marker leaked\n' >&2
	exit 1
fi
printf 'testlab-matrix: RESULT=PASS\n'
