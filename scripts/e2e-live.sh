#!/usr/bin/env bash

set -Eeuo pipefail
PROVIDER=${1:-}
[[ "${ENVBANK_LIVE_ACCEPTANCE:-}" == 1 ]] || { printf 'e2e-live: FAIL reason=EXPLICIT_AUTHORIZATION_REQUIRED\n' >&2; exit 1; }
[[ -t 0 && -t 1 ]] || { printf 'e2e-live: FAIL reason=INTERACTIVE_TTY_REQUIRED\n' >&2; exit 1; }
for forbidden in STRIPE_SECRET_KEY STRIPE_API_KEY RAILWAY_TOKEN RAILWAY_API_TOKEN CLERK_SECRET_KEY CLERK_API_KEY; do
	[[ -z "${!forbidden:-}" ]] || { printf 'e2e-live: FAIL reason=CREDENTIAL_ENVIRONMENT_FORBIDDEN\n' >&2; exit 1; }
done
case "$PROVIDER" in
stripe | railway)
	go run ./e2e/live "$PROVIDER"
	;;
clerk)
	: "${CLERK_ACCEPTANCE_TARGET:?CLERK_ACCEPTANCE_TARGET is required}"
	[[ "$CLERK_ACCEPTANCE_TARGET" == *ENVBANK_ACCEPTANCE* ]] || { printf 'e2e-live: FAIL reason=TARGET_MARKER_REQUIRED\n' >&2; exit 1; }
	: "${CLERK_ACCEPTANCE_MANIFEST:?CLERK_ACCEPTANCE_MANIFEST is required}"
	: "${CLERK_ACCEPTANCE_CONFIG:?CLERK_ACCEPTANCE_CONFIG is required}"
	: "${CLERK_ACCEPTANCE_PASSPHRASE_FILE:?CLERK_ACCEPTANCE_PASSPHRASE_FILE is required}"
	: "${CLERK_ACCEPTANCE_CLI:?CLERK_ACCEPTANCE_CLI is required}"
	: "${CLERK_ACCEPTANCE_APP:?CLERK_ACCEPTANCE_APP is required}"
	: "${CLERK_ACCEPTANCE_AUTHORIZED_PARTY:?CLERK_ACCEPTANCE_AUTHORIZED_PARTY is required}"
	[[ -x "$CLERK_ACCEPTANCE_CLI" ]] || { printf 'e2e-live: FAIL reason=CLERK_CLI_UNAVAILABLE\n' >&2; exit 1; }
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/envbank-clerk-acceptance.XXXXXX")
	trap 'rm -rf -- "$tmp"' EXIT
	go build -o "$tmp/envbank" ./cmd/envbank
	go build -o "$tmp/envbank-provider-clerk" ./cmd/envbank-provider-clerk
	"$tmp/envbank" bundle prepare-exec --manifest "$CLERK_ACCEPTANCE_MANIFEST" --config "$CLERK_ACCEPTANCE_CONFIG" --passphrase-file "$CLERK_ACCEPTANCE_PASSPHRASE_FILE" -- \
		"$tmp/envbank-provider-clerk" export --app "$CLERK_ACCEPTANCE_APP" --instance dev --authorized-party "$CLERK_ACCEPTANCE_AUTHORIZED_PARTY" --clerk "$CLERK_ACCEPTANCE_CLI" >"$tmp/result.out" 2>"$tmp/result.err"
	[[ "$(rg -c '^  [A-Z0-9_]+: prepared$' "$tmp/result.out" || true)" == 5 ]] || { printf 'e2e-live: FAIL reason=EXPECTED_RECORD_SET_MISMATCH\n' >&2; exit 1; }
	"$tmp/envbank" list --config "$CLERK_ACCEPTANCE_CONFIG" --passphrase-file "$CLERK_ACCEPTANCE_PASSPHRASE_FILE" >"$tmp/records.out" 2>>"$tmp/result.err"
	[[ "$(rg -c 'revision=[1-9][0-9]*$' "$tmp/records.out" || true)" -ge 5 ]] || { printf 'e2e-live: FAIL reason=REVISIONS_NOT_VERIFIED\n' >&2; exit 1; }
	if rg -n '(^|[^A-Za-z])(sk_|pk_|whsec_)[A-Za-z0-9_-]{12}' "$tmp/result.out" "$tmp/records.out" "$tmp/result.err" >/dev/null; then printf 'e2e-live: FAIL reason=PLAINTEXT_OUTPUT_DETECTED\n' >&2; exit 1; fi
	printf 'e2e-live: provider=clerk records=5 verification=NAMES_AND_REVISIONS_ONLY result=PASS\n'
	;;
vercel)
	printf 'e2e-live: provider=vercel result=PRODUCTION_ADAPTER_UNAVAILABLE\n' >&2
	exit 1
	;;
*)
	printf 'e2e-live: FAIL reason=PROVIDER_MUST_BE_STRIPE_CLERK_OR_RAILWAY\n' >&2
	exit 1
	;;
esac
