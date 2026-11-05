#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/e2e-scan.sh
source "$SCRIPT_DIR/e2e-scan.sh"
PROVIDER=${1:-}
[[ "${ENVBANK_LIVE_ACCEPTANCE:-}" == 1 ]] || { printf 'e2e-live: FAIL reason=EXPLICIT_AUTHORIZATION_REQUIRED\n' >&2; exit 1; }
[[ -t 0 && -t 1 ]] || { printf 'e2e-live: FAIL reason=INTERACTIVE_TTY_REQUIRED\n' >&2; exit 1; }
for forbidden in STRIPE_SECRET_KEY STRIPE_API_KEY RAILWAY_TOKEN RAILWAY_API_TOKEN CLOUDFLARE_API_TOKEN CLERK_SECRET_KEY CLERK_API_KEY; do
	[[ -z "${!forbidden:-}" ]] || { printf 'e2e-live: FAIL reason=CREDENTIAL_ENVIRONMENT_FORBIDDEN\n' >&2; exit 1; }
done
case "$PROVIDER" in
stripe | railway | cloudflare)
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
	[[ "$(grep -E -c '^  [A-Z0-9_]+: prepared$' "$tmp/result.out" || true)" == 5 ]] || { printf 'e2e-live: FAIL reason=EXPECTED_RECORD_SET_MISMATCH\n' >&2; exit 1; }
	"$tmp/envbank" list --config "$CLERK_ACCEPTANCE_CONFIG" --passphrase-file "$CLERK_ACCEPTANCE_PASSPHRASE_FILE" >"$tmp/records.out" 2>>"$tmp/result.err"
	[[ "$(grep -E -c 'revision=[1-9][0-9]*$' "$tmp/records.out" || true)" -ge 5 ]] || { printf 'e2e-live: FAIL reason=REVISIONS_NOT_VERIFIED\n' >&2; exit 1; }
	if e2e_scan_extended '(^|[^A-Za-z])(sk_|pk_|whsec_)[A-Za-z0-9_-]{12}' "$tmp/result.out" "$tmp/records.out" "$tmp/result.err"; then printf 'e2e-live: FAIL reason=PLAINTEXT_OUTPUT_DETECTED\n' >&2; exit 1; fi
	printf 'e2e-live: provider=clerk records=5 verification=NAMES_AND_REVISIONS_ONLY result=PASS\n'
	;;
vercel | vercel-production)
	# Disposable Preview acceptance through the configured vault workflow. The
	# owner binds the token (stdin -> Keychain), enrolls the Secure Enclave
	# approval key, plans and approves BEFORE this runs; see
	# docs/vercel-acceptance.md. This script never binds, approves or deletes.
	for forbidden in VERCEL_TOKEN VERCEL_API_TOKEN VERCEL_ACCESS_TOKEN VERCEL_AUTOMATION_BYPASS_SECRET VERCEL_OIDC_TOKEN ENVBANK_VERCEL_TOKEN; do
		[[ -z "${!forbidden:-}" ]] || { printf 'e2e-live: FAIL reason=CREDENTIAL_ENVIRONMENT_FORBIDDEN\n' >&2; exit 1; }
	done
    vercel_subcommand=accept
    if [[ "$PROVIDER" == vercel-production ]]; then
        vercel_subcommand=accept-production
        [[ "${ENVBANK_VERCEL_ACCEPTANCE_TARGET:-}" == disposable-production:*/*/envbank-acceptance-* ]] || { printf 'e2e-live: FAIL reason=DISPOSABLE_TARGET_REQUIRED\n' >&2; exit 1; }
    else
        [[ "${ENVBANK_VERCEL_ACCEPTANCE_TARGET:-}" == disposable:*/*/envbank-acceptance-*@envbank-acceptance* ]] || { printf 'e2e-live: FAIL reason=DISPOSABLE_TARGET_REQUIRED\n' >&2; exit 1; }
    fi
    # Keep the exact signed helper identity used for enrollment/binding. An
    # unsigned rebuilt binary may not access its Data Protection Keychain group.
    vercel_cli=${VERCEL_ACCEPTANCE_CLI:-}
    [[ "$vercel_cli" == /* && -f "$vercel_cli" && -x "$vercel_cli" ]] || { printf 'e2e-live: FAIL reason=TRUSTED_CLI_REQUIRED\n' >&2; exit 1; }
	: "${VERCEL_ACCEPTANCE_MANIFEST:?VERCEL_ACCEPTANCE_MANIFEST is required}"
	: "${VERCEL_ACCEPTANCE_CONFIG:?VERCEL_ACCEPTANCE_CONFIG is required}"
	: "${VERCEL_ACCEPTANCE_PASSPHRASE_FILE:?VERCEL_ACCEPTANCE_PASSPHRASE_FILE is required}"
	: "${VERCEL_ACCEPTANCE_PLAN:?VERCEL_ACCEPTANCE_PLAN is required; the owner must plan and approve first}"
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/envbank-vercel-acceptance.XXXXXX")
	trap 'rm -rf -- "$tmp"' EXIT
	status=0
	"$vercel_cli" vercel "$vercel_subcommand" --manifest "$VERCEL_ACCEPTANCE_MANIFEST" --plan "$VERCEL_ACCEPTANCE_PLAN" \
		--config "$VERCEL_ACCEPTANCE_CONFIG" --passphrase-file "$VERCEL_ACCEPTANCE_PASSPHRASE_FILE" >"$tmp/receipt.json" 2>"$tmp/result.err" || status=$?
	if e2e_scan_extended 'x-vercel-protection-bypass|"(proof|challenge|token|value)"|Bearer ' "$tmp/receipt.json" "$tmp/result.err"; then
		printf 'e2e-live: FAIL reason=PLAINTEXT_OUTPUT_DETECTED\n' >&2
		exit 1
	fi
	cat "$tmp/receipt.json"
	[[ "$status" == 0 ]] || { printf 'e2e-live: provider=%s result=BLOCKED (see receipt blocker; no fake PASS)\n' "$PROVIDER" >&2; exit 1; }
	printf 'e2e-live: provider=%s full_workflow=not-qualified result=PASS\n' "$PROVIDER"
	;;
*)
	printf 'e2e-live: FAIL reason=PROVIDER_MUST_BE_STRIPE_CLERK_CLOUDFLARE_RAILWAY_VERCEL_OR_VERCEL_PRODUCTION\n' >&2
	exit 1
	;;
esac
