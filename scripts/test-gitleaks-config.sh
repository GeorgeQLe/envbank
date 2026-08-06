#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scan_dir=$(mktemp -d "${TMPDIR:-/tmp}/envbank-gitleaks.XXXXXX")
trap 'rm -rf "$scan_dir"' EXIT HUP INT TERM

# Assemble the fixture so the test script itself does not contain a detectable
# credential. This value is synthetic and never used for authentication.
prefix=AKIA
suffix=ABCDEFGHIJKLMNOP
printf 'AWS_ACCESS_KEY_ID=%s%s\n' "$prefix" "$suffix" > "$scan_dir/fixture.env"

if gitleaks dir --redact --config "$repository_root/.gitleaks.toml" \
	--exit-code 42 "$scan_dir" >/dev/null 2>&1; then
	echo "synthetic secret was not detected" >&2
	exit 1
else
	status=$?
fi

if [ "$status" -ne 42 ]; then
	echo "gitleaks failed unexpectedly with status $status" >&2
	exit "$status"
fi

echo "synthetic secret detected"
