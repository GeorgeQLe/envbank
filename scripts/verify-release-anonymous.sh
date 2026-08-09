#!/usr/bin/env bash
set -euo pipefail

VERSION="v0.1.1"
REPOSITORY="GeorgeQLe/envbank"
LEGACY_REPOSITORY="GeorgeQLe/invisible-envs-bank"
IMAGE="ghcr.io/georgeqle/envbank"
WORKFLOW="GeorgeQLe/envbank/.github/workflows/release.yml"
API_URL="https://api.github.com/repos/${REPOSITORY}/releases/tags/${VERSION}"
CANONICAL_URL="https://github.com/${REPOSITORY}"
LEGACY_URL="https://github.com/${LEGACY_REPOSITORY}"

expected_assets=(
  SHA256SUMS
  envbank_0.1.1_artifacts.provenance.json
  envbank_0.1.1_darwin_amd64.tar.gz
  envbank_0.1.1_darwin_arm64.tar.gz
  envbank_0.1.1_image.provenance.json
  envbank_0.1.1_linux_amd64.tar.gz
  envbank_0.1.1_linux_arm64.tar.gz
  envbank_0.1.1_sbom.spdx.json
)

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

assert_safe_archive_entry() {
  local entry=$1 component
  [[ -n "$entry" ]] || return 1
  [[ "$entry" != /* ]] || return 1
  [[ "$entry" != *\\* ]] || return 1
  [[ "$entry" != *'//'* ]] || return 1
  IFS=/ read -r -a components <<< "${entry%/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || return 1
  done
}

assert_safe_archive_types() {
  [[ "$1" == $'-\n-\n-\nd' ]]
}

archive_safety_self_test() {
  local unsafe
  assert_safe_archive_entry 'envbank_0.1.1_linux_amd64/envbank'
  for unsafe in \
    '/absolute/path' \
    '../escape' \
    'root/../../escape' \
    'root/./file' \
    'root//file' \
    'root\\windows-path'; do
    if assert_safe_archive_entry "$unsafe"; then
      fail "archive safety fixture was accepted: $unsafe"
    fi
  done
  assert_safe_archive_types $'-\n-\n-\nd'
  if assert_safe_archive_types $'-\n-\nl\nd'; then
    fail 'archive symlink fixture was accepted'
  fi
  printf 'archive safety fixtures passed\n'
}

if [[ ${1:-} == --archive-safety-self-test ]]; then
  archive_safety_self_test
  exit 0
fi
[[ $# -eq 0 ]] || fail "usage: $0 [--archive-safety-self-test]"

for command in curl git gh jq tar docker; do
  need "$command"
done
if command -v sha256sum >/dev/null 2>&1; then
  checksum_command=(sha256sum --check)
elif command -v shasum >/dev/null 2>&1; then
  checksum_command=(shasum -a 256 --check)
else
  fail 'required command not found: sha256sum or shasum'
fi

verification_root=$(mktemp -d "${TMPDIR:-/tmp}/envbank-v0.1.1-anonymous.XXXXXX")
download_dir="$verification_root/downloads"
container_name="envbank-v011-verify-$$"
volume_name="envbank-v011-verify-$$"
immutable_image=''
image_was_present=false
container_created=false
volume_created=false

cleanup() {
  if [[ "$container_created" == true ]]; then
    docker rm -f "$container_name" >/dev/null 2>&1 || true
  fi
  if [[ "$volume_created" == true ]]; then
    docker volume rm "$volume_name" >/dev/null 2>&1 || true
  fi
  if [[ -n "$immutable_image" && "$image_was_present" == false ]]; then
    docker image rm "$immutable_image" >/dev/null 2>&1 || true
  fi
  rm -rf "$verification_root"
}
trap cleanup EXIT INT TERM

mkdir -p "$download_dir" "$verification_root/gh" "$verification_root/docker"
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
unset DOCKER_AUTH_CONFIG GIT_ASKPASS SSH_ASKPASS
export GH_CONFIG_DIR="$verification_root/gh"
export DOCKER_CONFIG="$verification_root/docker"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/false

curl_public=(
  curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2
  --fail --location --silent --show-error
)

printf 'Checking anonymous repository access and redirect...\n'
redirect_result=$("${curl_public[@]}" --output /dev/null \
  --write-out '%{url_effective}\n%{num_redirects}\n' "$LEGACY_URL")
[[ $(sed -n '1p' <<< "$redirect_result") == "$CANONICAL_URL" ]] ||
  fail 'legacy repository did not redirect to the canonical repository'
[[ $(sed -n '2p' <<< "$redirect_result") == 1 ]] ||
  fail 'legacy repository redirect was not exactly one hop'
"${curl_public[@]}" --output /dev/null "$CANONICAL_URL"
git -c credential.helper= clone --quiet --filter=blob:none --no-checkout \
  "${CANONICAL_URL}.git" "$verification_root/canonical"
git -c credential.helper= clone --quiet --filter=blob:none --no-checkout \
  "${LEGACY_URL}.git" "$verification_root/legacy"
canonical_head=$(git -C "$verification_root/canonical" rev-parse origin/main)
legacy_head=$(git -C "$verification_root/legacy" rev-parse origin/main)
[[ "$canonical_head" == "$legacy_head" ]] || fail 'canonical and legacy clones disagree on main'

tag_lines=$(git -c credential.helper= ls-remote --tags "${CANONICAL_URL}.git" \
  "refs/tags/$VERSION" "refs/tags/$VERSION^{}")
tag_object=$(awk -v ref="refs/tags/$VERSION" '$2 == ref {print $1}' <<< "$tag_lines")
tag_commit=$(awk -v ref="refs/tags/$VERSION^{}" '$2 == ref {print $1}' <<< "$tag_lines")
[[ -n "$tag_object" && -n "$tag_commit" && "$tag_object" != "$tag_commit" ]] ||
  fail "$VERSION is not an annotated tag"
git -C "$verification_root/canonical" merge-base --is-ancestor "$tag_commit" origin/main ||
  fail "$VERSION is not on main"

printf 'Downloading and validating the exact release asset set...\n'
release_json="$verification_root/release.json"
"${curl_public[@]}" --output "$release_json" "$API_URL"
jq -e --arg tag "$VERSION" \
  '.tag_name == $tag and .draft == false and .prerelease == true' \
  "$release_json" >/dev/null
actual_assets=$(jq -r '.assets[].name' "$release_json" | LC_ALL=C sort)
expected_asset_list=$(printf '%s\n' "${expected_assets[@]}" | LC_ALL=C sort)
[[ "$actual_assets" == "$expected_asset_list" ]] || fail 'release asset set does not match the expected eight files'
for asset in "${expected_assets[@]}"; do
  asset_url=$(jq -er --arg name "$asset" \
    '.assets[] | select(.name == $name) | .browser_download_url' "$release_json")
  [[ "$asset_url" == https://* ]] || fail "non-HTTPS asset URL for $asset"
  "${curl_public[@]}" --output "$download_dir/$asset" "$asset_url"
done

expected_archives=(
  envbank_0.1.1_darwin_amd64.tar.gz
  envbank_0.1.1_darwin_arm64.tar.gz
  envbank_0.1.1_linux_amd64.tar.gz
  envbank_0.1.1_linux_arm64.tar.gz
)
checksum_names=$(awk '{print $2}' "$download_dir/SHA256SUMS" | sed 's/^\*//' | LC_ALL=C sort)
expected_archive_list=$(printf '%s\n' "${expected_archives[@]}" | LC_ALL=C sort)
[[ "$checksum_names" == "$expected_archive_list" ]] || fail 'SHA256SUMS does not list exactly the four archives'
(cd "$download_dir" && "${checksum_command[@]}" SHA256SUMS)

for archive in "${expected_archives[@]}"; do
  archive_root=${archive%.tar.gz}
  archive_entries=$(tar -tzf "$download_dir/$archive")
  entry_count=$(printf '%s\n' "$archive_entries" | awk 'END {print NR}')
  [[ "$entry_count" == 4 ]] || fail "$archive does not contain exactly four entries"
  archive_types=$(tar -tvzf "$download_dir/$archive" | awk '{print substr($1, 1, 1)}' | LC_ALL=C sort)
  assert_safe_archive_types "$archive_types" || fail "$archive contains links or unsupported entry types"
  while IFS= read -r entry; do
    assert_safe_archive_entry "$entry" || fail "unsafe archive entry in $archive: $entry"
  done <<< "$archive_entries"
  sorted_entries=$(printf '%s\n' "$archive_entries" | LC_ALL=C sort)
  expected_entries=(
    "$archive_root/"
    "$archive_root/LICENSE"
    "$archive_root/README.md"
    "$archive_root/envbank"
  )
  expected_entry_list=$(printf '%s\n' "${expected_entries[@]}" | LC_ALL=C sort)
  [[ "$sorted_entries" == "$expected_entry_list" ]] || fail "unexpected paths in $archive"
done

jq -e '
  (.spdxVersion | startswith("SPDX-2.")) and
  .SPDXID == "SPDXRef-DOCUMENT" and
  .dataLicense == "CC0-1.0" and
  (.creationInfo.created | type == "string") and
  (.packages | type == "array" and length > 0)
' "$download_dir/envbank_0.1.1_sbom.spdx.json" >/dev/null

printf 'Verifying Sigstore bundles and release provenance...\n'
trusted_root="$verification_root/trusted_root.jsonl"
gh attestation trusted-root > "$trusted_root"
artifact_bundle="$download_dir/envbank_0.1.1_artifacts.provenance.json"
for subject in "${expected_archives[@]}" SHA256SUMS envbank_0.1.1_sbom.spdx.json; do
  gh attestation verify "$download_dir/$subject" \
    --bundle "$artifact_bundle" \
    --custom-trusted-root "$trusted_root" \
    --repo "$REPOSITORY" \
    --signer-workflow "$WORKFLOW" \
    --source-ref "refs/tags/$VERSION" \
    --source-digest "$tag_commit" >/dev/null
done

case "$(uname -s)/$(uname -m)" in
  Darwin/x86_64) host_archive=envbank_0.1.1_darwin_amd64.tar.gz ;;
  Darwin/arm64) host_archive=envbank_0.1.1_darwin_arm64.tar.gz ;;
  Linux/x86_64) host_archive=envbank_0.1.1_linux_amd64.tar.gz ;;
  Linux/aarch64 | Linux/arm64) host_archive=envbank_0.1.1_linux_arm64.tar.gz ;;
  *) fail "unsupported verification host: $(uname -s)/$(uname -m)" ;;
esac
host_root=${host_archive%.tar.gz}
tar -xzf "$download_dir/$host_archive" -C "$verification_root"
version_output=$("$verification_root/$host_root/envbank" version)
expected_build_date=$(git -C "$verification_root/canonical" show -s --format=%cI "$tag_commit")
[[ "$version_output" == "envbank $VERSION (commit $tag_commit, built $expected_build_date)" ]] ||
  fail "host binary metadata does not match $VERSION and $tag_commit: $version_output"

printf 'Verifying the public multi-platform image by immutable digest...\n'
manifest_json="$verification_root/manifest.json"
docker buildx imagetools inspect --raw "$IMAGE:$VERSION" > "$manifest_json"
jq -e '
  [.manifests[].platform | select(.os == "linux") | (.os + "/" + .architecture)]
  | sort == ["linux/amd64", "linux/arm64"]
' "$manifest_json" >/dev/null
image_digest=$(docker buildx imagetools inspect "$IMAGE:$VERSION" | awk '$1 == "Digest:" {print $2; exit}')
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'could not resolve OCI index digest'
immutable_image="$IMAGE@$image_digest"
gh attestation verify "oci://$immutable_image" \
  --bundle "$download_dir/envbank_0.1.1_image.provenance.json" \
  --custom-trusted-root "$trusted_root" \
  --repo "$REPOSITORY" \
  --signer-workflow "$WORKFLOW" \
  --source-ref "refs/tags/$VERSION" \
  --source-digest "$tag_commit" >/dev/null

if docker image inspect "$immutable_image" >/dev/null 2>&1; then
  image_was_present=true
fi
docker pull "$immutable_image" >/dev/null
docker container inspect "$container_name" >/dev/null 2>&1 && fail "verification container already exists: $container_name"
docker volume inspect "$volume_name" >/dev/null 2>&1 && fail "verification volume already exists: $volume_name"
docker volume create "$volume_name" >/dev/null
volume_created=true
docker run --detach --name "$container_name" \
  --publish 127.0.0.1::7337 \
  --volume "$volume_name:/data" \
  "$immutable_image" >/dev/null
container_created=true
host_port=$(docker port "$container_name" 7337/tcp | awk -F: 'NR == 1 {print $NF}')
[[ "$host_port" =~ ^[0-9]+$ ]] || fail 'could not resolve the health-check port'
health_headers="$verification_root/health.headers"
health_body="$verification_root/health.json"
for _ in {1..30}; do
  if curl --disable --fail --silent --show-error --dump-header "$health_headers" \
    --output "$health_body" "http://127.0.0.1:$host_port/healthz"; then
    break
  fi
  sleep 1
done
grep -Eq '^HTTP/[0-9.]+ 200([[:space:]]|$)' "$health_headers" || fail 'health endpoint did not return HTTP 200'
grep -Eiq '^cache-control:[[:space:]]*no-store[[:space:]]*$' "$health_headers" ||
  fail 'health endpoint did not return Cache-Control: no-store'
jq -e '. == {"status":"ok"}' "$health_body" >/dev/null

printf 'Anonymous verification passed.\n'
printf 'tag object: %s\n' "$tag_object"
printf 'tag commit: %s\n' "$tag_commit"
printf 'main head: %s\n' "$canonical_head"
printf 'image digest: %s\n' "$image_digest"
