#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/envbank-e2e-release.XXXXXX")
export GOCACHE="$WORK_DIR/go-cache"
CONTAINER=
IMAGE_TAG=
WEBSITE_PID=
cleanup() {
	local status=$?
	trap - EXIT
	if [[ -n "${WEBSITE_PID:-}" ]]; then kill "$WEBSITE_PID" 2>/dev/null || true; wait "$WEBSITE_PID" 2>/dev/null || true; fi
	if [[ -n "${CONTAINER:-}" ]]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; fi
	if [[ -n "${IMAGE_TAG:-}" ]]; then docker image rm "$IMAGE_TAG" >/dev/null 2>&1 || true; fi
	rm -rf -- "$WORK_DIR"
	exit "$status"
}
trap cleanup EXIT
VERSION=${VERSION:-dev}
COMMIT=$(git -C "$REPO_DIR" rev-parse HEAD)
BUILD_DATE=$(git -C "$REPO_DIR" show -s --format=%cI HEAD)
HOST_GOOS=$(go env GOOS)
HOST_GOARCH=$(go env GOARCH)

sha_file() {
	if command -v shasum >/dev/null; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi
}

select_loopback_port() {
	node -e 'const net=require("node:net"); const server=net.createServer(); server.once("error",()=>process.exit(1)); server.listen(0,"127.0.0.1",()=>{process.stdout.write(String(server.address().port)); server.close();});'
}

for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
	GOOS=${target%/*}; GOARCH=${target#*/}; root="envbank_${VERSION#v}_${GOOS}_${GOARCH}"
	CGO=0
	if [[ "$GOOS" == darwin && "$HOST_GOOS" == darwin ]]; then CGO=1; fi
	mkdir "$WORK_DIR/$root"
	(
		cd "$REPO_DIR"
		CGO_ENABLED=$CGO GOOS=$GOOS GOARCH=$GOARCH go build -trimpath \
			-ldflags="-X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
			-o "$WORK_DIR/$root/envbank" ./cmd/envbank
	)
	cp "$REPO_DIR/LICENSE" "$REPO_DIR/README.md" "$WORK_DIR/$root/"
	(cd "$WORK_DIR" && tar -czf "$root.tar.gz" "$root")
	if tar -tzf "$WORK_DIR/$root.tar.gz" | grep -E -q '(^/|(^|/)\.\.(/|$))'; then printf 'e2e-release-local: FAIL unsafe archive path\n' >&2; exit 1; fi
	mkdir "$WORK_DIR/extract-$GOOS-$GOARCH"
	tar -xzf "$WORK_DIR/$root.tar.gz" -C "$WORK_DIR/extract-$GOOS-$GOARCH"
	test -x "$WORK_DIR/extract-$GOOS-$GOARCH/$root/envbank"
	digest=$(sha_file "$WORK_DIR/$root.tar.gz")
	printf '%s  %s\n' "$digest" "$root.tar.gz" >>"$WORK_DIR/SHA256SUMS"
	go version -m "$WORK_DIR/extract-$GOOS-$GOARCH/$root/envbank" | grep -F 'github.com/GeorgeQLe/envbank/cmd/envbank' >/dev/null
	if [[ "$GOOS" == darwin && "$HOST_GOOS" == darwin ]]; then otool -L "$WORK_DIR/extract-$GOOS-$GOARCH/$root/envbank" | grep -F 'Security.framework' >/dev/null; fi
	if [[ "$GOOS" == "$HOST_GOOS" && "$GOARCH" == "$HOST_GOARCH" ]]; then
		"$WORK_DIR/extract-$GOOS-$GOARCH/$root/envbank" version | grep -F "envbank $VERSION (commit $COMMIT, built $BUILD_DATE)" >/dev/null
	fi
	printf 'e2e-release-local: PASS archive %s/%s sha256=%s\n' "$GOOS" "$GOARCH" "$digest"
done
(cd "$WORK_DIR" && if command -v shasum >/dev/null; then shasum -a 256 -c SHA256SUMS >/dev/null; else sha256sum -c SHA256SUMS >/dev/null; fi)
printf 'e2e-release-local: PASS checksums\n'

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
	IMAGE_TAG="envbank-e2e-release-local:$(basename "$WORK_DIR" | tr '[:upper:]' '[:lower:]')"
	docker build --build-arg VERSION="$VERSION" --build-arg COMMIT="$COMMIT" --build-arg BUILD_DATE="$BUILD_DATE" -t "$IMAGE_TAG" "$REPO_DIR" >/dev/null
	CONTAINER=$(docker run -d --rm -p 127.0.0.1::7337 "$IMAGE_TAG")
	port=$(docker port "$CONTAINER" 7337/tcp | awk -F: 'NR == 1 {print $NF}')
	for ((attempt = 0; attempt < 100; attempt++)); do curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
	curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null
	docker rm -f "$CONTAINER" >/dev/null
	CONTAINER=
	printf 'e2e-release-local: PASS container-health\n'
else
	printf 'e2e-release-local: SKIP container-health reason=DOCKER_UNAVAILABLE\n'
fi

test -d "$REPO_DIR/website/node_modules" || { printf 'e2e-release-local: FAIL website dependencies missing\n' >&2; exit 1; }
npm --prefix "$REPO_DIR/website" run build >/dev/null
website_port=$(select_loopback_port)
npm --prefix "$REPO_DIR/website" run start -- --hostname 127.0.0.1 --port "$website_port" >"$WORK_DIR/website.out" 2>"$WORK_DIR/website.err" &
WEBSITE_PID=$!
for ((attempt = 0; attempt < 100; attempt++)); do curl -fsS "http://127.0.0.1:$website_port/" >/dev/null 2>&1 && break; sleep 0.1; done
node "$REPO_DIR/website/scripts/smoke.mjs" "http://127.0.0.1:$website_port" >/dev/null
kill "$WEBSITE_PID" 2>/dev/null || true
wait "$WEBSITE_PID" 2>/dev/null || true
WEBSITE_PID=
printf 'e2e-release-local: PASS website-production-smoke\n'
