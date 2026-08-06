.PHONY: build test test-go test-extension format-check race vet security secret-scan-test build-cross recovery-drill

build:
	go build -o envbank ./cmd/envbank

test: test-go test-extension

format-check:
	test -z "$$(gofmt -l .)"

test-go:
	go test ./...

test-extension:
	node --test extension/test/*.test.js

race:
	go test -race ./...

vet:
	go vet ./...

security:
	govulncheck ./...

secret-scan-test:
	./scripts/test-gitleaks-config.sh

build-cross:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o /tmp/envbank-darwin-amd64 ./cmd/envbank
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o /tmp/envbank-darwin-arm64 ./cmd/envbank
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/envbank-linux-amd64 ./cmd/envbank
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/envbank-linux-arm64 ./cmd/envbank

recovery-drill:
	./scripts/recovery-drill.sh
