.PHONY: build test test-go test-extension race vet build-linux recovery-drill

build:
	go build -o envbank ./cmd/envbank

test: test-go test-extension

test-go:
	go test ./...

test-extension:
	node --test extension/test/*.test.js

race:
	go test -race ./...

vet:
	go vet ./...

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/envbank-linux ./cmd/envbank

recovery-drill:
	./scripts/recovery-drill.sh
