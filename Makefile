GO ?= go
export CGO_ENABLED = 0

.PHONY: build test race cover lint vuln tidy

build:
	$(GO) build -trimpath -o bin/pqtrustd ./cmd/pqtrustd

test:
	$(GO) test ./... -count=1

race:
	CGO_ENABLED=1 $(GO) test -race ./... -count=1

cover:
	$(GO) test ./... -count=1 -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -n 1

lint:
	golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy:
	$(GO) mod tidy
