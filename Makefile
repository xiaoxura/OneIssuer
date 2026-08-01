SHELL := /bin/sh

VERSION ?= v0.1.0-dev.2
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

TOOLS_DIR := $(CURDIR)/.tools/bin
SQLC_VERSION := v1.31.1
GOOSE_VERSION := v3.27.3
GOLANGCI_LINT_VERSION := v2.12.2
GOVULNCHECK_VERSION := v1.6.0
REDOCLY_VERSION := 2.43.2
SQLC := $(TOOLS_DIR)/sqlc
GOOSE := $(TOOLS_DIR)/goose
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint
GOVULNCHECK := $(TOOLS_DIR)/govulncheck
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

.PHONY: tools generate generate-check migration-check openapi-check sensitive-check fuzz-smoke fmt fmt-check go-lint lint test integration-test vuln build go-check web-install web-check contract-check check migrate-up migrate-status dev web compose-up compose-down compose-smoke clean

tools: $(SQLC) $(GOOSE) $(GOLANGCI_LINT) $(GOVULNCHECK)

$(TOOLS_DIR):
	mkdir -p $@

$(SQLC): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

$(GOOSE): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)

$(GOLANGCI_LINT): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOVULNCHECK): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

generate: $(SQLC)
	$(SQLC) generate

generate-check: $(SQLC)
	./scripts/check-generated.sh $(SQLC)

migration-check:
	./scripts/check-migrations.sh

openapi-check:
	REDOCLY_VERSION=$(REDOCLY_VERSION) ./scripts/check-openapi.sh

sensitive-check:
	./scripts/check-sensitive-examples.sh

fuzz-smoke:
	./scripts/fuzz-smoke.sh

fmt:
	gofmt -w $$(find cmd internal -type f -name '*.go' -not -path '*/sqlcgen/*')

fmt-check:
	@files=$$(gofmt -l $$(find cmd internal -type f -name '*.go')); \
	if [ -n "$$files" ]; then echo "Go files need gofmt:"; echo "$$files"; exit 1; fi

go-lint: tools fmt-check generate-check
	go vet ./...
	$(GOLANGCI_LINT) run ./...

lint: go-lint web-install
	cd web && npm run lint

test:
	go test -race ./...

integration-test:
	go test -race -run Integration ./internal/storage/postgres ./internal/httpserver ./internal/app

vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o bin/oneissuer ./cmd/oneissuer

go-check: tools fmt-check generate-check migration-check sensitive-check
	go vet ./...
	$(GOLANGCI_LINT) run ./...
	go test -race ./...
	$(MAKE) fuzz-smoke
	$(GOVULNCHECK) ./...
	$(MAKE) build

web-install:
	cd web && npm ci

web-check: web-install
	cd web && npm run check
	cd web && npm audit --audit-level=high --fetch-retries=5 --fetch-retry-mintimeout=1000 --fetch-retry-maxtimeout=10000 --fetch-timeout=30000

contract-check: migration-check sensitive-check openapi-check

check: go-check web-check openapi-check

migrate-up:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; go run ./cmd/oneissuer migrate up

migrate-status:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; go run ./cmd/oneissuer migrate status

dev:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; go run ./cmd/oneissuer serve

web:
	cd web && npm run dev

compose-up:
	docker compose -f deploy/docker-compose.yml up --build -d

compose-down:
	docker compose -f deploy/docker-compose.yml down -v --remove-orphans

compose-smoke:
	./scripts/smoke-compose.sh

clean:
	rm -rf bin .tools coverage web/dist
