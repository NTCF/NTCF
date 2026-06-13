# NTCF Makefile. Requires Go 1.25+ (the toolchain auto-downloads if needed).

BINARY      := ntcf
PKG         := github.com/ntcf/ntcf
CMD         := ./cmd/ntcf
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG)/pkg/version.Software=$(VERSION) \
	-X $(PKG)/pkg/version.Commit=$(COMMIT) \
	-X $(PKG)/pkg/version.BuildDate=$(DATE)

FUZZTIME ?= 20s

.PHONY: all
all: fmt vet test build

.PHONY: build
build: ## Build the ntcf binary
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

.PHONY: install
install: ## go install the ntcf binary
	go install -trimpath -ldflags "$(LDFLAGS)" $(CMD)

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run tests with the race detector (needs a C toolchain / CGO)
	go test -race ./...

.PHONY: cover
cover: ## Run tests with coverage
	go test -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -func=coverage.txt | tail -1

.PHONY: fuzz
fuzz: ## Smoke-run each fuzz target for $(FUZZTIME)
	go test ./internal/encoding/ -run=^$$ -fuzz=FuzzDecodeInts     -fuzztime=$(FUZZTIME)
	go test ./internal/encoding/ -run=^$$ -fuzz=FuzzRoundTripInts  -fuzztime=$(FUZZTIME)
	go test ./internal/compress/ -run=^$$ -fuzz=FuzzDecompress     -fuzztime=$(FUZZTIME)
	go test ./internal/column/   -run=^$$ -fuzz=FuzzDecodeChunk    -fuzztime=$(FUZZTIME)
	go test ./internal/index/    -run=^$$ -fuzz=FuzzReadColumnIndex -fuzztime=$(FUZZTIME)
	go test ./internal/query/    -run=^$$ -fuzz=FuzzParse          -fuzztime=$(FUZZTIME)

.PHONY: bench
bench: build ## Run the compression benchmark across all sources
	@for s in generic-flow honeypot web-access; do ./$(BINARY) bench --source $$s --count 200000; echo; done

.PHONY: fmt
fmt: ## Format code
	gofmt -s -w .

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint (must be installed)
	golangci-lint run

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY) $(BINARY).exe coverage.txt *.ntcf *.jsonl

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
