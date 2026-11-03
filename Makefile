# Makefile for rolekeeper

GO       ?= go
VERSION  := $(shell cat VERSION)
IMAGE    := ghcr.io/runos-official/rolekeeper
PYTHON   ?= python3

.DEFAULT_GOAL := help

.PHONY: build
build: ## Build a static binary stamped with the version
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)" -o rolekeeper ./cmd/rolekeeper

.PHONY: test
test: ## Run the tests with the race detector
	$(GO) test -count=1 -race ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: staticcheck
staticcheck: ## Run staticcheck (go install honnef.co/go/tools/cmd/staticcheck@2026.2.2)
	staticcheck ./...

.PHONY: vulncheck
vulncheck: ## Run govulncheck (go install golang.org/x/vuln/cmd/govulncheck@v1.9.0)
	govulncheck ./...

.PHONY: image
image: ## Build the image for this machine's architecture (no push)
	docker build --build-arg VERSION=$(VERSION) -t rolekeeper:local .

.PHONY: leakcheck
leakcheck: ## Scan every tracked file for credentials and internal identifiers
	$(PYTHON) scripts/leakcheck.py
	$(PYTHON) scripts/unscannable_check.py
	$(PYTHON) scripts/denycheck.py

.PHONY: leakcheck-staged
leakcheck-staged: ## Scan only the staged diff
	$(PYTHON) scripts/leakcheck.py --staged

.PHONY: leakcheck-test
leakcheck-test: ## Test the leak checker itself
	$(PYTHON) scripts/leakcheck_test.py

.PHONY: sourcecheck
sourcecheck: ## Check the files against the tree hash recorded in SOURCE
	$(PYTHON) scripts/treehash.py --check

.PHONY: hooks
hooks: ## Install the tracked git hooks (run once per clone)
	git config core.hooksPath .githooks

.PHONY: version
version: ## Print the version
	@echo $(VERSION)

.PHONY: help
help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-16s %s\n", $$1, $$2}'
