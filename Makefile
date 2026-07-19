.PHONY: gen check check-scope dev build

GO := go
GOFMT := gofmt
GOLANGCI_LINT := $(shell go env GOPATH)/bin/golangci-lint

gen:
	@echo "gen: no codegen targets yet (templ, sqlc)"

check: gen check-scope
	@echo "--- gofmt ---"
	$(GOFMT) -d -l . | awk '{print} END{exit NR>0}'
	@echo "--- go vet ---"
	$(GO) vet ./...
	@echo "--- golangci-lint ---"
	$(GOLANGCI_LINT) run
	@echo "--- tests ---"
	$(GO) test -race ./...
	@echo "--- git diff check (generated files) ---"
	cp go.mod go.mod.check && go mod tidy && diff -q go.mod go.mod.check >/dev/null && rm go.mod.check || { echo "go.mod/go.sum out of sync — run go mod tidy"; exit 1; }
	@echo "check: PASS"

check-scope:
	@echo "check-scope: placeholder pass (no tenant tables yet)"

dev:
	@echo "dev: run 'go run ./cmd/bc' with local .env"

build:
	$(GO) build ./cmd/bc
