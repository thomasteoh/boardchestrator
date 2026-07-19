.PHONY: gen check check-scope dev build

GO := go
GOFMT := gofmt
GOLANGCI_LINT := $(shell go env GOPATH)/bin/golangci-lint

# Pinned codegen tool versions so `make gen` works identically on a clean
# machine (fetched via `go run mod@version`; nothing global to install).
# sqlc v1.30.0 is the newest release whose go directive builds under the
# repo's Go 1.25 toolchain (v1.31.x requires go >= 1.26).
SQLC_VERSION := v1.30.0

gen:
	@echo "--- sqlc generate ---"
	@if ls internal/db/queries/*.sql >/dev/null 2>&1; then \
		$(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate; \
	else \
		echo "sqlc: no query files under internal/db/queries yet — skipping"; \
	fi

check: gen check-scope
	@echo "--- generated files diff-clean ---"
	git diff --exit-code -- internal/db/sqlc || { echo "sqlc output out of date — run make gen and commit"; exit 1; }
	@echo "--- gofmt ---"
	$(GOFMT) -d -l . | awk '{print} END{exit NR>0}'
	@echo "--- go vet ---"
	$(GO) vet ./...
	@echo "--- golangci-lint ---"
	$(GOLANGCI_LINT) run
	@echo "--- tests ---"
	$(GO) test -race ./...
	@echo "--- git diff check (go.mod tidy) ---"
	cp go.mod go.mod.check && go mod tidy && diff -q go.mod go.mod.check >/dev/null && rm go.mod.check || { echo "go.mod/go.sum out of sync — run go mod tidy"; exit 1; }
	@echo "check: PASS"

check-scope:
	@./scripts/check-scope.sh

dev:
	@echo "dev: run 'go run ./cmd/bc' with local .env"

build:
	$(GO) build ./cmd/bc
