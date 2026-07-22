# WU-008 — Dockerfile + CI

## Context
This is a Go project (boardchestrator). The main repo is at ~/projects/boardchestrator. 
Worktree: this directory (wu-008).
Branch: wu-008/phase-0, based on build-phase-0.

## What to build

### Dockerfile
Multi-stage distroless nonroot container:
- Stage 1: build Go binary (`make build`)
- Stage 2: distroless/static-nonroot (or alpine → distroless), copy binary, /data volume, port 8080
- HEALTHCHECK using /healthz endpoint
- CGO_ENABLED=0 for pure-Go static binary (modernc.org/sqlite)

### CI workflows (`.github/workflows/`)
1. `lint.yml` — PR to main: golangci-lint, gofmt, templ generate check
2. `test.yml` — push to main: `go test -race ./...`
3. `release.yml` — tag matching `^\d+\.\d+\.\d+$`: buildx + push to ghcr.io, tag X.Y.Z + latest
   - rc tags (`^\d+\.\d+\.\d+-rc\.\d+$`): build image, no push

### Acceptance criteria
- `docker build` succeeds locally
- Workflows lint clean (actionlint if available)
- Tag-pattern filtering covered by workflow-level `if` conditions

## Progress recording
Update BACKLOG.md in this worktree after each meaningful step. Mark WU-008 as `in-progress` at the start. When done, set to `done <date> <commit subject>`. Commit messages: `WU-008: <summary>`.

## Files to read for context
- PRD.md, SPEC.md, BACKLOG.md, WORKER.md, Makefile, go.mod, cmd/bc/, internal/
