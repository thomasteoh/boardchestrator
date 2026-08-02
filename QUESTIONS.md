# QUESTIONS.md — Open Items

Workers append here per WORKER.md. Humans answer inline under **Answer:** and flip any `blocked(Qn)` WUs back to `ready`.

---

## Q1 — Codex SSO provider feasibility

**Context:** PRD §8 lists Codex SSO (OAuth to a ChatGPT/OpenAI account) as a provider kind alongside OpenAI-compatible APIs. Using consumer-subscription auth for programmatic API calls may violate OpenAI's terms, and the token flow is undocumented/unstable.
**Options:** (a) implement best-effort against the observed Codex CLI auth flow, accept breakage risk; (b) keep the provider kind registered but stubbed "not yet supported" until confirmed; (c) drop it, OpenAI-compatible keys only.
**Recommendation:** (b) — the interface already isolates it; WU-302 builds the stub, no other WU depends on it.
**Answer:** (b) — stub it; OpenAI-compatible keys are the supported path for now. *(resolved 2026-07-17)*

## Q2 — Wiki edits by Google-only users

**Context:** SPEC §13 commits wiki edits with the user's GitHub token, falling back to the org bot token with `Co-authored-by`. Confirming this is acceptable rather than requiring a linked GitHub account to edit.
**Recommendation:** keep the bot-token fallback (as spec'd).
**Answer:** No bot-token fallback. Wiki edits always commit as the editing user's linked GitHub account, configured in personal settings (OAuth link or PAT). Users without a linked account get read-only wiki with a prompt to connect. *(resolved 2026-07-17)*

## Q4 — Require BC_SESSION_SECRET at startup?

**Context:** WU-005 signs the per-session CSRF token with HMAC keyed on `BC_SESSION_SECRET`. `config.Load` loads it but does not require it (only `BC_SECRET_KEY` is required). With an empty secret the CSRF HMAC still functions but is keyed on "", weakening it, and future session-cookie signing (if added) would be unsafe. I did **not** add a required-check here because it would break the existing config tests (which set only `BC_SECRET_KEY`) and the bootstrap/OAuth WUs may assume the current shape — a change beyond this WU's scope.
**Options:** (a) make `BC_SESSION_SECRET` required in `config.Load` (min length, e.g. 32 bytes) and update config tests + OAuth WUs; (b) leave optional, document that operators must set it; (c) auto-generate a random secret at startup if unset (breaks multi-instance and restarts — sessions/CSRF invalidated on every boot).
**Recommendation:** (a), folded into WU-101 (Google OIDC login) where sessions are first issued for real — that WU already touches auth startup. Assumption taken now (non-blocking): the secret is treated as present; server tests and `bc serve` supply it.
**Answer:**

## Q3 — SQLite driver choice (modernc.org/sqlite)

**Context:** SPEC names SQLite, golang-migrate and sqlc but no Go driver. WU-003 had to pick one. The two mainstream options are mattn/go-sqlite3 (cgo) and modernc.org/sqlite (pure Go). WU-008 targets a distroless container and CI runs `go test -race ./...`; a cgo-free build keeps both static and simple, and golang-migrate's `sqlite` database driver targets modernc.
**Options:** (a) modernc.org/sqlite — pure Go, static binary, slightly slower; (b) mattn/go-sqlite3 — cgo, marginally faster, complicates cross-compilation and distroless.
**Recommendation:** (a). **Assumption taken (not blocking):** proceeded with modernc.org/sqlite v1.46.1 — the newest version whose dependency closure keeps `go 1.25` in go.mod under the pinned local Go 1.25 toolchain. Swapping is confined to `internal/db` if answered differently.
