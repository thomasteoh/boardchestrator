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
**Answer:** (a) — implemented in `87afbf8` (WU-101, 2026-07-24): `config.Load` requires `BC_SESSION_SECRET` ≥32 chars (fatal on load), covered by `TestLoadRequiresSessionSecret` + `TestLoadSessionSecretTooShort`. *(resolved 2026-08-16)*

## Q3 — SQLite driver choice (modernc.org/sqlite)

**Context:** SPEC names SQLite, golang-migrate and sqlc but no Go driver. WU-003 had to pick one. The two mainstream options are mattn/go-sqlite3 (cgo) and modernc.org/sqlite (pure Go). WU-008 targets a distroless container and CI runs `go test -race ./...`; a cgo-free build keeps both static and simple, and golang-migrate's `sqlite` database driver targets modernc.
**Options:** (a) modernc.org/sqlite — pure Go, static binary, slightly slower; (b) mattn/go-sqlite3 — cgo, marginally faster, complicates cross-compilation and distroless.
**Recommendation:** (a). **Assumption taken (not blocking):** proceeded with modernc.org/sqlite v1.46.1 — the newest version whose dependency closure keeps `go 1.25` in go.mod under the pinned local Go 1.25 toolchain. Swapping is confined to `internal/db` if answered differently.

## Q5 — CSRF vs the API-key write surface (WU-542 / WU-523)

**Context:** Middleware order is API-key → Session → CSRF, all mounted globally on the single chi mux (`internal/server/server.go:166-175`). `SessionConfig.CSRF()` (`internal/auth/middleware.go:162-185`) exempts only safe methods; for anything else it requires a **session**. A pure API-key client has no session cookie, so `POST /api/v1/actions/{name}`, `PUT /api/v1/orgs/.../tasks/{taskID}` and `POST /mcp` return 403 before ever reaching `APIKeyActorFrom`. The documented write API is dead on arrival for its only auth method.

To be precise about which way this fails: it is a **broken API, not a CSRF bypass**. There is no API-key exemption today, so a cookie-bearing browser cannot forge a state-changing request either. The reads are unaffected — every cross-tenant leak found in the review (`/files/{id}`, `/api/search`, the `/api/v1/orgs/{orgID}/...` resource routes, `/events`) is a GET and therefore exempt as a safe method.

**Options:**
(a) Exempt a request from CSRF only when it resolved to an API-key actor **and** no ambient session cookie was used. An attacker cannot set an `Authorization` header cross-origin without a CORS preflight, so gating on a *successfully resolved API-key actor* is safe.
(b) Exempt when a `Bearer` token is merely present. **Unsafe** — gating on session-absence or header-presence alone is the classic bypass; do not take this option.
(c) Split the router: mount session+CSRF on `/app/*` and API-key auth on `/api/v1/*` and `/mcp`, with no shared middleware chain.

**Recommendation:** (c) if the routing churn is acceptable, since it makes the two auth surfaces structurally separate and removes the whole class of confusion; otherwise (a). Either way this **must** land after WU-523 (API keys bound to their org) — enabling API-key writes before the org binding exists converts the currently-fails-closed `POST /api/v1/actions/{name}` into a full cross-tenant write RPC.
**Answer:**

## Q6 — Re-encryption path for `BC_SECRET_KEY` (WU-536)

**Context:** `tenant.PadKey` (`internal/tenant/secrets.go:76`) zero-pads a short `BC_SECRET_KEY` to 32 bytes with no KDF, and `config.Load` only checks it is non-empty. WU-536 requires ≥32 chars and an HKDF derivation, and additionally binds `org_id||key` as AES-GCM associated data. Both changes alter how existing ciphertexts decrypt, and there are live secrets encrypted under the old scheme: per-org S3 credentials (`internal/action/storage_settings.go:59`), user GitHub PATs and OAuth tokens (`github_connection.go:81`, `internal/auth/handler.go:261`), and skill secrets (`skills.go:207`).

**Options:**
(a) Versioned ciphertext envelope — prefix a scheme byte, decrypt v0 with the legacy path and v1 with HKDF+AAD, re-encrypt lazily on next write. No downtime, no operator action, carries the legacy code path indefinitely.
(b) One-shot migration command (`bc secrets rewrap`) run at upgrade with both old and new key material in the environment; fails loudly on any row it cannot rewrap.
(c) Invalidate — drop all stored secrets and require operators to re-enter S3 credentials and re-link GitHub accounts.

**Recommendation:** (a) plus a `bc secrets rewrap` to force completion and then drop the v0 path in a later release — the deployment is self-hosted, so we cannot assume a coordinated upgrade window, and (c) silently breaks every org's storage backend and wiki editing.
**Answer:**
