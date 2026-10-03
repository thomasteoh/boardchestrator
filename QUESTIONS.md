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

## Q7 — Third-party dependencies for Phase 7 (IAM)

**Context:** WORKER.md forbids new dependencies without a QUESTIONS.md entry. PRD §4 (rewritten 2026-10-03) adds verified OIDC, SAML 2.0 and passkeys. Hand-rolling any of these is the higher risk: the original Google flow decoded ID tokens without verifying them (WU-526).

**Dependencies:**
- `github.com/coreos/go-oidc/v3`: OIDC discovery, JWKS caching, ID-token verification. The de-facto Go RP library; pulls `github.com/go-jose/go-jose/v4`.
- `github.com/crewjam/saml`: SAML SP primitives (AuthnRequest, response/assertion validation, metadata). Most widely used Go SAML library; past XML signature-wrapping CVEs are fixed in current releases, and we pin a version at or above the latest advisory fix. Alternative `russellhaering/gosaml2` is smaller but has less IdP coverage in the wild.
- `github.com/go-webauthn/webauthn`: WebAuthn ceremonies and attestation parsing. The maintained successor to duo-labs/webauthn.

**Recommendation:** accept all three, pinned, with `go mod verify` in CI.
**Answer:** Accepted 2026-10-03 (Phase 7 scope approved by the product owner, including SAML, SCIM, OIDC logout and passkeys).

## Q8 — Unverified-email providers (Microsoft Entra) and sign-up

**Context:** SPEC §7.1 makes the Microsoft preset untrusted, and Entra's `email` claim carries no `email_verified`, so WU-602 asserts `EmailVerified=false` for Microsoft unless an admin maps a verification claim (e.g. the optional `xms_edov`) in `claim_map_json`. WU-601's `auth.Resolve` refuses any unseen identity whose email is unverified, before the sign-up step. Together these mean a Microsoft provider with the default claim map can never sign anyone in: there is no path to the first identity, not even with an invite. Other IdPs that omit `email_verified` hit the same wall.

**Options:**
1. Keep the refusal; document that Entra needs `xms_edov` (or a custom verification claim) mapped. Safe, but a surprising setup step.
2. In WU-604, let an **invite** (token bound to the flow, not the asserted email) or org JIT on a verified domain (WU-607/608) create the identity even when the IdP does not vouch for the email; never link by an unverified email.
3. Treat `trust_email=1` as "the admin vouches for this IdP's emails" and set `EmailVerified` from it when the IdP sends no claim.

**Recommendation:** 2 (with 1 documented meanwhile). Option 3 conflates linking trust with verification and reopens the takeover WU-601 closed.
**Assumption taken in WU-602:** behaviour as in option 1; nothing in WU-602 depends on the answer.

## Q9 — SSRF guard for the "Test discovery" button (WU-603)

**Context:** `idp.discover` (platform admins only, permission `platform.idp`) fetches `<issuer>/.well-known/openid-configuration` and reports the endpoints it found. The existing SSRF guard (`action.isPrivateHost`, used for MCP endpoint URLs) rejects loopback and every private range. Self-hosted IdPs (Keycloak, authentik, Zitadel) commonly sit on the operator's private network, so that guard would make the button useless for exactly the providers that most need testing. The login registry itself already fetches discovery from whatever issuer the admin configures, with no guard.

**Assumption taken in WU-603:** discovery uses the IdP client (10 s, 1 MiB, no redirects) over a dialer whose `Control` hook checks the address actually dialled (after DNS, so no rebinding) and refuses link-local (including `169.254.169.254` cloud metadata), multicast, unspecified and `fd00:ec2::254`. Private and loopback addresses are allowed. Only the parsed endpoint URLs from a document whose `issuer` matches are shown; failures show a reference code and the upstream error is only logged. Rationale: platform admins already control which hosts the server talks to for sign-in, so blocking private ranges here adds no protection against them, while metadata endpoints stay out of reach.

**Options:** (a) keep this; (b) apply the full private-range block and add an operator allow-list (`BC_IDP_ALLOW_PRIVATE=1` or CIDRs); (c) apply the same link-local guard to the registry's own discovery/JWKS/token traffic for consistency.
**Recommendation:** (a) now plus (c) in WU-614's hardening pass.
**Answer:** (orchestrator decision 2026-10-03, flagged to the product owner) An unverified email may still **create** an identity when (1) the flow carries a valid invite token for that email (possession of the invite is the proof; the invite email is used), or (2) the provider is org-owned, JIT is on and the email domain is verified for that org (the org vouches for its own IdP). Linking an unseen identity to an **existing** user by email still requires `EmailVerified` and `trust_email`. Implemented in WU-604.

## Q10 — Platform-scope permission is evaluated against a caller-supplied org (found in WU-603)

**Context:** `perm.CheckerAdapter.Allow` passes `ac.Org` through for every action. For a `ScopePlatform` action, `DBScopeResolver` checks nothing, so a caller who sends `X-Org-Id` (or an `org_id` input field, which `web.handleAction` copies into `Opts.Org`) has the permission checked against **that org's** grants instead of the platform org's. An org Owner holds `*` in their own org, so they pass the check for any platform action reachable through `/api/action/*` or `/api/v1/actions/*` (for example `provider.create`, `pricing.upsert`, `org.create`). Some platform-scope actions (`user.theme.update`, `session.revoke`, `notif.*`) appear to rely on this to work for ordinary users at all.

**Mitigation in WU-603:** every `idp.*` handler refuses a call that carries an org/team/project id (`idp.platformOnly`), with a test that an org Owner passing their own org id is refused.

**Options:** (a) in `DBScopeResolver`, refuse a tenant id on `ScopePlatform` actions and move the per-user actions (`user.*`, `session.revoke`, `notif.*`) to a new `ScopeSelf` that needs no grant; (b) in `CheckerAdapter`, always evaluate `ScopePlatform` against the platform org and grant the per-user actions to everyone explicitly.
**Recommendation:** (a), as its own security WU before Phase 7 merges.
**Answer:** (a), as WU-603a on `feat/iam` before WU-604 (orchestrator decision 2026-10-03, flagged to the product owner).

## Q11 — SSRF guard for organisation-owned identity providers (WU-607)

**Context:** Q9 let platform admins point discovery at private and loopback addresses, because they already control which hosts the server talks to. WU-607 lets **org owners** configure identity providers too. An org owner is a tenant, not an operator: allowing their issuer URL to resolve to `10.x`, `127.0.0.1` or the operator's internal services would let any org owner probe the server's private network (the "Test discovery" button reports success or failure, and the login flow fetches discovery, JWKS and token endpoints).

**Decision taken in WU-607 (non-blocking):** every outbound request for an org-owned provider (registry discovery, JWKS, token, userinfo, and `org.idp.discover`) goes through `idp.NewOrgIdPClient`: no proxy, and a dial-time check on the resolved address (so DNS cannot rebind past it) that refuses link-local/metadata, multicast and unspecified (as Q9) **plus loopback, RFC 1918/ULA private, 100.64/10 and 0/8**. Operators whose tenants run IdPs on the private network set `BC_ORG_IDP_ALLOW_PRIVATE=true` (default false), which relaxes it to the Q9 platform guard. Platform providers keep Q9's behaviour.

**Options:** (a) keep this; (b) replace the boolean with a CIDR allow-list (`BC_ORG_IDP_ALLOW_CIDRS`) so operators can open one subnet rather than all private space; (c) per-org override set by a platform admin.
**Recommendation:** (a) now; (b) if an operator asks for it.
**Answer:**

## Q12 — Group sync when a membership already exists at the mapped resource (WU-608)

**Context:** SPEC §7.5 says sync reconciles only `source='idp'` memberships and never touches `manual|invite|jit` ones. The `memberships` table allows one membership per user per resource (`UNIQUE(org_id, actor_id, actor_type, resource_type, resource_id)`), so when a mapping targets a resource where the user already holds a non-idp membership, sync cannot add a second one. Separately, an IdP that stops sending the group claim (misconfiguration, or Entra omitting `groups` for a user with none) looks the same as "member of no groups".

**Decision taken in WU-608 (non-blocking):** (1) the existing non-idp membership wins: sync leaves it and its role alone and reports the mapping as `kept` in the `membership.synced` result; an admin who wants sync to manage that resource removes the manual membership. JIT likewise only adds its default org membership when the user has no org-level membership after sync, so an org-scope mapping and JIT never fight. (2) When several mappings target the same resource with different roles, the oldest mapping wins (deterministic; grants are not merged into a synthetic role). (3) As first built, an absent group claim was treated as an empty group list, so sync removed every `idp` membership. **Changed in WU-609 (orchestrator decision, option (b)):** an absent claim skips reconciliation entirely (INFO log, no audit); a present but empty claim still removes every `idp` membership. Entra's groups overage (`_claim_names` naming `groups` or the configured claim, or `hasgroups: true`) also skips sync, with a WARN log and an org audit row `membership.sync_skipped` (`reason: groups_overage`). Consequence: a user removed from their last group keeps their `idp` memberships if the IdP then omits the claim rather than sending it empty; such IdPs need SCIM (WU-611) for removals.

**Options:** for (1), (a) keep; (b) let idp upgrade a manual membership to the mapped role (would change a manual grant, which §7.5 forbids). For (3), (a) keep; (b) skip reconciliation when the claim is absent (safer against misconfiguration, but a user removed from their last group would keep access).
**Recommendation:** (a) for both.
**Answer:** (3): option (b), per the WU-609 brief (orchestrator, 2026-10-04); implemented in WU-609. (1) and (2): no answer yet; the WU-608 behaviour stands.

## Q13 — SAML email verification comes from `trust_email` (WU-610)

**Context:** SAML assertions carry no "email verified" flag. The WU-610 brief said to treat a SAML provider's email as verified only when the provider's `trust_email` is set. That is Q8's option 3, which Q8 recommended against for OIDC because it ties linking trust to verification.

**Decision taken in WU-610 (non-blocking, per the brief):** `EmailVerified = email present && trust_email`. An untrusted SAML provider's email is never verified, so it can't link by email or sign up by open sign-up or bootstrap. Invites and org JIT on verified domains still work, as Q8's answer allows for unverified emails. A trusted provider links by email under §7.3, and org-owned providers link only on the org's verified domains. The admin form says this in plain words.

**Options:** (a) keep; (b) add a separate per-provider "emails are verified" flag for SAML, so trust (linking) and verification (sign-up) can be set independently.
**Recommendation:** (a). For SAML the admin who configures the IdP is the only possible source of verification, so a second flag adds a setting without adding safety.
**Answer:**

## Q14 — SCIM groups and sign-in group sync for the same user (WU-611)

**Context:** SPEC §7.5 lets both sign-in group sync (the assertion's groups, provider-specific plus org-wide mappings) and SCIM group changes (SCIM group display names, org-wide mappings only) reconcile a user's `source='idp'` memberships. If both run for one user they fight: an IdP that sends no or different groups in its tokens would strip at every sign-in what SCIM granted, and SCIM would put it back at its next push. Separately, a SCIM user that the IdP deactivated could get a JIT membership back by signing in, and an org IdP that is not trusted for email could never sign in a person SCIM created (unseen identity, existing email, so §7.3 step 3 refuses and JIT never links).

**Decision taken in WU-611 (non-blocking):** per user, not per org. (1) A user with a `scim_users` row in the org (active or not) is SCIM-managed there: sign-in through the org's providers skips group sync and JIT for that org (INFO log); their `idp` memberships follow their SCIM groups only. Users the IdP does not provision by SCIM keep sign-in sync, even when the org has an active SCIM token. (2) Provisioning by the org on its own verified domain is JIT-level trust: an unseen identity from one of the org's own providers links to an existing user when the email's domain is verified for that org and the user has an **active** `scim_users` row there, whatever `trust_email`/`email_verified` say (audit `identity.linked_by_email` with `via: scim`). (3) SCIM creates a platform user only for an address no account uses; an existing account is linked only on the org's verified domains, otherwise 409 (`users.email` is unique, and linking would hand another account to the org).

**Options:** (a) keep per-user; (b) per org: when the org has an active SCIM token, skip sign-in group sync for everyone in it (simpler to explain, but users outside the SCIM assignment lose sign-in sync); (c) merge: reconcile from the union of SCIM groups and assertion groups (no fight, but removal from either source never removes access while the other still lists it).
**Recommendation:** (a).
**Answer:**
