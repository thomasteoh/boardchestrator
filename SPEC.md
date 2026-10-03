# Boardchestrator — Technical Specification

**Status:** v1, governs implementation. PRD.md governs scope; if they conflict, PRD wins and the conflict goes in QUESTIONS.md.
**Reading order for workers:** WORKER.md → this file (§1–§5 always; the domain section for your work unit) → BACKLOG.md.

---

## 1. Architecture Overview

One Go binary. One SQLite database. Everything embedded.

```
                       ┌────────────────────────────────────────────┐
 Browser (templ/HTMX) ─┤                                            │
 REST client ──────────┤  chi router → middleware → handlers        │
 MCP client ───────────┤        │                                   │
                       │        ▼                                   │
                       │  ACTION DISPATCH (internal/action)         │
                       │  authn → tenant scope → permission →       │
                       │  approval gate → execute → event → audit   │
                       │        │                        │          │
 Agent tool loop ──────┤────────┘                        ▼          │
 (internal/agentrt)    │                          event bus         │
                       │                     ┌──────┼──────┬─────┐  │
                       │                    SSE  notify  webhook activity
                       │                                            │
                       │  sqlc data layer (org-scoped) → SQLite WAL │
                       └────────────────────────────────────────────┘
```

Rules that must never be violated:

1. **All mutations go through action dispatch.** Handlers never write to the DB directly. Reads may use the data layer directly but must pass an org scope.
2. **The data layer requires scope.** Every sqlc query touching tenant data takes an `org_id` (and narrower ids where relevant) parameter. A CI grep-gate (`make check-scope`) fails on tenant-table queries without it.
3. **Actors are polymorphic.** `Actor{Type: user|agent|apikey, ID}` flows through dispatch; nothing downstream may assume a human.

## 2. Repository Layout

```
cmd/bc/                 main; subcommands: serve, backup, gen-key
internal/config/        env loading (BC_*), validation
internal/server/        chi router assembly, middleware (reqid, log, recover, csrf, csp, session)
internal/db/            sqlite open (WAL, foreign_keys, busy_timeout), embedded migrations, sqlc out
internal/action/        registry, dispatch pipeline, impact classes, idempotency, dry-run
internal/event/         in-process event bus, typed events
internal/perm/          permission engine, role resolution
internal/auth/          oauth (google oidc, github), sessions, api keys, bootstrap
internal/tenant/        orgs, teams, projects, memberships, roles, invites, org settings, audit log
internal/task/          tasks, labels, relations, custom fields, comments, sprints, boards, filters,
                        templates, recurring, archive, activity
internal/storage/       attachment backend interface; local/, s3/
internal/notify/        notification engine + prefs
internal/sse/           per-user/per-project SSE hub
internal/search/        FTS5 index maintenance + query
internal/agentrt/       providers, agents, skills, job queue, runs, tool loop, approvals, cost
internal/chat/          chat sessions, streaming
internal/restapi/       /api/v1 from registry, OpenAPI generation
internal/mcp/           /mcp streamable HTTP server from registry
internal/ghub/          github oauth link, inbound webhooks, PR↔task transitions
internal/wiki/          go-git checkout cache, render, edit-commit, history
internal/report/        burndown, cycle time, agent usage, CSV export
internal/web/           handlers + templ views (views/), static assets (static/: vendored htmx,
                        alpine, sortablejs, mermaid; app.css tokens; sw.js; manifest)
migrations/             NNNN_name.up.sql / .down.sql (append-only once merged)
```

## 3. Conventions

- **Go**: latest stable; `gofmt`; `golangci-lint` (default set + errcheck, gosec); wrap errors with `%w`; no panics in request paths; context first arg everywhere.
- **IDs**: 16-byte random, hex-encoded TEXT primary keys (portable, no autoincrement leakage). Task numbers are per-project sequences (§5, `projects.next_task_num`) presented as `KEY-<n>`.
- **Time**: store UTC ISO-8601 TEXT (`strftime('%Y-%m-%dT%H:%M:%fZ')`-compatible); render in the user's timezone.
- **Migrations**: append-only after merge to main; every up has a down; no data-destructive downs.
- **templ/HTMX**: pages are full templ layouts; HTMX endpoints return partial templ components. Use `hx-boost` for nav, explicit `hx-*` for interactions. All state-changing requests carry the CSRF token (hx-headers on `<body>`). SSE via native `EventSource` in a small vendored JS helper; server sends named events (`task-updated`, `notification`, `chat-delta`, `run-status`).
- **JS policy**: Alpine for local component state; no build step, no npm. Vendored libs pinned by version in `internal/web/static/vendor/`.
- **CSS**: single `app.css`, design tokens as custom properties (`--bc-*`), `data-theme` attribute for dark/light, mobile-first with breakpoints 640/1024.
- **UI copy**: Australian English (organisation, customisable, colour).
- **Testing**: table-driven unit tests; handler tests with `httptest` against a real temp-file SQLite with migrations applied (helper in `internal/db/dbtest`); no mocking the DB. Race detector always on in CI.
- **Make targets**: `make gen` (templ + sqlc), `make check` (gen + git-diff-clean check, gofmt check, vet, golangci-lint, check-scope, `go test -race ./...`), `make dev` (serve with local .env), `make build`.
- **Commits**: `WU-NNN: imperative summary` (one WU per commit unless a WU explicitly allows more).

## 4. Action Registry (internal/action)

```go
type Impact int // ImpactRead, ImpactLow, ImpactHigh

type Definition struct {
    Name       string            // "task.create" — stable, never renamed
    Impact     Impact
    Permission string            // perm key checked against actor's effective grants
    Scope      ScopeKind         // platform|org|team|project — what id the input must carry
    Input      *Schema           // JSON schema (compiled once)
    Output     *Schema
    Handle     HandlerFunc       // func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error)
    Preview    HandlerFunc       // optional; nil ⇒ dry-run returns validated input echo
}

type ActionCtx struct {
    Actor    Actor              // user | agent | apikey (with owning user)
    Org, Team, Project string   // resolved scope ids ("" where n/a)
    DryRun   bool
    Idem     string             // idempotency key ("" = none)
}
```

- `Register(def)` at package init; duplicate names panic at startup.
- `Dispatch(ctx, actorRef, name, input, opts)` runs: resolve actor → validate input schema → resolve+verify scope (ids exist, actor is member) → permission check → **approval gate**: if actor is an agent and its policy for `def.Impact` is `require-approval`, persist an `approvals` row and return `ErrApprovalPending{ID}`; `forbid` returns `ErrForbidden` → idempotency check (return stored result on hit) → execute in a tx → store idempotent result → emit `event.Event{Name, Org, Actor, Subject, Payload}` → append audit row for ImpactHigh (all actors) and all agent actions.
- **Derivation surfaces** (REST §11, MCP §12, agent tools §10) iterate `action.All()`; they never hand-register endpoints for registered actions.
- Approval resume: `approval.decide(id, approve|reject)` (itself an action, ImpactHigh) re-dispatches the stored call as the original agent actor with the gate satisfied, then wakes the owning run.

Action naming: `<resource>.<verb>`: `org.create`, `team.update`, `project.archive`, `member.invite`, `member.remove`, `role.create`, `role.assign`, `task.create/update/move/assign/label/relate/archive`, `comment.create/update/delete`, `sprint.create/update/close`, `label.create`, `filter.save`, `attachment.upload/delete`, `agent.create/update`, `skill.create/import/attach`, `run.cancel`, `approval.decide`, `wiki.edit`, `webhook.create`, `apikey.create/revoke`, `search.query` (read), `notification.markread`, `settings.update` per scope.

## 5. Data Model

Compact notation: `table(col…)`; all tables carrying tenant data include `org_id` even when reachable via joins (denormalised on purpose for the scope gate). PKs are `id TEXT` unless noted. Encrypted columns end `_enc` (AES-GCM via `BC_SECRET_KEY`).

**Identity & access**
```
users(id, email UNIQUE, name, avatar_url, theme, timezone, created_at, deleted_at)
identities(id, user_id, provider, subject, email, token_enc, UNIQUE(provider,subject))
sessions(token_hash PK, user_id, ip, ua, created_at, last_seen_at, expires_at)
api_keys(id, user_id, name, prefix, key_hash, scope_json, last_used_at, revoked_at, created_at)
platform_settings(id=1, context, bootstrap_done, settings_json)        -- settings: passkeys_enabled
auth_providers(id, org_id NULL, kind, preset, display_name, enabled, managed_by, issuer,
               client_id, client_secret_enc, scopes, claim_map_json, trust_email,
               allow_signup, allowed_tenants_json, saml_metadata_url, saml_metadata_xml,
               sp_key_enc, sp_cert, position, created_at, updated_at)     -- kind: oidc|github|saml; managed_by: ui|env
-- identities += last_login_at; sessions += provider_id, auth_method, idp_sid, idp_subject, id_token_enc
-- api_keys += expires_at; memberships += source (manual|invite|jit|idp|scim)
org_domains(id, org_id, domain, verify_token, verified_at, created_at,
            UNIQUE(org_id,domain))                                      -- + UNIQUE(domain) WHERE verified_at IS NOT NULL
org_sso_settings(org_id PK, enforce_sso, jit_enabled, jit_default_role_id, group_claim, group_sync)
idp_group_mappings(id, org_id, provider_id NULL, group_value, role_id, resource_type, resource_id,
                   created_at)            -- UNIQUE(org_id, COALESCE(provider_id,''), group_value, resource_type, resource_id)
scim_tokens(id, org_id, name, prefix UNIQUE, token_hash, created_by, expires_at, last_used_at, revoked_at, created_at)
scim_users(id, org_id, user_id, external_id, user_name, email, given_name, family_name, display_name, active,
           created_at, updated_at)   -- UNIQUE(org_id, lower(user_name)), UNIQUE(org_id, user_id)
scim_groups(id, org_id, external_id, display_name, created_at, updated_at)
scim_group_members(group_id, user_id, org_id, PK(group_id,user_id))
webauthn_credentials(id, user_id, credential_id UNIQUE, public_key, sign_count, aaguid,
                     transports_json, name, created_at, last_used_at)
```

**Tenancy**
```
orgs(id, name, slug UNIQUE, context, settings_json, created_at)         -- settings: attachment limits, spend cap
org_secrets(org_id, kind, value_enc)                                    -- s3 creds, etc.
teams(id, org_id, name, context, created_at)
projects(id, org_id, team_id, key, name, context, visibility, swimlane_json,
         next_task_num INT, archived_at, UNIQUE(org_id,key))
roles(id, org_id NULL, name, permissions_json, system BOOL)             -- org_id NULL = platform default
memberships(id, org_id, scope_type, scope_id, actor_type, actor_id, role_id,
            UNIQUE(scope_type,scope_id,actor_type,actor_id))            -- actor_type: user|agent
invites(id, org_id, email, role_id, token_hash, invited_by, expires_at, accepted_at)
audit_log(id, org_id NULL, actor_type, actor_id, action, subject, detail_json, ip, created_at)
idempotency_keys(key PK, actor, action, result_json, created_at)
```

**Tasks & boards**
```
tasks(id, org_id, project_id, num INT, title, description, state, priority, points,
      due_date, sprint_id NULL, position REAL, archived_at, created_by, created_at,
      updated_at, UNIQUE(project_id,num))
task_assignees(task_id, user_id) ; task_watchers(task_id, user_id)
labels(id, org_id, name, colour) ; task_labels(task_id, label_id)
task_relations(id, org_id, from_task, to_task, kind)                    -- blocks|relates|duplicates
custom_field_defs(id, project_id, org_id, name, kind, options_json, position)
custom_field_values(task_id, field_id, value, PK(task_id,field_id))
comments(id, org_id, task_id, author_type, author_id, body, edited_at, deleted_at, created_at)
task_activity(id, org_id, task_id, actor_type, actor_id, kind, detail_json, created_at)
attachments(id, org_id, task_id, uploader_id, filename, mime, size, storage_key, created_at)
sprints(id, org_id, project_id, name, starts_on, ends_on, state)
board_columns(id, org_id, project_id, name, colour, position, wip_limit, state,
              move_roles_json NULL, trigger_agent_id NULL, trigger_prompt NULL)
saved_filters(id, org_id, project_id, owner_id, name, query_json, shared BOOL, pinned BOOL)
task_templates(id, org_id, project_id, name, template_json)
recurring_rules(id, org_id, project_id, template_id, cron, next_at, active)
```

**Notify / integrate**
```
notifications(id, org_id, user_id, kind, actor_type, actor_id, subject_kind, subject_id,
              body, read_at, created_at)
notification_prefs(user_id, kind, enabled, PK(user_id,kind))
webhooks(id, org_id, team_id NULL, url, secret_enc, events_json, active)
webhook_deliveries(id, webhook_id, event_json, attempts, status, last_code, next_retry_at)
github_links(id, org_id, task_id, kind, repo, ref, url, state, UNIQUE(task_id,url))
project_github(project_id PK, org_id, repo, transitions_json, webhook_secret_enc)
```

**Agent runtime**
```
providers(id, kind, name, base_url, api_key_enc, models_json, created_at)   -- kind: openai_compat|codex_sso
provider_orgs(provider_id, org_id)
agents(id, org_id NULL, template_id NULL, name, provider_id, model, context,
       role_id, retry_max, backoff_secs, runs_per_hour, token_budget,
       approval_policy_json, active, UNIQUE(org_id,name))                    -- org_id NULL = platform template
skills(id, org_id NULL, name, version INT, description, instructions,
       allowed_actions_json, param_schema_json, mcp_endpoints_enc, created_at)
agent_skills(agent_id, skill_id)
jobs(id, kind, payload_json, run_at, attempts, max_attempts, status, locked_by, locked_at)
runs(id, org_id, agent_id, trigger, task_id NULL, chat_session_id NULL, initiated_by NULL,
     status, error, prompt_tokens INT, completion_tokens INT, created_at, started_at, finished_at)
     -- status: queued|running|awaiting_approval|succeeded|failed|cancelled
run_steps(id, run_id, seq INT, kind, request_json, response_json, tokens INT, created_at)
approvals(id, org_id, run_id, action_name, input_json, status, requested_at,
          decided_by NULL, decided_at NULL)
chat_sessions(id, org_id, user_id, scope_type, scope_id, agent_id, created_at)
chat_messages(id, session_id, role, content, cards_json, run_id NULL, created_at)
scheduled_triggers(id, org_id, project_id, agent_id, cron, prompt, next_at, active)
```

**Wiki & search**
```
wiki_configs(project_id PK, org_id, repo_url, ref, path, updated_by, updated_at)
search_index  -- FTS5: (kind, org_id UNINDEXED, ref UNINDEXED, title, body); app-maintained
```

## 6. Permission Engine (internal/perm)

- A permission is a string key = action name (plus a few UI-only reads like `report.view`).
- Roles carry `permissions_json` (list, `*` wildcard suffix allowed: `task.*`).
- Resolution for actor A on scope S: gather memberships for A on S and S's ancestors (project → team → org); union grants; nearest-scope membership wins where roles conflict is unnecessary — grants are additive; absence = deny.
- Agents: effective = role grants ∩ union of attached skills' `allowed_actions`.
- Column move restriction: `board_columns.move_roles_json` checked inside `task.move`.
- Seeded system roles per PRD table; system roles are copy-on-edit (editing creates an org-owned copy).

## 7. Identity & Auth (internal/auth, internal/auth/…)

PRD §4 governs scope. Packages: `internal/auth` (sessions, CSRF, flow cookie, login resolution, handlers), `internal/auth/idp` (provider registry, presets, OIDC/GitHub/SAML connectors), `internal/auth/scim`, `internal/auth/passkey`, `internal/auth/oidctest` (in-process fake OIDC IdP for tests: discovery, JWKS, authorize, token, end_session; signs RS256 ID/logout tokens with a test key; supports claim overrides and misbehaviours such as wrong `aud`/`iss`/`nonce`, expired, unsigned/`alg:none`).

### 7.1 Provider registry

- `auth_providers` rows (§5) are the single source; env vars **seed/upsert** rows with `managed_by='env'` at startup (`BC_GOOGLE_CLIENT_ID/SECRET` → id `google`, `BC_GITHUB_CLIENT_ID/SECRET` → id `github`, `BC_OIDC_<NAME>_ISSUER/_CLIENT_ID/_CLIENT_SECRET/_PRESET/_DISPLAY_NAME/_TRUST_EMAIL/_ALLOW_SIGNUP` → id `<name>` lower-cased). Env-managed rows are read-only in the UI. Ids `google`/`github` match existing `identities.provider` values, so no identity migration is needed.
- `idp.Registry` loads enabled rows, builds a connector per row, and caches it (invalidate on any `idp.*` action via the event bus). OIDC discovery is lazy and cached with a 1 h TTL; discovery failure fails only that provider's login, never startup.
- **Presets** (`internal/auth/idp/presets.go`) are data, not code paths: issuer template, default scopes, claim map (`email`, `email_verified`, `name`, `picture`, `groups`), `trust_email` default, logout support, docs URL. Google (`https://accounts.google.com`, trust), Microsoft (`https://login.microsoftonline.com/{tenant}/v2.0`; `{tenant}` may be `organizations`/`common` → multi-tenant mode: skip go-oidc's issuer check and require `iss == "https://login.microsoftonline.com/" + tid + "/v2.0"`, optional allowed-tenant list; no trust), GitLab (`https://gitlab.com` or self-hosted; trust), Okta, Auth0, Keycloak (`…/realms/<realm>`), Zitadel, Authentik (`…/application/o/<slug>/`), Generic (no trust). All presets except GitHub are plain OIDC underneath.
- **Connector interface:** `Begin(ctx, flow *Flow) (redirectURL string, err error)` and `Complete(ctx, r *http.Request, flow *Flow) (*Assertion, error)`. `Assertion{ProviderID, Subject, Email, EmailVerified, Name, Picture, Groups []string, SID, IDTokenRaw, RawClaims map}`. OIDC uses `github.com/coreos/go-oidc/v3` + `x/oauth2` with PKCE (`oauth2.GenerateVerifier`/`S256ChallengeOption`), nonce, and `oidc.IDTokenVerifier` (signature, `iss`, `aud`, `exp`); userinfo fetched only to fill missing claims and its `sub` must equal the ID token `sub`. GitHub sends credentials in the POST body (never the URL) and uses `/user` + `/user/emails`. All outbound IdP HTTP uses a client with 10 s timeout and `io.LimitReader` (1 MiB).
- Errors from connectors are logged with the request id and rendered as a generic login-failed page with a reference code; **internal error strings are never reflected** to the client.

### 7.2 Login flow & flow cookie

- Routes: `GET /login` (page), `GET /auth/{providerID}` (begin; `?return_to=` relative path only, `?login_hint=`), `GET /auth/{providerID}/callback` (OIDC/GitHub), `POST /auth/saml/{providerID}/acs`, `GET /auth/saml/{providerID}/metadata`, `GET|POST /auth/saml/{providerID}/slo`, `GET /auth/saml/{providerID}/certificate`, `GET /auth/saml/{providerID}/link` (WU-610), `POST /auth/logout`, `POST /auth/oidc/{providerID}/backchannel-logout`, `GET /auth/sso/discover?email=` (home-realm discovery), passkey routes under `/auth/passkey/*`. `/auth/google/callback` and `/auth/github/callback` keep working because they are just provider ids.
- **Flow cookie** `__Host-bc_flow`: AES-GCM sealed (key derived from `BC_SECRET_KEY` with a distinct HKDF info label, `bc-auth-flow`), Secure, HttpOnly, Path=/, Max-Age 600. Payload: `{state, nonce, pkce_verifier, provider_id, return_to, intent: login|link|bootstrap, link_session_hash?, bootstrap: bool, saml_request_id?, webauthn_session?, exp}`. The callback requires `state` from the query to equal the cookie's `state` and the provider id to match; the cookie is cleared on every callback outcome. No server-side map. **SameSite=Lax** for OIDC/GitHub (top-level GET callbacks); **SameSite=None** only for SAML flows, because the ACS is a cross-site POST.
- Session cookies are always `Secure`; there is no production `Insecure` switch (browsers treat `http://localhost` as a secure context). The test seam stays test-only.

### 7.3 Login resolution (`auth.Resolve`)

Given an `Assertion` and the flow:
1. **Identity hit:** `identities(provider, subject)` → user. Deleted user ⇒ refuse. Update `identities.email`, `last_login_at`; refresh name/avatar only if the user has not edited them.
2. **Link intent:** the flow's `link_session_hash` must still resolve to a live session; attach identity to that session's user (refuse if the identity belongs to someone else).
3. **Email link:** if `EmailVerified` and provider `trust_email` (and, for org-owned providers, the email domain is one of that org's verified domains) and a user exists with that email ⇒ link + audit `identity.linked_by_email`.
4. **Sign-up:** allowed iff provider `allow_signup`, or a pending unexpired invite exists for the email, or org JIT applies (§7.5), or the flow is a bootstrap claim. Else refuse ("no account for this email; ask an admin for an invite").
5. Bootstrap (`platform_settings.bootstrap_done=0`): only `BC_ADMIN_EMAILS` members or a flow that presented `BC_BOOTSTRAP_TOKEN` at `GET /setup?token=` (constant-time compare; token printed to log at startup while unclaimed) may sign in; success grants the platform-owner membership and sets `bootstrap_done`.
6. Session: revoke any session presented in the request cookie (rotation), create a new one recording `provider_id`, `auth_method` (`oidc|github|saml|passkey`), `idp_sid`, `idp_subject`, and `id_token_enc` (for RP-initiated logout hint). Audit `auth.login` (success) / `auth.login_failed` (reason code, no secrets).

All writes in resolution go through internal (non-registered) functions in one transaction; they are authentication events, not actions, but write audit rows directly with `actor_type='user'` (or `'anonymous'` for failures).

### 7.4 Organisation SSO

- `org_domains`: `org.domain.add` returns a TXT record `_boardchestrator-challenge.<domain> = bc-verify=<token>`; `org.domain.verify` resolves it (resolver injectable for tests, 5 s timeout). A domain may be verified by only one org. Any number of orgs may hold a **pending** claim on a domain (unique per org; unique across orgs only once verified, via a partial unique index), so a squatter's unverified claim never blocks the real owner; once verified, add and verify by any other org are refused. Domains are stored normalised: lower-case, IDNA A-labels, no trailing dot; IP addresses, single-label names and public suffixes are refused. Discovery matches the email's domain exactly (a verified `example.com` does not cover `eng.example.com`).
- Org-owned providers are `auth_providers` rows with `org_id` set, managed by the `ScopeOrg` actions `org.idp.list|get|create|update|delete|enable|disable|discover` (permission `org.sso`; amended in WU-607, because dispatch refuses an org id on the platform-scope `idp.*` actions). Platform admins manage `org_id IS NULL` rows with `idp.*` (permission `platform.idp`). Org providers are OIDC or SAML (SAML since WU-610; GitHub OAuth is not an org IdP), their ids are global and must start with `<org slug>-`, `allow_signup` is always 0, and they can never claim `BC_ADMIN_EMAILS` platform admin. Their outbound traffic (login and `org.idp.discover`) refuses private and loopback addresses unless `BC_ORG_IDP_ALLOW_PRIVATE` (Q11).
- `org_sso_settings(org_id PK, enforce_sso, jit_enabled, jit_default_role_id, group_claim, group_sync)`. **Enforcement** lives in dispatch scope verification: for a `user` actor on an org with `enforce_sso=1`, `Actor.AuthProviderID` (copied from the session) must be one of the org's enabled providers, else `ErrSSORequired{OrgID, Providers}` (matches `ErrForbidden`) which the web layer renders as "This organisation requires single sign-on" with a link to `/auth/{provider}?return_to=`. It applies only to members of the org (non-members are refused by the permission check without learning the policy). Platform owners are exempt everywhere (break-glass). Platform admins acting at platform scope are unaffected. API-key and agent actors are unaffected. The same check (`action.CheckOrgSSO`) gates session requests to org pages (`/app/org/{id}/…`, `/app/project/{id}/…`, `/api/project/{id}/…`), attachment downloads, and search results. `org.sso.update` refuses turning enforcement on unless the org has an enabled provider and the caller's own session was signed in through one; the last enabled provider cannot be disabled or deleted while enforcement is on.
- **Home-realm discovery:** `GET /auth/sso/discover?email=` → if the domain is verified by an org with an enabled provider, redirect to `/auth/{providerID}?login_hint=<email>` (the org's first provider in display order; `return_to` and `invite` carried over); otherwise re-render the login page with a neutral message (do not disclose whether the domain is registered beyond what the redirect implies). It is a GET (changed from POST in WU-606) because it changes no state and so needs no CSRF exemption (§7.11), and a hit puts the address in the `/auth/{id}?login_hint=` URL anyway; the request log records paths, not query strings. It is under the `/auth/*` rate limit.

### 7.5 JIT provisioning & group mapping

- JIT applies when the assertion came from an org-owned provider with `jit_enabled`, the email domain is verified for that org, and no user exists: create user + org membership (`source='jit'`) with `jit_default_role_id`.
- `idp_group_mappings(org_id, provider_id NULL, group_value, role_id, resource_type, resource_id)`. On every sign-in through a provider of that org (and on SCIM group changes), compute the desired set of `(resource, role)` from the user's groups and reconcile **only memberships with `source='idp'`**: insert missing, delete stale. Memberships with `source` `manual|invite|jit` are never removed by sync. Reconciliation emits `membership.synced` events and audit rows.
- As built (WU-608): JIT also adds the default org membership for an **existing** user who signs in through the org's provider with an address on the org's verified domains and holds no org-level membership there; JIT never links an unseen identity to an existing user (only step 3 does). The default role must be usable in the org and may not be the Owner role or any role granting `*` (checked on save and again at sign-in). Settings live in `org.sso.update` (`jit_enabled`, `jit_default_role_id`, `group_claim`, `group_sync`); mappings are managed by `org.idp_mapping.list|create|delete` (`ScopeOrg`, `org.sso`). Mappings with `provider_id` NULL apply to all the org's providers; `group_claim` (when set) replaces the provider's claim-map `groups` path. Sync runs only when `group_sync=1`, inside the login transaction, and never for platform providers or the platform org. Where a non-idp membership already holds a mapped resource it is left alone (Q12); several mappings onto one resource: the oldest wins. Amended in WU-609 (Q12): a group claim that is **absent** from the assertion skips reconciliation entirely (INFO log, no audit), while a present but empty claim still means "no groups" and removes every `idp` membership; an Entra **groups overage** (`_claim_names` naming `groups` or the configured claim, or `hasgroups: true`) also skips it, with a WARN log and an org audit row `membership.sync_skipped` (`reason: groups_overage`). Audit rows: `auth.signup` (method `jit`), `membership.jit`, `membership.synced` (org-scoped, ids only).

### 7.6 Logout

- `POST /auth/logout` (CSRF-protected): revoke session, clear cookie; if the session's provider has an `end_session_endpoint` (OIDC) or SLO URL (SAML), redirect there with `id_token_hint`, `post_logout_redirect_uri=<BASE_URL>/login?signed_out=1`, `state`; else redirect to `/login?signed_out=1`.
- **Back-channel logout** (OIDC Back-Channel Logout 1.0): verify `logout_token` with the provider's verifier (signature, `iss`, `aud`, `iat` within 5 min, `events` contains `http://schemas.openid.net/event/backchannel-logout`, `sid` or `sub` present, **no** `nonce`); reject `jti` replays (in-memory TTL cache). Revoke sessions by `(provider_id, idp_sid)` or `(provider_id, idp_subject)`. Respond 200 with `Cache-Control: no-store`; 400 on any failure.
- As built (WU-609): RP-initiated logout is per provider (`auth_providers.idp_logout`, "Sign out of the identity provider too", default = the preset's logout support; never for GitHub) and only for a live session whose sealed ID token decrypts and whose provider is still enabled; anything else falls back to the local redirect. The request carries `id_token_hint`, `client_id`, `post_logout_redirect_uri` and a random `state`. The provider forms show the post-logout redirect URI and the back-channel URI to register. Back-channel logout also requires `jti`, checks `exp` only when present, accepts a JOSE `typ` of absent/`JWT`/`logout+jwt`, and when both `sid` and `sub` are present revokes only sessions matching both. Failures answer 400 `{"error":"invalid_request"}` with no detail. The jti cache is bounded and fails closed when full of live entries. Audit `auth.backchannel_logout` (`actor_type='service'`, `actor_id='idp:<provider>'`, revoked count; in the org's log for an org-owned provider).
- SAML SLO: SP-initiated redirect to the IdP SLO URL; IdP-initiated `LogoutRequest` at `/auth/saml/{id}/slo` revokes matching sessions and returns a `LogoutResponse`.

### 7.7 SAML 2.0

- Library `github.com/crewjam/saml` (SP primitives only, not `samlsp` middleware). Per-provider SP entity id `<BASE_URL>/auth/saml/{id}/metadata`, ACS `<BASE_URL>/auth/saml/{id}/acs`, SP signing/encryption key pair generated on create and stored `sp_key_enc`. IdP metadata from URL (fetched with the SSRF guard, cached) or pasted XML.
- Require signed assertions (or signed response), audience = SP entity id, `InResponseTo` = flow's `saml_request_id`, NotBefore/NotOnOrAfter with 2 min skew; reject IdP-initiated SSO (no unsolicited responses). Assertion ids are replay-cached until expiry. Attribute map in `claim_map_json` (defaults: NameID persistent as subject; email from `emailaddress`/`mail`; groups from `groups`/`memberOf`).
- As built (WU-610): crewjam/saml v0.5.1 with goxmldsig v1.6.1. A response must carry exactly one assertion, and at least one AudienceRestriction, all naming the SP. RelayState must equal the flow state. Subject is a persistent NameID unless `claim_map_json.subject` names an attribute or is `NameID` (any non-transient NameID is accepted). `EmailVerified` = email present and `trust_email` (Q13). Sessions record the NameID as `idp_subject`, the SessionIndex as `idp_sid`, and a sealed NameID/SessionIndex logout hint in `id_token_enc`. A link through SAML finishes at `GET /auth/saml/{id}/link` (sealed `__Host-bc_saml_link` cookie), because the cross-site ACS POST cannot see the Lax session cookie. `GET /auth/saml/{id}/certificate` serves the SP certificate. SLO messages are sent by HTTP-Redirect only. Received LogoutRequests must be signed (either binding).

### 7.8 SCIM 2.0 (RFC 7643/7644)

- Base `/scim/v2`; bearer **SCIM token** bound to one org (`scim_tokens`, SHA-256 hash, constant-time compare, prefix lookup like API keys). Endpoints: `ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `Users` (GET list with `filter=userName eq "…"`/`externalId eq "…"`, `startIndex`, `count`; GET/POST/PUT/PATCH/DELETE by id), `Groups` (same; PATCH add/remove/replace `members`). JSON `application/scim+json`; SCIM error envelope.
- Mapping: SCIM User ⇄ `users` + `scim_users(org_id, user_id, external_id, user_name, active)`; creating one creates/links the user by email (SCIM is trusted for the org's verified domains only; other emails create a user without linking) and an org membership `source='scim'`. `active=false` or DELETE ⇒ delete all of that user's memberships in the org, revoke their API keys for the org, and audit. SCIM Group ⇄ `scim_groups` + `scim_group_members`; group display names feed §7.5 mapping as group values.
- Tolerate known IdP quirks: Entra's `"active": "False"` strings and capitalised `op` values; Okta's PUT-only user updates.
- SCIM requests are not actions from an agent/user; they dispatch internal provisioning functions as `Actor{Type: service, ID: "scim:<token id>"}` scoped to the token's org, and every mutation writes an audit row.
- As built (WU-611): package `internal/auth/scim`, mounted by the server at `/scim/v2` and `/scim/v2/*`. Tokens are `bcscim_<12 hex prefix>_<64 hex secret>`; `scim_tokens` stores the prefix and the SHA-256 of the whole token, with optional `expires_at`. `scim.token.list` (Read) / `create` / `revoke` (High) are `ScopeOrg` actions with `org.sso`; create refuses agent and service actors and returns the token once: its result implements `action.SecretResult`, so dispatch stores, emits and audits only the redacted form (idempotent replays return it too). Auth: `Authorization: Bearer` (scheme case-insensitive), constant-time hash compare, revoked/expired refused, `last_used_at` touched at most once a minute; failures are 401 with `WWW-Authenticate: Bearer realm="scim"`. The API-key middleware skips `/scim/v2`. Responses are `application/scim+json` with `meta` and the RFC 7644 error envelope. Filters: `eq` and `pr` joined by `and`, parentheses, value paths (`emails[type eq "work"].value`), dotted sub-attributes, core schema URN prefixes; anything else is 400 `invalidFilter`; `startIndex`/`count` (max 200), `attributes`/`excludedAttributes` (top level). Unknown attributes and extension schemas (Entra's enterprise user) are accepted and ignored in POST/PUT/PATCH. A SCIM user's email is kept in `scim_users.email`; the platform account's `users.email` is set only when SCIM creates the account and never changed afterwards. Linking: an existing account (case-insensitive email) only when its domain is verified for the org, else 409 `uniqueness`; deleted accounts 409; one SCIM user per account per org. Membership: org-level `source='scim'` with the JIT default role when set and usable (never owner-equivalent), else the Member system role; an existing org-level membership of any source is kept. `active=false` or DELETE: delete every membership of the user in the org (any source), revoke their API keys bound to the org, and revoke their sessions only when they belong to no organisation any more (otherwise they would be signed out of the others); audit `scim.user.deactivated|deleted`, `membership.scim_removed`, `apikey.scim_revoked`, `session.scim_revoked`. Reactivation restores the SCIM membership and re-reconciles groups. Group changes reconcile each affected active user via `ReconcileIdPMemberships` (provider "" = org-wide mappings, groups = display names of the user's SCIM groups); renames re-reconcile all members. Sign-in interplay (Q14): SCIM-managed users skip sign-in group sync and JIT for that org, and an unseen identity from the org's own provider links to an active SCIM user on the org's verified domain. Rate limit 600/min burst 100 per token; failed authentications share a per-IP bucket of the same size.

### 7.9 Passkeys

- Library `github.com/go-webauthn/webauthn`. RP id = host of `BC_BASE_URL`, origin = `BC_BASE_URL`. Credentials in `webauthn_credentials`. Registration and login ceremonies keep `SessionData` in the flow cookie. Login uses discoverable credentials (usernameless). Platform setting `passkeys_enabled` (default on).
- First-method registration without an IdP: allowed only with a valid invite token (`/invite/{token}`) or the bootstrap token; creates the user, then the passkey. Users must keep at least one sign-in method.

### 7.10 Sessions & API keys

- Sessions: 32-byte token, SHA-256 stored, cookie `__Host-bc_session` Secure HttpOnly SameSite=Lax; rotated at login; sliding 14 d + absolute 90 d. `session.revoke` is scoped to the caller's own sessions; `session.revoke_all` signs out everywhere; deleting a user or SCIM deactivation revokes as described. Session lookup refuses sessions whose user is deleted.
- API keys: format `bc_<prefix>_<secret>`; prefix stored plain for lookup, secret SHA-256 hashed, constant-time compare; `expires_at` optional and enforced; scope JSON `{org_id, team_id?, project_id?, actions?[]}` intersected with the owner's live permissions at request time. Org owners (`org.permissions`) can list and revoke any key bound to their org.

### 7.11 Rate limits & CSRF exemptions

- Per-IP token bucket (in-memory; single-node per PRD §19): `/auth/*` and `/login` 20/min burst 10; `/scim/v2/*` 600/min per token. 429 with `Retry-After`.
- Global CSRF middleware exempts exactly these routes, which authenticate by other means and never read the session cookie: `POST /auth/saml/{id}/acs`, `POST /auth/saml/{id}/slo`, `POST /auth/oidc/{id}/backchannel-logout`, `/scim/v2/*`, and the passkey login-finish endpoint (bound to the flow cookie challenge). The exemption list is a constant in `internal/auth` (`csrf_exempt.go`, `IsCSRFExempt`) with a test asserting its exact contents; the session middleware also skips these routes, so their handlers never see a session.

## 8. Realtime (internal/sse)

- `/events` (session auth) and per-project `/events?project=` streams; hub keyed by user id with topic filters; heartbeat every 25s; `Last-Event-ID` replay from a small ring buffer (best effort).
- Event bus subscribers: sse hub, notification engine, webhook dispatcher, search indexer, activity writer, github transition engine.

## 9. Storage (internal/storage)

```go
type Store interface {
    Put(ctx, key string, r io.Reader, size int64, mime string) error
    Get(ctx, key string) (io.ReadCloser, error)
    Delete(ctx, key string) error
}
```
`local` (files under `BC_DATA_DIR/attachments`, key = `<org>/<task>/<id>`), `s3` (AWS SDK v2, custom endpoint). Selected per org (org_secrets) falling back to local. Upload path: validate size/type per org settings → images re-encoded (png/jpeg) via stdlib image; SVG passed through sanitiser (strip scripts/foreignObject/event attrs) → store → attachment row.

## 10. Agent Runtime (internal/agentrt)

- **Queue**: `jobs` polled by N workers (default 4, `BC_AGENT_WORKERS`); claim via `UPDATE … WHERE status='queued' … RETURNING`; exponential backoff to `max_attempts` = agent `retry_max`.
- **Run lifecycle**: trigger (mention/column/chat/schedule) → create `runs` row + job. Worker: assemble context → tool loop → finish. Cancellation sets a flag checked between steps.
- **Context assembly order**: platform context → org → team → project → agent context → skill instructions (each attached skill) → trigger payload (task snapshot: fields, comments, relations, attachment names; or chat history). Each block labelled with its source.
- **Tool loop**: chat-completions with `tools` = registry actions filtered to the agent's effective permission set (schemas from action Input), plus external MCP tools from skills (namespaced `mcp_<skill>_<tool>`). Execute via Dispatch as the agent actor; `ErrApprovalPending` → persist state, set run `awaiting_approval`, stop; on decision, resume with the approval result appended. Cap steps per run (default 25).
- **Provider client**: OpenAI-compatible chat completions with streaming; retries with jitter on 429/5xx; token usage recorded per step. `codex_sso` kind is stubbed behind the same interface (see QUESTIONS.md).
- **Budgets**: pre-run check org monthly spend vs cap (hard stop + notification at threshold); per-agent `runs_per_hour` and `token_budget` enforced at claim time.
- **Mention parsing**: `@name` in saved description/comment where name matches an active org agent → job. Column trigger: `task.move` handler enqueues when target column has `trigger_agent_id`.

## 11. REST API (internal/restapi)

- Router generated from registry: `POST /api/v1/actions/{name}` (uniform RPC) **plus** resource-style aliases for the common reads (`GET /api/v1/projects/{key}/tasks` etc. — thin wrappers over read actions).
- Bearer API keys; scope enforcement in dispatch; `Idempotency-Key` header → `ActionCtx.Idem`; problem+json errors with `code`; cursor pagination on list reads; ETag/If-Match on task update.
- OpenAPI 3.1 document generated at startup from registry schemas, served at `/api/v1/openapi.json` + embedded viewer at `/api/docs`.
- Per-key token-bucket rate limit (default 120/min) with `RateLimit-*` headers.

## 12. MCP Server (internal/mcp)

- Streamable HTTP at `/mcp`; auth `Authorization: Bearer <api key>`.
- **Tools**: from registry filtered to key scope ∩ owner permissions; unauthorized tools omitted from `tools/list`. Names: dots→underscores (`task_create`).
- **Resources**: `bc://project/{key}`, `bc://task/{key}-{n}`, `bc://project/{key}/context`, `bc://wiki/{key}/{path}`; `resources/list` scoped; subscriptions via list-changed where cheap.
- **Prompts**: `decompose_task(task)`, `summarise_sprint(project, sprint)`, `triage_backlog(project)`.
- High-impact tool call by a key whose policy requires approval → tool result `{"status":"approval_pending","approval_id":…}` (never silent execution).
- Implementation: `modelcontextprotocol/go-sdk` if it satisfies streamable HTTP + auth hooks; otherwise minimal in-repo JSON-RPC implementation. Decide at WU-403 and record in BACKLOG notes.

## 13. Wiki (internal/wiki)

- Per-project checkout cache under `BC_DATA_DIR/wiki/<project>` (go-git, shallow, single ref); refreshed on read if older than 60s (config) or on webhook.
- Render: goldmark (GFM, task lists) + `mermaid` fenced blocks → client-side render; SVG through the shared sanitiser; relative links/images resolved within the configured path (no traversal above it).
- Edit: UI editor (textarea + preview) → commit to `ref` using the editor's linked GitHub token (from user settings, WU-406); no linked token ⇒ wiki is read-only for that user with a "connect GitHub in settings" prompt; push; on non-fast-forward, re-pull and retry once, else surface conflict.
- History: `git log` for the file; render any revision read-only.

## 14. Search (internal/search)

- FTS5 table maintained by the event-bus indexer (task created/updated, comment, wiki refresh walk).
- Query API: `search.query(q, org, filters)` → grouped results (tasks, wiki, attachments-by-name), permission-filtered post-query by project visibility.
- Command palette endpoint returns top-N mixed results + matching registered actions the user may perform.

## 15. Security Requirements (gate for every WU)

CSRF token on all mutating browser requests; nonce CSP (`default-src 'self'`) with zero inline script except nonced bootstrap; `__Host-` cookies; org-scope on every tenant query (`make check-scope`); secrets only in `_enc` columns; attachments `Content-Disposition: attachment` + nosniff; sanitised SVG/mermaid output; SSRF guard on webhook/MCP-endpoint URLs (deny private ranges, resolve-then-connect pinning); rate limits on auth and API; audit rows for ImpactHigh; IdP tokens verified per §7 (never decode-only); no internal error strings in responses.

## 16. Verification Gates

A work unit is **done** only when:
1. `make check` passes (gen diff-clean, fmt, vet, lint, scope-gate, tests with race).
2. Every acceptance criterion in its BACKLOG entry has a corresponding automated test, or an explicit `Manual:` note in the BACKLOG entry saying how it was verified with `bc serve`.
3. BACKLOG.md status updated with date + commit subject in the same commit.
