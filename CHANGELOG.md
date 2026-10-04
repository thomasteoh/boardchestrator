# Changelog

All notable changes to boardchestrator are tracked here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are tagged
`vX.Y.Z` (stable) and `vX.Y.Z-rc.N` (release candidates). The release pipeline
builds a Docker image to `ghcr.io/<owner>/boardchestrator` on every tag push
(`.github/workflows/release.yml`).

## [Unreleased]

### Added (Phase 7: identity and access management, WU-600 to WU-614)
- Sign-in through any OpenID Connect provider, with presets for Google, Microsoft Entra ID (single and multi-tenant), GitLab, Okta, Auth0, Keycloak, Zitadel and authentik, plus generic OIDC. Authorisation-code flow with PKCE, `state` and `nonce`; ID tokens verified against the provider's keys. GitHub keeps its OAuth flow and uses only the verified primary email.
- Identity providers managed in Platform admin → Identity providers (with "Test discovery") or by environment (`BC_GOOGLE_*`, `BC_GITHUB_*`, `BC_OIDC_<NAME>_*`). Google is no longer required.
- `/login` page, per-provider email trust and sign-up policy, invite-gated sign-up (`BC_ALLOW_SIGNUP`), and Settings → Sign-in methods to link and unlink providers.
- Bootstrap claim page `/setup?token=` with a logged claim URL while unclaimed; per-IP sign-in rate limit; `BC_TRUSTED_PROXIES`; sign-in audit rows and Platform admin → Audit log.
- Organisation single sign-on: DNS-verified email domains, organisation-owned OIDC and SAML providers, home-realm discovery, "Require single sign-on" (platform owners exempt), JIT provisioning and IdP group to role mapping at org, team or project level.
- OIDC RP-initiated and back-channel logout; SAML 2.0 service provider with SP-initiated login, metadata and single logout in both directions.
- SCIM 2.0 provisioning (`/scim/v2`) with per-organisation tokens, user and group endpoints and deprovisioning.
- Passkeys: usernameless sign-in, registration from Sign-in methods, passkey sign-up from an invite or the bootstrap claim, and a platform toggle.
- Session list with sign out of one session, everywhere else or everywhere; API key expiry (90 days by default) and organisation API key management; last-owner protection.
- "Sign-in and identity" guide in `DEPLOY.md` and on the website: provider recipes, URLs to register, organisation SSO, SCIM, passkeys and known limits. Verified end to end against a real authentik 2026.8 (OIDC, SAML, SCIM, back-channel logout) with Chromium and a virtual authenticator.

### Security
- Sign-in no longer fails with a 500 for every new user (unknown email treated as an error) and every returning user (duplicate identity insert).
- Users are resolved by `(provider, subject)`, never by email alone; email linking needs a trusted provider and a verified address. ID tokens are verified (the old Google flow decoded them unverified). The bootstrap token is now checked.
- Platform-scope actions were checked against a caller-supplied organisation, so an org owner could run platform actions such as `org.create`, `provider.create` and `pricing.upsert` (Q10). Platform actions now always check the platform organisation; per-user actions moved to a self scope.
- `/app/org/{id}/audit` and its export showed any organisation's audit log to any signed-in user; `audit.log.list`/`export` also read the organisation from the input.
- `membership.*`, `member.remove` and `role.*` acted on an `org_id` from the input instead of the verified organisation, letting a caller with rights in one organisation change another.
- `BC_ADMIN_EMAILS` granted platform admin on a sign-in through an organisation-owned provider, so an org owner's IdP could mint a platform admin.
- `session.revoke` could revoke other users' sessions, `user.export` exported any user, and the notification actions read and wrote any user's notifications.
- Plaintext API keys, invite tokens and skill tokens no longer reach audit rows, events, webhooks or idempotency records; `apikey.list` no longer returns key hashes for every organisation.
- The chat sessions partial accepted any `org_id` without a membership check; live events and the chat organisation list now respect organisation SSO.
- `X-Forwarded-For` is believed only from `BC_TRUSTED_PROXIES`, so clients can't spoof their IP for rate limits and audit rows.
- Session and sign-in flow cookies are always `Secure` (`__Host-` prefixed); the production `Insecure` switch is gone.

### Fixed
- Signing out with IdP sign-out on, linking a provider from Sign-in methods, and "Sign in with SSO" did nothing in browsers: CSP `form-action 'self'` blocks a form's redirect to another origin. These now continue through a short same-origin page (WU-614).
- The "Sign in with ..." button on the SSO-required page was an htmx-boosted link that could not follow the redirect to the identity provider (WU-614).
- The provider ID field's `pattern` was invalid under the RegExp `v` flag browsers use, so it was ignored (WU-614).
- SAML groups sent as `http://schemas.xmlsoap.org/claims/Group` (authentik, ADFS) are read without a claim override (WU-614).
- The environment reference listed `BC_LOG_LEVEL_STR` and `BC_ADMIN_EMAILS_STR`, which don't exist; a test now keeps the documented tables in step with the configuration (WU-614).

### Added (operations)
- `bc backup` — online SQLite snapshot via `VACUUM INTO` + prune-to-newest-N (WU-507).
- `/readyz` now reports DB + queue health (depth + oldest queued age) in addition
  to server readiness; any degraded check returns 503 (WU-507).
- Env reference generator (`config.EnvReference`) + `RESTORE.md` / `DEPLOY.md` docs (WU-507).
- Compose smoke test (`scripts/smoke.sh`) driving org → project → task creation
  over HTTP with session + CSRF auth (WU-508).
- `compose.yaml` + Dockerfile fixes for non-root container runtime (WU-508).

### Fixed (operations)
- Platform-scope actions (org.create, pricing, providers) were ungrantable:
  the permission engine now walks the platform sentinel-org membership, and
  bootstrap admins are granted an Org Owner membership there (WU-508).
- Org creator's Owner role now grants `*` (was missing project/team/task
  permissions), so the first admin can create projects and tasks (WU-508).
- Missing HTTP routes for `org.create`, `project.create`, `team.create` added (WU-508).

## [0.1.0-rc.1] — 2026-08-15

First release candidate. Includes WU-506 (S3 attachment backend) and WU-507
(backup + ops polish). See the `WU-*` entries in `BACKLOG.md` for scope.
