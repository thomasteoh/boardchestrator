---
title: Sign-in and identity
desc: Identity providers, organisation single sign-on, SCIM, passkeys and the URLs to register.
order: 4
---

Boardchestrator stores no passwords. People sign in through an identity provider (OpenID Connect, GitHub OAuth or SAML 2.0) or with a passkey. This page covers how sign-in decides who someone is, what to register with each provider, and how organisations bring their own single sign-on.

Throughout, `<BASE>` is your `BC_BASE_URL` (for example `https://bc.example.com`) and `<id>` is the provider's ID in Boardchestrator (`google`, `github`, `authentik`, `acme-sso`, ...).

## How sign-in decides who you are

Every sign-in is resolved in this order:

1. **Known identity.** If the `(provider, subject)` pair has signed in before, that user signs in. Email plays no part.
2. **Link by email.** A first sign-in links to an existing account with the same email only when the provider is marked **trusted for email** and asserts that the address is verified. An organisation-owned provider only links addresses on that organisation's verified domains.
3. **Sign-up.** Otherwise a new account is created only when one of these holds: the provider allows open sign-up, the person arrived through a pending invite for that address, the provider belongs to an organisation with just-in-time (JIT) provisioning on and the address is on one of its verified domains, or the person is claiming an unclaimed instance.
4. Anything else is refused with "no account for this email, ask an admin for an invite".

Two per-provider switches control this:

- **Trust this provider's verified email addresses** (`trust_email`). Turn it on only for a provider whose users can't choose or change their own address, such as your company directory. Linking by an email the user controls is an account takeover. Google, GitHub and GitLab default to on; Microsoft, Okta, Auth0, Keycloak, Zitadel, authentik, generic OIDC and SAML default to off.
- **Let anyone who signs in through this provider create an account** (`allow_signup`). Providers added in the admin UI start invite-only. Env-configured providers follow `BC_ALLOW_SIGNUP` (default `true`). Organisation providers never allow open sign-up; they use JIT instead.

An unverified email never links and never opens a sign-up on its own. It still works with an invite (the invite's address is used) or with org JIT on a verified domain, which is how Entra users get in without the `xms_edov` claim (see the Entra recipe).

People link extra sign-in methods themselves from **Settings → Sign-in methods** while signed in, and can remove any method except the last.

## Claiming a new instance

Until someone claims it, an instance lets in only `BC_ADMIN_EMAILS` and whoever presents the bootstrap token. At every start while unclaimed the server logs one WARN line with the claim URL, `<BASE>/setup?token=…`:

- with `BC_BOOTSTRAP_TOKEN` set, the URL carries that token;
- with neither `BC_BOOTSTRAP_TOKEN` nor `BC_ADMIN_EMAILS` set, the server generates a random token at each start and stores only its SHA-256, so only the URL in the latest start's log works;
- with only `BC_ADMIN_EMAILS` set, no token exists and the first sign-in by a listed address with a verified email claims the instance.

Opening the URL shows "Claim this instance" with the configured sign-in providers and, if passkeys are available, "Claim with a passkey". The first person to finish signing in becomes platform owner, whatever their email, and the token stops working (`/setup` then answers 404, as it does for a wrong token). The bootstrap sign-in still needs the provider to assert a verified email; a passkey claimant types an address, which is stored unverified and never used to link an IdP account by email. Claim before exposing the instance publicly.

The token is logged on purpose. Treat logs from an unclaimed instance like any other secret.

`BC_ADMIN_EMAILS` addresses also hold platform admin on every sign-in through a **platform** provider with a verified email. Organisation-owned providers can never grant it.

## URLs to register

| What | URL |
|------|-----|
| OIDC / GitHub redirect (callback) URI | `<BASE>/auth/<id>/callback` (Google: `<BASE>/auth/google/callback`, GitHub: `<BASE>/auth/github/callback`) |
| Post-logout redirect URI | `<BASE>/login?signed_out=1` |
| OIDC back-channel logout URI | `<BASE>/auth/oidc/<id>/backchannel-logout` |
| SAML SP entity ID and metadata | `<BASE>/auth/saml/<id>/metadata` |
| SAML ACS (HTTP-POST) | `<BASE>/auth/saml/<id>/acs` |
| SAML single logout (HTTP-Redirect) | `<BASE>/auth/saml/<id>/slo` |
| SAML SP signing certificate | `<BASE>/auth/saml/<id>/certificate` |
| SCIM 2.0 base URL | `<BASE>/scim/v2` |

The provider forms (Platform admin → Identity providers, and Org settings → Single sign-on) show the exact URLs for the ID you type. Pick the ID before registering anything: it appears in the callback URL and can't be changed later.

The redirect URI must match exactly, including scheme and port. Behind a reverse proxy, `BC_BASE_URL` is the public URL, not the internal one.

## Configuring providers

Platform providers can be added in two ways.

- **Admin UI.** Platform admin → Identity providers (`/admin/identity-providers`). Pick a preset, fill in the issuer parameters and client credentials, and use **Test discovery** to check the issuer before saving. Client secrets are encrypted at rest and never shown again.
- **Environment variables.** `BC_GOOGLE_*`, `BC_GITHUB_*` and the `BC_OIDC_<NAME>_*` family, for unattended installs. These rows are read-only in the UI. Removing a provider's variables disables it at the next start; its users' identities are kept.

`BC_OIDC_<NAME>_*` creates the provider with ID `<name>` lower-cased, `_` becoming `-`: `BC_OIDC_CORP_SSO_CLIENT_ID` configures provider `corp-sso` with callback `<BASE>/auth/corp-sso/callback`. Each provider needs at least `_CLIENT_ID`; presets with no parameters (Google, gitlab.com) need no `_ISSUER`. `google` and `github` are reserved for their own variables. A typo in a suffix (`BC_OIDC_CORP_CLIENTID`) stops the server at startup instead of being ignored. Microsoft's allowed-tenant list and claim overrides other than groups are UI-only.

```sh
BC_OIDC_CORP_PRESET=keycloak
BC_OIDC_CORP_ISSUER=https://sso.example.com/realms/staff
BC_OIDC_CORP_CLIENT_ID=boardchestrator
BC_OIDC_CORP_CLIENT_SECRET=...
BC_OIDC_CORP_DISPLAY_NAME="Example staff"
BC_OIDC_CORP_TRUST_EMAIL=true
BC_OIDC_CORP_ALLOW_SIGNUP=false
```

Issuers must be `https`, except `localhost` and loopback addresses for local testing. Discovery runs lazily and is cached for an hour; if one provider's discovery fails, only that provider's button fails.

Every OIDC preset uses the authorisation-code flow with PKCE, `state` and `nonce`, and verifies the ID token's signature, `iss`, `aud`, `exp` and `nonce`. Register Boardchestrator as a **confidential web application** with the authorisation-code grant.

## Provider recipes

Where a console's menu names change often, the steps below say what to set rather than where to click.

### Google

1. In Google Cloud, create an OAuth client of type "Web application".
2. Authorised redirect URI: `<BASE>/auth/google/callback`.
3. Set `BC_GOOGLE_CLIENT_ID` and `BC_GOOGLE_CLIENT_SECRET`, or add the Google preset in the UI with ID `google`.

Google asserts verified emails and is trusted for email by default. It publishes no end-session endpoint, so signing out ends only the Boardchestrator session. There are no groups.

### Microsoft Entra ID (OIDC)

1. Register an application (Web platform). Redirect URI `<BASE>/auth/<id>/callback`. Also add `<BASE>/login?signed_out=1` as a redirect URI so RP-initiated sign-out can return.
2. Create a client secret.
3. Preset **Microsoft**, tenant = your directory (tenant) ID for a single tenant.
4. For multi-tenant sign-in use tenant `organizations` (work and school accounts) or `common`. Boardchestrator then checks the token's `iss` against its own `tid` and, if you list any, only lets in the tenants under **Allowed tenants**. List them: without a list any Entra tenant can sign in, subject to your sign-up policy.

**Email verification.** Entra's `email` claim is not verified and Entra sends no `email_verified`. With the default claim map, Entra emails count as unverified: they never link to existing accounts and never open a sign-up. People still get in with an invite, or through org JIT on a verified domain. To treat Entra emails as verified, add the optional claim `xms_edov` (email domain owner verified) to the ID token and set the provider's **Email verified claim** to `xms_edov`. Even then, leave **Trust this provider's verified email addresses** off for multi-tenant apps unless you restrict the allowed tenants.

**Groups.** Add a groups claim to the ID token. Entra sends group object IDs (GUIDs), so map those IDs, not display names. When a user is in more groups than fit in the token (the "groups overage"), Entra sends a pointer to Graph instead of the list. Boardchestrator then skips group sync for that sign-in, logs a warning and writes `membership.sync_skipped` to the org audit log. Use SCIM for organisations whose users have many groups. Entra may also omit the claim for a user with no groups; an absent claim skips sync rather than removing access.

**Logout.** RP-initiated logout works (`end_session_endpoint`). Entra does not send OIDC back-channel logout, so leave that URL unregistered.

### Microsoft Entra ID (SAML)

1. Create an enterprise application (non-gallery) and choose SAML single sign-on.
2. Identifier (Entity ID) `<BASE>/auth/saml/<id>/metadata`; Reply URL (ACS) `<BASE>/auth/saml/<id>/acs`; Logout URL `<BASE>/auth/saml/<id>/slo`.
3. Unique User Identifier (Name ID): `user.objectid` with format **Persistent**. The default (`user.userprincipalname`, email format) is refused unless you set the provider's **Subject attribute** to `NameID`, which accepts any non-transient Name ID; prefer the object ID, because a UPN can be renamed.
4. Add a group claim if you want group sync. Entra sends it as `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`, which Boardchestrator reads by default.
5. In Boardchestrator, preset **Microsoft Entra (SAML)**, with the App Federation Metadata URL.

SAML has no "email verified" flag. With **Trust this provider's verified email addresses** on, every address the provider asserts counts as verified; with it off, addresses are never used to link accounts. Boardchestrator requires signed assertions or a signed response and refuses unsigned IdP-initiated logout requests. Entra sends unsigned front-channel logout requests, so signing out at Entra does not end Boardchestrator sessions; signing out in Boardchestrator does reach Entra.

### GitHub

1. Create an OAuth app (not a GitHub App). Authorisation callback URL `<BASE>/auth/github/callback`.
2. Set `BC_GITHUB_CLIENT_ID` and `BC_GITHUB_CLIENT_SECRET`, or add the GitHub preset with ID `github`.

GitHub is OAuth, not OIDC. Boardchestrator reads `/user` and `/user/emails` and only uses the verified primary address. The token also powers wiki edits. GitHub has no groups, no sign-out endpoint and cannot be an organisation's IdP.

### GitLab (gitlab.com and self-managed)

1. Create an OAuth application (user, group or instance level) with scopes `openid`, `profile`, `email`, confidential, redirect URI `<BASE>/auth/<id>/callback`.
2. Preset **GitLab**. GitLab URL defaults to `https://gitlab.com`; for self-managed use your instance URL, for example `https://gitlab.example.com` (env: `BC_OIDC_GITLAB_PRESET=gitlab`, `BC_OIDC_GITLAB_ISSUER=https://gitlab.example.com`).

Groups come from `groups_direct` (full group paths). GitLab is trusted for email by default. The preset does not do RP-initiated logout.

### Okta (OIDC)

1. Create an OIDC web application. Sign-in redirect URI `<BASE>/auth/<id>/callback`; sign-out redirect URI `<BASE>/login?signed_out=1`; grant type authorisation code.
2. Preset **Okta**, domain `example.okta.com` (the org authorisation server) or `example.okta.com/oauth2/default` for a custom authorisation server.
3. Groups: the preset asks for the `groups` scope. On the org authorisation server, set the application's groups claim filter (claim name `groups`). On a custom authorisation server, add a `groups` claim and scope there, or set the provider's scopes to `openid email profile` so the authorise request doesn't ask for a scope the server lacks.

Okta asserts `email_verified`; trust is off by default. RP-initiated logout works.

### Okta (SAML)

1. Create a SAML 2.0 application. Single sign-on URL `<BASE>/auth/saml/<id>/acs`; Audience URI (SP Entity ID) `<BASE>/auth/saml/<id>/metadata`; Name ID format **Persistent**.
2. Attribute statements: `email` → `user.email`. Group attribute statement `groups` with a filter for the groups you want sent.
3. Single logout: enable it, Single Logout URL `<BASE>/auth/saml/<id>/slo`, SP Issuer = the entity ID, and upload the SP certificate from `<BASE>/auth/saml/<id>/certificate`.
4. In Boardchestrator, preset **Okta (SAML)** with the metadata URL from the application's Sign On tab.

### Okta SCIM

Turn on SCIM provisioning for the application. SCIM connector base URL `<BASE>/scim/v2`; unique identifier field `userName`; authentication mode HTTP header (Bearer) with a token from Org settings → Single sign-on → SCIM tokens. Enable push of new users, profile updates, deactivation and groups. Okta updates users with PUT; Boardchestrator accepts that.

### Auth0

1. Create a Regular Web Application. Allowed Callback URLs `<BASE>/auth/<id>/callback`; Allowed Logout URLs `<BASE>/login?signed_out=1`.
2. Preset **Auth0**, domain `example.au.auth0.com` (or your custom domain). The issuer ends in `/`.
3. Auth0 has no groups claim of its own. Add one with a post-login Action that sets a namespaced claim, for example `https://bc.example.com/groups`, and put that name in the provider's **Groups claim** (namespaced URLs are matched as exact claim names).

For RP-initiated logout, turn on the tenant setting that publishes `end_session_endpoint` in discovery; otherwise signing out is local only.

### Keycloak

1. Create an OpenID Connect client with client authentication on and the standard flow enabled.
2. Valid redirect URI `<BASE>/auth/<id>/callback`; valid post-logout redirect URI `<BASE>/login?signed_out=1`; back-channel logout URL `<BASE>/auth/oidc/<id>/backchannel-logout` with "back-channel logout session required" on.
3. For groups, add a Group Membership mapper with claim name `groups` and full group path off. For realm roles instead, set the provider's **Groups claim** to `realm_access.roles`.
4. Preset **Keycloak**, Keycloak URL `https://sso.example.com`, realm `staff` (issuer `https://sso.example.com/realms/staff`).

### Zitadel

1. In a project, create a Web application with the authorisation-code flow (client secret). Redirect URI `<BASE>/auth/<id>/callback`; post-logout URI `<BASE>/login?signed_out=1`.
2. To receive roles, turn on the project's "assert roles on authentication" setting. The preset requests `urn:zitadel:iam:org:project:roles`.
3. Preset **Zitadel**, domain `example.zitadel.cloud` or your own.

The roles claim is an object keyed by role name, `{"admin": {"<org id>": "<org domain>"}, "dev": {...}}`. Boardchestrator uses the keys (`admin`, `dev`) as group values, so map role keys. If your Zitadel version offers OIDC back-channel logout, register `<BASE>/auth/oidc/<id>/backchannel-logout`.

### authentik (OIDC)

Verified end to end against authentik 2026.8.3.

1. Create an OAuth2/OpenID provider: client type confidential, authorisation flow of your choice, redirect URIs `<BASE>/auth/<id>/callback` (strict, type authorisation) and `<BASE>/login?signed_out=1` (strict, type logout). For back-channel logout set the logout URI to `<BASE>/auth/oidc/<id>/backchannel-logout` with logout method back-channel. Create an application with slug, for example, `boardchestrator` and attach the provider.
2. Preset **authentik**, authentik URL `https://auth.example.com`, application slug `boardchestrator` (issuer `https://auth.example.com/application/o/boardchestrator/`).

Things the live test turned up:

- authentik's default `email` scope mapping returns `email_verified: false`. With it, sign-ups and the bootstrap claim fail with "Your identity provider didn't confirm your email address"; invites and org JIT still work. If your authentik users can't change their own addresses, attach a custom scope mapping for scope `email` that returns `{"email": request.user.email, "email_verified": True}` in place of the default one.
- Groups arrive in the `groups` claim of the default `profile` scope.
- A provider created through authentik's API has no grant types, and authorise requests then fail with "The request is otherwise malformed". Set grant types `authorization_code` (and `refresh_token` if you like); the admin UI sets them for you.
- The default provider invalidation flow ends the application session but not the authentik session, so after signing out the next sign-in goes straight through without a password. Use an invalidation flow with a user logout stage if you want signing out to end the authentik session too.
- Back-channel logout works: ending the user's authentik session (or the user signing out there) revokes the matching Boardchestrator sessions.

### authentik (SAML)

1. Create a SAML provider: ACS URL `<BASE>/auth/saml/<id>/acs`, service provider binding Post, audience `<BASE>/auth/saml/<id>/metadata`, SLS URL `<BASE>/auth/saml/<id>/slo` with binding Redirect, a signing certificate, sign assertions and responses on, sign logout requests on, and default NameID policy **Persistent**. Attach it to an application.
2. In Boardchestrator, preset **SAML 2.0**, metadata URL `https://auth.example.com/api/v3/providers/saml/<provider number>/metadata/?download`. The `/application/saml/<slug>/metadata/` URL answers with a redirect, and Boardchestrator does not follow redirects when fetching metadata, so use the download URL or paste the XML.
3. authentik sends groups as `http://schemas.xmlsoap.org/claims/Group`, which Boardchestrator reads by default.

### authentik SCIM

Create a SCIM provider with URL `<BASE>/scim/v2`, authentication mode token and a token from Org settings → Single sign-on → SCIM tokens, then add it to the application as a backchannel provider. Set a **group filter**: without one authentik pushes every user, including `akadmin`, and Boardchestrator creates accounts for all of them in the organisation (addresses already used by an account outside the org's verified domains get 409). Groups are pushed as they change; existing groups can be pushed from the provider's sync page.

### Generic OpenID Connect

Preset **OpenID Connect** with the issuer URL; the provider must publish `/.well-known/openid-configuration`. Defaults: scopes `openid email profile`, claims `email`, `email_verified`, `name`, `picture`, `groups`. Override any claim name on the form; nested claims use dots (`realm_access.roles`). Trust is off by default.

### Generic SAML 2.0

Preset **SAML 2.0** with the IdP's metadata URL (https, cached for an hour) or pasted metadata XML. The IdP must:

- support SP-initiated SSO with the HTTP-Redirect binding for the AuthnRequest and HTTP-POST to the ACS (IdP-initiated, unsolicited responses are refused);
- sign the assertion or the response, with exactly one assertion and an audience of `<BASE>/auth/saml/<id>/metadata`;
- send a persistent Name ID, or you set **Subject attribute** to an attribute name (or to `NameID` to accept an email-format Name ID).

Default attributes: email from `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, `mail` or `email`; name from `displayName` or the claims `name` URI; groups from the Entra groups URI, `http://schemas.xmlsoap.org/claims/Group`, `groups` or `memberOf`. Single logout uses HTTP-Redirect; logout requests from the IdP must be signed (SHA-1 is refused).

## Organisation single sign-on

An org owner (anyone with the `org.sso` permission) sets this up under **Org settings → Single sign-on** (`/app/org/<org id>/settings/sso`).

1. **Domains.** Add each email domain and publish the TXT record shown: `_boardchestrator-challenge.<domain>` with value `bc-verify=<token>`. Press Verify once DNS has it. Only one organisation can verify a domain; a pending claim never blocks the real owner. `example.com` does not cover `eng.example.com`.
2. **Identity provider.** Add the organisation's OIDC or SAML provider. Its ID must start with the organisation's slug and a hyphen (for example `acme-sso`), which the form fills in. The callback and logout URLs follow the same patterns as above. Organisation providers are trusted for email only on the organisation's verified domains, can't open sign-up and can never grant platform admin. They may only reach public addresses unless the operator sets `BC_ORG_IDP_ALLOW_PRIVATE=true`.
3. **Home-realm discovery.** Once a domain is verified and a provider enabled, `/login` shows "Sign in with SSO". An address on the domain is sent to the organisation's first provider with `login_hint`.
4. **Just-in-time provisioning.** Turn on JIT and choose a default role (owner-equivalent roles are not allowed). A first sign-in through the org's provider with an address on a verified domain creates the account and an org membership. An existing user on the domain who has no org membership also gets one. JIT never links a new identity to an existing account by email; that needs trust.
5. **Group mappings.** Turn on group sync, optionally name the group claim (blank uses the provider's), and map group values to roles at organisation, team or project level. Every sign-in through the org's providers reconciles the memberships sync created: it adds missing ones and removes stale ones. Memberships granted by hand, by invite, by JIT or by SCIM are never changed, and where one exists on a mapped resource it wins. An absent group claim skips sync; a present but empty one removes every synced membership. Sync never removes or demotes the organisation's last owner.
6. **Require single sign-on.** Once a provider works and you are signed in through it, turn on "Require single sign-on". Members can then only open the organisation's pages, act in it, see its search results and receive its live events from a session signed in through one of its providers; others see "This organisation requires single sign-on" with a sign-in button. API keys and agents are unaffected. You can't turn it on from a session that would lock you out, or disable the last enabled provider while it is on.
7. **SCIM.** Create a SCIM token (shown once) and give the IdP `<BASE>/scim/v2` and the token. SCIM creates and links users (existing accounts only on verified domains), adds an org membership with the JIT default role or Member, and maps SCIM group display names through the organisation-wide group mappings. Deactivating or deleting a user removes all their memberships in the organisation, revokes their API keys for it and, if they belong to no other organisation, their sessions. Users managed by SCIM skip group sync and JIT at sign-in, so the two never fight.

Platform owners are exempt from organisation SSO everywhere. If an organisation's IdP breaks, a platform owner signs in with a platform provider and turns the requirement off.

## Passkeys

Passkeys (WebAuthn) are on by default and can be turned off under Platform admin → Identity providers. Signed-in users add them under **Settings → Sign-in methods → Add a passkey**, then sign in from `/login` with "Sign in with a passkey" without typing a username. An invitee can create an account with a passkey from the invite link, and the bootstrap claim page offers "Claim with a passkey".

- The relying-party ID is the host of `BC_BASE_URL`. If that host is an IP address, passkeys are unavailable (startup warning, UI hidden). Changing the host later invalidates every registered passkey.
- Browsers only offer WebAuthn on secure origins: `https`, or `http://localhost` for testing.
- A passkey session counts as a sign-in through provider `passkey`, so organisations that require single sign-on refuse it.
- A passkey that has verified its user once must verify them every time. A sign count that stops advancing is refused and audited as `auth.passkey_clone_suspected`.

Tested with Chromium's virtual authenticator: registration from Sign-in methods, usernameless sign-in, and invite sign-up with a passkey.

## Sessions, sign-out and API keys

- Sessions live in the `__Host-bc_session` cookie (always `Secure`), rotate at every sign-in, slide for 14 days and end after 90 days at most. Settings lists your sessions with their sign-in method; you can sign out one session, everywhere else, or everywhere. Removing a sign-in method signs out the sessions it created.
- **Sign out** ends the local session. With "Sign out of the identity provider too" on and a provider that publishes an end-session endpoint (OIDC) or a Redirect SLO service (SAML), the browser then goes to the IdP, which returns to `<BASE>/login?signed_out=1`.
- **OIDC back-channel logout** at `<BASE>/auth/oidc/<id>/backchannel-logout` revokes sessions by `sid` or `sub` when the IdP sends a valid logout token. **SAML** IdP-initiated logout requests at the SLO URL must be signed.
- API keys default to a 90-day expiry (30, 365 days or never on request) and are shown once. Org owners see and revoke every key bound to their organisation under Org settings → API keys.
- Sign-in routes (`/login`, `/setup`, `/auth/*`) are limited to 20 requests a minute per client IP with bursts of 10, and SCIM to 600 a minute per token. Set `BC_TRUSTED_PROXIES` to your reverse proxy's address so the limit and the audit log see real client addresses.
- Sign-ins, sign-outs, failures (with a reason code and reference, never tokens), claims, links and unlinks go to the audit log. Platform-wide rows are under Platform admin → Audit log; org-provider events are in the organisation's log.

## Known limits

- Entra emails are unverified unless you map `xms_edov`; without it, Entra users join only by invite or org JIT (QUESTIONS Q8).
- Entra groups overage, and an absent group claim, skip group sync instead of removing access. Users removed from their last group keep synced memberships if the IdP then omits the claim; use SCIM for removals.
- Unsigned SAML logout requests are refused, so Entra's front-channel sign-out does not end Boardchestrator sessions.
- Entra does not send OIDC back-channel logout. GitHub and Google have no IdP sign-out.
- SAML emails count as verified exactly when the provider is trusted (Q13).
- SAML metadata URLs that redirect are not followed; use the final URL or paste the XML.
- Passkeys need a host name, not an IP address, in `BC_BASE_URL`.
- A passkey bootstrap claimant's email is never marked verified.
- An org-level group mapping does not change a SCIM user's org membership, because SCIM already holds an org-level membership and existing non-sync memberships win (Q12). Map SCIM groups to teams or projects, or set the JIT default role to the role SCIM users should get.
- SCIM creates an account for any address it pushes that no account uses, even outside the organisation's verified domains. Scope the IdP's SCIM assignment to the people who should have access.
- SCIM does not support `or`, `ne`, `co` or `sw` filters, sorting, ETags or bulk requests.
- Rate limits are in memory per process (single node).
