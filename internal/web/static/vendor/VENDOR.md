# Vendored JS libraries

No CDN or network fetch at runtime; these files are committed and served from
the embedded static filesystem. Pin exact versions; record the source URL and
SHA-256 of every file. To upgrade: download the new file with `curl -fsSL`,
update this table, and commit both in the same WU.

| File | Library | Version | Source URL | SHA-256 |
|------|---------|---------|------------|---------|
| `htmx.min.js` | htmx | 2.0.8 | https://unpkg.com/htmx.org@2.0.8/dist/htmx.min.js | `22283ef68cb7545914f0a88a1bdedc7256a703d1d580c1d255217d0a50d31313` |
| `alpine-csp.min.js` | Alpine.js (CSP build) | 3.15.8 | https://unpkg.com/@alpinejs/csp@3.15.8/dist/cdn.min.js | `87df87078f7b3a880e91eef7fb0866f5086de52f9289bc96503608311810a7fc` |

Downloaded 2026-07-19 (WU-004).

## Why the Alpine CSP build

SPEC §15 mandates a nonce-based CSP (`default-src 'self'`) with no
`unsafe-eval`. Standard Alpine evaluates `x-*` expressions with
`new Function()`, which a spec-compliant CSP blocks. The official CSP build
(`@alpinejs/csp`) restricts expressions to property/method references on
components registered via `Alpine.data(...)` — so all component logic lives
in `app.js` and templates only reference names (e.g. `x-on:click="toggleDrawer"`).
Write all Alpine usage in that style.
