# QUESTIONS.md — Open Items

Workers append here per WORKER.md. Humans answer inline under **Answer:** and flip any `blocked(Qn)` WUs back to `ready`.

---

## Q1 — Codex SSO provider feasibility

**Context:** PRD §8 lists Codex SSO (OAuth to a ChatGPT/OpenAI account) as a provider kind alongside OpenAI-compatible APIs. Using consumer-subscription auth for programmatic API calls may violate OpenAI's terms, and the token flow is undocumented/unstable.
**Options:** (a) implement best-effort against the observed Codex CLI auth flow, accept breakage risk; (b) keep the provider kind registered but stubbed "not yet supported" until confirmed; (c) drop it, OpenAI-compatible keys only.
**Recommendation:** (b) — the interface already isolates it; WU-302 builds the stub, no other WU depends on it.
**Answer:** _pending_

## Q2 — Wiki edits by Google-only users

**Context:** SPEC §13 commits wiki edits with the user's GitHub token, falling back to the org bot token with `Co-authored-by`. Confirming this is acceptable rather than requiring a linked GitHub account to edit.
**Recommendation:** keep the bot-token fallback (as spec'd).
**Answer:** _pending_
