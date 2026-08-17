# Process Retrospective — boardchestrator sprint

**Sprint:** 2026-07-20 → 2026-08-17 · 6 phases · 72 WUs · 162 commits · ~73.5K insertions · 1007 files · `v0.1.0-rc.1` shipped.

This document records *how* the planning phase produced a smooth implementation, so the loop can be replicated on future builds. It complements `PROCESS-WORKFLOW.md` (the process itself) and `SPEC.md §16` (verification gates).

## What made planning → implementation smooth

1. **Planning artifacts preceded code.** The first 4 commits were pure planning — PRD, PRD v2, then SPEC/BACKLOG/WORKER/QUESTIONS, then Q1/Q2 resolutions — before any code. Scope, architecture, task order, and open questions all existed up front.
2. **A 4-document source-of-truth hierarchy** (from WORKER.md): PRD (scope) > SPEC (how) > BACKLOG (what next) > QUESTIONS (open items). Conflicts resolve downward and get recorded in QUESTIONS. Nothing was guessed; ambiguity went to QUESTIONS.md.
3. **The backlog was a plan-as-ledger.** Each WU carried deps, acceptance criteria (AC), and a live `done <date> <commit>` status. The worker rule — "first ready WU whose deps are all done" — forced correct ordering (Foundation first, everything layered on it). No rework from building on unstable ground.
4. **AC with a mandatory test gate** (SPEC §16): every AC needed an automated test or an explicit `Manual:` note. `make check` green was the objective done-gate, not a vibe.
5. **The verification-gate stack was pre-built.** `make check` = gen diff-clean + fmt + vet + lint + **check-scope** (a custom gate rejecting tenant-table queries missing org scope — the security invariant) + race tests. The scope-gate shipped in WU-003 and enforced SPEC §1 tenancy on every later WU. Self-tested against fixtures so it can't silently weaken.
6. **Checkpoint-every-step as the anti-catastrophe design.** TASK.md's numbered checklist doubled as a recovery log — if a worker died mid-task, the next resumed from the last checkpointed step, not from scratch. This is why the sprint survived interruptions.
7. **Test-first build order baked in** (WORKER.md step 5): migrations before queries, queries before actions, actions before handlers, handlers before views.

## The worker loop (per WU)

Orient → select first ready WU (deps done) → mark in-progress → decompose to a numbered checklist in TASK.md → build test-first → checkpoint (commit each verified step) → verify full gate green → record `done <date> <commit>` in BACKLOG.md **in the same commit** → commit/push to the phase branch → report.

One WU per iteration. A finished small WU beats a half-finished big one — every iteration leaves mergeable state.

## Git flow

Phase branches (`build/phase-N`) → branch-per-WU (`wu-NNN`) → PR → squash-merge → delete local + remote branch. `main` is the single source of truth; no intermediate integration branch.

**The one process lapse:** step 9 (delete branch after merge) drifted at the sprint tail — 4 fully-merged branches/worktrees (wu-304/305/306/307) survived until cleanup on 2026-08-17. Enforce a tail sweep: `git branch -d`, `git worktree remove`, `git push origin --delete`.

## QUESTIONS.md mechanics

On ambiguity, PRD/SPEC conflict, broken dependency, or a security/schema decision: append `Qn`, mark the affected WU `blocked(Qn)` (or note the assumption taken and continue), move to the next eligible WU, and never invent scope to unblock yourself. Humans answer inline under **Answer:**. Defer non-blocking decisions cleanly (Q4 was deferred 2026-07-24 → resolved 2026-08-16 via a dedicated WU) rather than blocking the whole build.

## Hard rules that held

- No pushes to `main`.
- No bypassing the action/domain layer for mutations.
- Never weaken a gate to pass it (no deleting failing tests, no loosening scope-gate, no unjustified suppressions).
- Migrations append-only once a phase branch merges — fix forward.
- No new deps beyond SPEC without a QUESTIONS entry; no runtime network fetch; vendor everything.
- Security requirements apply to every WU, not just security-labelled ones.

## Reusable takeaways

- **Scope-gate pattern:** build a check that enforces the hardest architectural invariant early and wire it into `make check` so it guards every subsequent WU.
- **Checkpointing** is the anti-catastrophe design for long autonomous builds.
- **Branch cleanup lapses at the tail** — schedule a sweep when the sprint ends.
- The full loop is captured as the Hermes skill `planning-to-implementation-loop` for reuse on future projects.
