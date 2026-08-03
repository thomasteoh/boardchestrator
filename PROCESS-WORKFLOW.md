# Workflow Process

## Branching

Each WU gets a **distinct branch** named `wu-<N>` (e.g. `wu-208`), branched from `main`.

- One branch per WU, one commit series per WU.
- No stacking WUs on the same branch.
- No committing WU work directly to `main`.

## Lifecycle

1. `git checkout main && git pull origin main` — sync latest.
2. `git checkout -b wu-<N>`
3. Implement. Commit as you go.
4. `make check && go test ./...` — green before PR.
5. Update `BACKLOG.md`: mark WU `done <date> <commit-subject>` in the same commit as the work.
6. `git push origin wu-<N>`
7. User opens PR on GitHub, reviews, merges to `main`.
8. `git checkout main && git pull origin main` — sync merged result.
9. Delete local branch: `git branch -d wu-<N>`

## Rationale

- PR review before merge catches issues before they land on `main`.
- Squash merge happens on GitHub (select "Squash and merge" in PR).
- No intermediate integration branch needed — `main` is the single source of truth.
