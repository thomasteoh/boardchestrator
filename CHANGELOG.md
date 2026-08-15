# Changelog

All notable changes to boardchestrator are tracked here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are tagged
`vX.Y.Z` (stable) and `vX.Y.Z-rc.N` (release candidates). The release pipeline
builds a Docker image to `ghcr.io/<owner>/boardchestrator` on every tag push
(`.github/workflows/release.yml`).

## [Unreleased]

### Added
- `bc backup` — online SQLite snapshot via `VACUUM INTO` + prune-to-newest-N (WU-507).
- `/readyz` now reports DB + queue health (depth + oldest queued age) in addition
  to server readiness; any degraded check returns 503 (WU-507).
- Env reference generator (`config.EnvReference`) + `RESTORE.md` / `DEPLOY.md` docs (WU-507).
- Compose smoke test (`scripts/smoke.sh`) driving org → project → task creation
  over HTTP with session + CSRF auth (WU-508).
- `compose.yaml` + Dockerfile fixes for non-root container runtime (WU-508).

### Fixed
- Platform-scope actions (org.create, pricing, providers) were ungrantable:
  the permission engine now walks the platform sentinel-org membership, and
  bootstrap admins are granted an Org Owner membership there (WU-508).
- Org creator's Owner role now grants `*` (was missing project/team/task
  permissions), so the first admin can create projects and tasks (WU-508).
- Missing HTTP routes for `org.create`, `project.create`, `team.create` added (WU-508).

## [0.1.0-rc.1] — 2026-08-15

First release candidate. Includes WU-506 (S3 attachment backend) and WU-507
(backup + ops polish). See the `WU-*` entries in `BACKLOG.md` for scope.
