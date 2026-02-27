---
inclusion: always
---

# Git Best Practices for CipherSwarmAgent

## Branching

- Feature branches for all work. Never commit directly to `main`.
- All changes go through pull requests.
- Keep branches short-lived and up-to-date with `main` via rebase or merge.

## Commits

- **Conventional Commits**: `<type>(<scope>): <description>`. See `commit-style.md` for details.
- **Atomic commits**: Each commit is a single, logical change. Never commit broken or untested code.
- All commits must pass `just ci-check` and linting.

## Pull Requests & Code Review

- All changes require a PR and at least one review.
- Address feedback promptly. Use the PR template and checklist if provided.

## .gitignore Hygiene

- Ensure build artifacts, IDE files, and secrets (e.g., `data/`, `cipherswarmagent.yaml`) are ignored.
- Never commit secrets, credentials, or sensitive data. Use environment variables.
- The user's `~/.gitignore_global` ignores `gen/` directories — never use `gen` as a directory name.

## CI Integration

- All commits and PRs must pass CI (lint, test, build) before merge.
- CI workflows live in `.github/workflows/`. See `github-actions.md` for details.
- Local CI: `just ci-check` (fast), `just ci-full` (comprehensive).

## Tagging & Releases

- Tag releases with semantic versioning: `git tag vX.Y.Z`.
- Push tag, then run `just release` locally.
- Requires a PAT with `write:packages` scope exported as `GITHUB_TOKEN`; `docker login ghcr.io` for containers.

## Changelog

- `CHANGELOG.md` is auto-generated from commit messages using `git-cliff`.
- Generate: `just changelog`. For a specific version: `just changelog-version vX.Y.Z`.

## Repository Maintenance

- Regularly prune stale branches after merge.
- Never commit large files, secrets, or generated data.
- Resolve merge conflicts carefully and test after resolving.
