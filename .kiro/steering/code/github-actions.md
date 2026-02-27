---
inclusion: fileMatch
fileMatchPattern: [.github/workflows/*.yml]
---

# GitHub Actions for CipherSwarmAgent

CI/CD workflows for the CipherSwarmAgent project.

## Workflows

### `go.yml` — Build, Test, Lint, Coverage

- **Build & Test**: Matrix build across `ubuntu-latest`, `macos-latest`, `windows-latest` with Go `stable`.
- **Lint**: `golangci/golangci-lint-action` on `ubuntu-latest`.
- **Coverage**: Generates `coverage.out` and uploads to Codecov. Uses `fail_ci_if_error: false` to avoid failing PRs on transient upload issues.
- **Triggers**: Push to `main`, all pull requests.

### `git-chglog.yml` — Changelog Generation

- Uses `nuuday/github-changelog-action` with config from `.chglog/`.
- **Triggers**: Push to `main`, PRs against `main`.

## Toolchain Setup

- Use `jdx/mise-action@v3` for installing dev toolchains (Go, pre-commit hooks, etc.) and enabling caching.
- Use `actions/setup-go@v6` for Go version management.
- Use `actions/checkout@v6` for repository checkout.

## Conventions

- **Pin action versions**: Always pin actions to specific major versions (e.g., `@v6`, `@v3`).
- **Minimal permissions**: Set `permissions: contents: read` at the workflow level.
- **Secret management**: Access secrets via `${{ secrets.SECRET_NAME }}`. Never hardcode credentials.
- **Caching**: `mise-action` handles Go module caching. No separate `actions/cache` step needed.

## Local Testing

- Use `act` to test workflows locally: `just act-run go`, `just act-pr`.
- Dry-run (list steps): `just act-dry go`.
- See `justfile` act recipes for available commands.

## Pre-commit Hooks

Pre-commit hooks (`.pre-commit-config.yaml`) run locally and include:

- `actionlint` — validates GitHub Actions workflow files.
- `shellcheck` — lints shell scripts.
- `mdformat` — auto-formats markdown files.
- Standard checks: large files, merge conflicts, YAML/JSON/TOML validation.

Install hooks: `just install` (runs `pre-commit install --hook-type commit-msg`).

## CI Recipes (justfile)

- `just ci-check` — pre-commit, format-check, lint, test, integration tests.
- `just ci-full` — ci-check + security (SBOM), release-check, docs-test.
- `just ci-smoke` — fast build + short tests for quick validation.
