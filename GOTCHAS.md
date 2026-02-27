# Gotchas

Known pitfalls and edge cases. Referenced from AGENTS.md.

## Linting

- `//go:fix inline` directives conflict with `gocheckcompilerdirectives` — avoid adding them.
- `just ci-check` includes a `go fix -diff` dry-run whose output is informational only, not a failure.
- `contextcheck` flags functions not propagating context — use `//nolint:contextcheck // reason` when the callee genuinely cannot accept a context parameter.
- `revive` requires each exported constant to have its own `// ConstName is...` doc comment. A group comment alone doesn't satisfy it.
- `//nolint:revive` does NOT suppress `staticcheck` for the same issue — list all linters (e.g., `//nolint:revive,staticcheck`).
- `//nolint:errcheck` does NOT suppress `gosec` G104 (unhandled error return) — list both (e.g., `//nolint:gosec,errcheck // G104 - reason`).
- `containedctx` flags `context.Context` stored in structs — use `//nolint:containedctx // reason` when the context is intentionally part of the struct lifecycle.
- `gocritic` `whyNoLint` rule requires every `//nolint:` directive to include an explanation. Bare `//nolint:linter` directives fail CI.
- A blank `//` line between a doc comment and a type/func declaration breaks the linter's comment association — keep them contiguous.
- `.golangci.yml` has `fix: true` — `nolintlint` auto-strips `//nolint:` directives that don't suppress an active warning. Don't add nolint for rules that aren't actually firing; verify with a clean cache first (`golangci-lint cache clean`).

## golines & nolint Comments

- `golines` (max-len 120) splits long lines, moving `//nolint:` off the flagged line. Keep nolint reasons short so total line stays under 120 chars.
- When `golines` splits multi-line expressions, even short inline `//nolint:` comments get displaced. Place nolint as a standalone comment on the line above.
- `//nolint:revive` on `APIError`, `Error_`, and `APIClient` can be stripped by `golines` or other formatters. Verify they survive after running formatters.

## Code Generation (oapi-codegen)

- oapi-codegen v2 config does NOT support `input-spec` — the spec path must be a positional CLI argument.
- `docs/swagger.json` is downloaded from the CipherSwarm server — never modify it locally. Open issues on `unclesp1d3r/CipherSwarm` for spec problems.
- During coordinated client+server development, local `swagger.json` changes are acceptable. CodeRabbit may flag these as policy violations when the upstream server PR hasn't merged yet — these are false positives.
- `lib/api/client.gen.go` is auto-generated — never manually modify. Regenerate with `just generate`.
- oapi-codegen generates a `Client` struct — the hand-written aggregate interface is named `APIClient` (with `//nolint:revive` for stutter) to avoid the conflict. `APIError` and `SetTaskAbandonedError.Error_` also have `//nolint:revive`.
- Use `exclude-schemas` in `lib/api/config.yaml` when a generated type needs manual customization (e.g., `ErrorObject` excluded so it can implement the `error` interface).
- oapi-codegen's `Parse*Response` methods read and close `HTTPResponse.Body` during parsing. Use the parsed `Body` byte slice (`resp.Body`), not `resp.HTTPResponse.Body` (already drained and closed).
- When an API method returns HTTP 200, always guard `resp.JSON200 == nil` — oapi-codegen silently sets it to nil if JSON unmarshaling fails.

## Error Handling

- Generated types with an `Error` field (e.g., `ErrorObject`) can't implement Go's `error` interface — use a wrapper type like `api.APIError`.
- `cserrors.LogAndSendError` returns the `err` parameter directly — always pass a non-nil error in error paths, or callers will see success.

## Configuration

- `SetDefaultConfigValues` runs before config files/env vars are loaded. Never derive defaults from other viper keys (e.g., `viper.GetString("data_path")`) — they only return the registered default, not user overrides. Derive in `SetupSharedState` instead.

## Testing

- `agentstate.State` contains `atomic.Bool` and `sync.RWMutex` — never copy the struct. Use per-field save/restore in test helpers and getter/setter methods for synchronized fields.
- `hashcat` package tests cannot import `testhelpers` (circular: testhelpers -> hashcat). Use local test helpers.
- Package-level `var` test fixtures get mutated by production code across subtests. Use factory functions (e.g., `newSampleData()`) that return fresh copies to prevent cross-test contamination.
- `nxadm/tail` `Cleanup()` returns void — do not attempt to capture a return value. `Stop()` returns an error; `Cleanup()` does not.

## Tooling

- Do not name directories `gen/` — the user's global gitignore excludes them.
- `mdformat` pre-commit hook auto-fixes markdown files on first run, causing `just ci-check` to fail. Re-run after the auto-fix passes.
- `govulncheck` may fail with Go 1.26 if built against an older Go version. Rebuild with `go install golang.org/x/vuln/cmd/govulncheck@latest`.

## Releasing

- `go generate ./...` was removed from `.goreleaser.yaml` hooks — `oapi-codegen` is a mise tool, not a Go tool. Generated code is already committed.
- Goreleaser's `milestones.close` expects `vX.Y.Z` format — manual milestone names (e.g., `v0.6`) may warn but won't fail.
