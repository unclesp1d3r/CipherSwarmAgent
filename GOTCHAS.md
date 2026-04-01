# Gotchas

Known pitfalls and edge cases. Referenced from AGENTS.md.

## Linting

- `charmbracelet/log` methods take `func(msg any, keyvals ...any)` — not `func(msg string, ...)`. Functions that accept a log callback (e.g., `ValidateAndFilterDevices`) must use `any` for the message parameter.

- `//go:fix inline` directives conflict with `gocheckcompilerdirectives` — avoid adding them.

- `just ci-check` includes a `go fix -diff` dry-run whose output is informational only, not a failure.

- `contextcheck` flags functions not propagating context — use `//nolint:contextcheck // reason` when the callee genuinely cannot accept a context parameter.

- `revive` requires each exported constant to have its own `// ConstName is...` doc comment. A group comment alone doesn't satisfy it.

- `//nolint:revive` does NOT suppress `staticcheck` for the same issue — list all linters (e.g., `//nolint:revive,staticcheck`).

- `//nolint:errcheck` does NOT suppress `gosec` G104 (unhandled error return) — list both (e.g., `//nolint:gosec,errcheck // G104 - reason`).

- `containedctx` flags `context.Context` stored in structs — use `//nolint:containedctx // reason` when the context is intentionally part of the struct lifecycle.

- `gocritic` `whyNoLint` rule requires every `//nolint:` directive to include an explanation. Bare `//nolint:linter` directives fail CI.

- A blank `//` line between a doc comment and a type/func declaration breaks the linter's comment association — keep them contiguous.

- `errorsastype` suggests replacing `errors.As(err, &target)` with generic `errors.AsType[T]()` (Go 1.26+). Adopt when touching affected code; don't refactor unrelated lines.

- `.golangci.yml` has `fix: true` — `nolintlint` auto-strips `//nolint:` directives that don't suppress an active warning. Don't add nolint for rules that aren't actually firing; verify with a clean cache first (`golangci-lint cache clean`).

- `gosec G118` flags goroutines that use `context.Background()` or don't propagate the parent context. Use `//nolint:gosec // G118 - reason` as a standalone comment above `go func()`.

- `gosec G204` does NOT fire on `exec.CommandContext` when the binary path comes from a function parameter or internal function return — don't add `//nolint:gosec // G204` unless verified with a clean lint run.

- `gosec G304` does NOT fire on `os.Open` in test helper packages — don't add `//nolint:gosec // G304` unless verified with a clean lint run.

- `durationcheck` flags `time.Duration * time.Duration` — use `int64` intermediate for multipliers (e.g., `time.Duration(int64(1) << shift)`).

- `gocritic` `importShadow` fires when a parameter name matches an imported package name (e.g., `config` parameter shadowing `lib/config` import). Rename the parameter.

- `revive` stutter rule applies to exported type names (interfaces, structs), not just constants — e.g., `progress.ProgressTracker` stutters, rename to `progress.Tracker`.

- `revive` `redefines-builtin-id` flags local variables that shadow Go builtins (`real`, `imag`, `complex`, `new`, `make`, `len`, `cap`, etc.). Rename the variable — e.g., `real` → `result`.

- `errcheck` flags discarded errors (`val, _ := fn()`) — even when intentional. Either handle the error explicitly or log at Debug level. `//nolint:errcheck` is acceptable but must include a reason per `gocritic` `whyNoLint`.

- `mnd` (magic number detector) flags bare numeric literals in conditions and expressions (e.g., `len(matches) < 2`). Extract a named constant (e.g., `const hashInfoMatchGroups = 2`). Applies to non-obvious numbers; `0` and `1` are usually exempt.

## golines & nolint Comments

- `golines` (max-len 120) splits long lines, moving `//nolint:` off the flagged line. Keep nolint reasons short so total line stays under 120 chars.
- When `golines` splits multi-line expressions, even short inline `//nolint:` comments get displaced. Place nolint as a standalone comment on the line above.
- `//nolint:revive` on `APIError`, `Error_`, and `APIClient` can be stripped by `golines` or other formatters. Verify they survive after running formatters.

## Hashcat Output Routing

- Hashcat `event_log_warning` and `event_log_advice` go to **stdout**, not stderr — only `event_log_error` goes to stderr. Hash parse errors (Token length exception, Separator unmatched, etc.) are warnings, so they appear on stdout.
- `--status-json` only structures the periodic status display — errors/warnings remain plain text regardless of output mode.
- v7.x changed per-hash error prefix from `Hashfile '...'` to `Hash parsing error in hashfile: '...'` — patterns must match both.
- Machine-readable error format (`<file>:<line>:<hash>:<error>`) uses colons as delimiters, but many hash types also contain colons (MD5:salt, PBKDF2 `sha256:20000:salt`, Kerberos). The regex uses non-greedy `(.+?)` for the file path capture — greedy `(.+)` misparses by consuming hash colons into the file group. Any new colon-delimited parsing must account for hash types with embedded colons.

## Code Generation (oapi-codegen)

- oapi-codegen v2 config does NOT support `input-spec` — the spec path must be a positional CLI argument.
- `docs/swagger.json` is downloaded from the CipherSwarm server — never modify it locally. Open issues on `unclesp1d3r/CipherSwarm` for spec problems.
- During coordinated client+server development, local `swagger.json` changes are acceptable. CodeRabbit may flag these as policy violations when the upstream server PR hasn't merged yet — these are false positives.
- `lib/api/client.gen.go` is auto-generated — never manually modify. Regenerate with `just generate`.
- oapi-codegen generates a `Client` struct — the hand-written aggregate interface is named `APIClient` (with `//nolint:revive` for stutter) to avoid the conflict. `APIError` and `SetTaskAbandonedError.Error_` also have `//nolint:revive`.
- Use `exclude-schemas` in `lib/api/config.yaml` when a generated type needs manual customization (e.g., `ErrorObject` excluded so it can implement the `error` interface).
- oapi-codegen's `Parse*Response` methods read and close `HTTPResponse.Body` during parsing. Use the parsed `Body` byte slice (`resp.Body`), not `resp.HTTPResponse.Body` (already drained and closed).
- When an API method returns HTTP 200, always guard `resp.JSON200 == nil` — oapi-codegen silently sets it to nil if JSON unmarshaling fails.
- oapi-codegen emits anonymous structs for inline OpenAPI schemas — hand-written struct literals must exactly match JSON tags (including `omitempty`). Use constructor helpers in `lib/api/` (e.g., `NewErrorMetadata`) to co-locate coupling with the generated code. The root fix is extracting inline schemas to named `$ref` components in the server spec.

## Error Handling

- Generated types with an `Error` field (e.g., `ErrorObject`) can't implement Go's `error` interface — use a wrapper type like `api.APIError`.
- `cserrors.LogAndSendError` returns the `err` parameter directly — always pass a non-nil error in error paths, or callers will see success.

## Configuration

- `SetDefaultConfigValues` runs before config files/env vars are loaded. Never derive defaults from other viper keys (e.g., `viper.GetString("data_path")`) — they only return the registered default, not user overrides. Derive in `SetupSharedState` instead.
- `bridgeDeprecatedFlags` must use `cmd.Root().PersistentFlags()` — `cmd.Flags()` only returns local (non-persistent) flags and all agent flags are persistent. Also skip bridging when `canonical.Changed` is true (user explicitly set the canonical flag).

## Download (grab/v3)

- `grab.Response.Err()` blocks until the transfer goroutine closes the response body and flushes the file. On context cancellation, always call `resp.Err()` before returning — early return without it causes resource leaks and races. See `TestGrabDownloader_CancellationWaitsForFinalization`.
- `resp.Err()` finishes quickly after context cancellation — client-side finalization is independent of the server handler lifecycle. Blocking a server handler (handler gate) does NOT hold `resp.Err()`. To test cancellation ordering, gate `dp.Finish()` via a `finalizationTracker` instead — see `TestGrabDownloader_CancellationWaitsForFinalization`.
- `grab.Response.Size()` returns -1 when the server doesn't send `Content-Length`. `progress.StartTracking` treats negative totalSize as unknown (0).

## Testing

- `hashcat.NewTestSession` creates sessions with `proc=nil` — calling `Start()` panics. Tests that need `runBenchmarkTask` or `UpdateBenchmarks` to actually run cannot be unit tested without refactoring to accept an interface.
- `.golangci.yml` has `fix: true` — the linter auto-transforms `assert.True(t, errors.Is(err, sentinel))` → `assert.ErrorIs(t, err, sentinel)` and removes the now-unused `errors` import. Don't manually add `errors` imports for testify-only assertions.
- `agentstate.State` contains `atomic.Bool` and `sync.RWMutex` — never copy the struct. Use per-field save/restore in test helpers and getter/setter methods for synchronized fields.
- `hashcat` package tests cannot import `testhelpers` (circular: testhelpers -> hashcat). Use local test helpers.
- Package-level `var` test fixtures get mutated by production code across subtests. Use factory functions (e.g., `newSampleData()`) that return fresh copies to prevent cross-test contamination.
- `nxadm/tail` `Cleanup()` returns void — do not attempt to capture a return value. `Stop()` returns an error; `Cleanup()` does not.
- httpmock URL patterns must match the generated client paths (check `client.gen.go`), not the Go method names. E.g., `SetTaskAbandoned` hits `/tasks/{id}/abandon`, not `/tasks/{id}/set_abandoned`.
- `httpmock.ResponderFromResponse` with manually constructed `*http.Response` triggers `bodyclose` lint. Use `httpmock.NewJsonResponderOrPanic` for JSON mocks instead.
- `os.Symlink` requires elevated privileges (or Developer Mode) on Windows. Tests using symlinks must skip on Windows: `if runtime.GOOS == "windows" { t.Skip("os.Symlink requires elevated privileges on Windows") }`.
- `os.Chmod(0o000)` does not prevent reading when running as root/elevated privileges. Tests relying on permission denial must also skip when elevated: attempt `os.Open` on the restricted file; if it succeeds, `t.Skip("running with elevated privileges")`.
- `os.DirEntry.Type()` can return 0 (unknown) on some filesystems/platforms, causing `IsRegular()` to return false for real files. When filtering directory entries, fall back to `entry.Info()` (calls `os.Lstat`) when type is unknown. See `isRegularFile()` in `lib/hashcat/session_dir.go`.
- For subprocess tests needing `CmdFactory` injection (e.g., `lib/devices/`), use the `TestHelperProcess` + `os.Args[0]` + env vars pattern with a `CmdFactory` field on the struct under test. This avoids shell-script stubs and works cross-platform. See `helperCmdFactory` in `lib/devices/devices_test.go`.

## Tooling

- Do not name directories `gen/` — the user's global gitignore excludes them.
- `mdformat` pre-commit hook auto-fixes markdown files on first run, causing `just ci-check` to fail. Re-run after the auto-fix passes.
- `govulncheck` may fail with Go 1.26 if built against an older Go version. Rebuild with `go install golang.org/x/vuln/cmd/govulncheck@latest`.
- IDE/editor post-save hooks (e.g., goimports, golines, LSP actions) may refactor code beyond the original edit (e.g., changing return types, removing unused sentinels). Check the file state after saves before making further dependent edits.
- `.golangci.yml` `fix: true` auto-refactors string concatenation in loops to `strings.Builder`, but may leave dead variables (e.g., the original `result` string). Always review auto-fixed code for leftover artifacts.

## Releasing

- `go generate ./...` was removed from `.goreleaser.yaml` hooks — `oapi-codegen` is a mise tool, not a Go tool. Generated code is already committed.
- Goreleaser's `milestones.close` expects `vX.Y.Z` format — manual milestone names (e.g., `v0.6`) may warn but won't fail.
