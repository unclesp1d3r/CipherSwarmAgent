---
inclusion: fileMatch
fileMatchPattern: '*.go'
---

# Go Conventions for CipherSwarmAgent

Project-specific Go conventions. For general rules, see AGENTS.md.

## 1. Project Structure

- `cmd/` for CLI entrypoint (Cobra).
- `lib/` for core agent logic, decomposed into focused sub-packages:
  - `agent/` — lifecycle (startup, heartbeat, task polling, shutdown)
  - `api/` — API client layer (generated `client.gen.go`, wrapper `client.go`, interfaces, mocks)
  - `apierrors/` — generic API error handler (`Handler`)
  - `arch/` — OS-specific abstractions (Linux, macOS, Windows)
  - `benchmark/` — benchmark execution, caching, and submission
  - `config/` — configuration defaults as exported constants
  - `cracker/` — hashcat binary discovery and extraction
  - `cserrors/` — centralized error reporting (`SendAgentError`, `LogAndSendError`)
  - `display/` — user-facing output (status, progress, benchmarks)
  - `downloader/` — file download with checksum verification
  - `hashcat/` — hashcat session management, parameters, and output parsing
  - `progress/` — progress calculation utilities
  - `task/` — task lifecycle (accept, run, status, crack submission)
  - `testhelpers/` — shared test fixtures, HTTP mocking, state setup
  - `zap/` — zap file monitoring for cracked hashes
- `agentstate/` for global agent state, loggers, and synchronized fields.

## 2. Code Organization

- **Files**: `snake_case.go`. **Interfaces/Structs**: `PascalCase`. **Functions**: `camelCase`/`PascalCase`.
- **CLI Flags**: `kebab-case`. Use `Bool`/`String`/`Int`/`Duration` (not `BoolP`/`StringP`) unless providing a short flag letter.
- Keep packages focused and small. Prefer explicit, minimal interfaces for testability.
- Avoid global mutable state except for `agentstate.State`.

## 3. Error Handling

- Always check errors. Use `fmt.Errorf` with `%w` for wrapping. Use stdlib `errors` only (not `github.com/pkg/errors`).
- Use `defer` for resource cleanup. Never use `panic` for normal control flow.
- Never silently correct invalid inputs — always log a warning.
- Handle `obj == nil && err == nil` as a separate error case for API responses (prevents nil pointer dereferences).
- In deferred cleanup, use `os.IsNotExist` to skip already-removed files. Include file paths in error messages.
- For data-critical files (cracked hashes, downloads), log `file.Close()` errors instead of discarding.
- **Error reporting**: Use `cserrors.SendAgentError(msg, task, severity, opts ...ErrorOption)` for all error reporting. Add metadata via `WithClassification(category, retryable)`. Always pass a non-nil error.

## 4. Concurrency & State

- Use goroutines and channels for async tasks. Prefer channel-based communication over mutexes.
- Use `context.Context` for cancellation and deadlines in all long-running or networked operations.
- **Synchronized state**: Fields in `agentstate.State` use `atomic.Bool` or `sync.RWMutex`. Always use getter/setter methods.
- **Context propagation**: Use `ctx` for stoppable operations; `context.Background()` for must-complete operations (e.g., `AbandonTask`), with `//nolint:contextcheck // must-complete: reason`.
- **Data-loss logging**: When a channel send is skipped due to `ctx.Done()`, always log the dropped value at Warn level.
- **Context-aware sleep**: Use `sleepWithContext(ctx, duration)` (in `lib/agent/agent.go`) instead of `time.Sleep`.
- Run tests with `-race` flag to detect data races.

## 5. Configuration

- Use `spf13/viper` for config: env vars, CLI flags, and YAML.
- Configuration defaults live in `lib/config/config.go` as exported constants.
- **Config access**: Read from `agentstate.State` (wired in `SetupSharedState()`), not `viper.Get*()` directly.
- Validate numeric/duration config fields in `SetupSharedState()` — clamp invalid values to defaults with a warning.

## 6. Logging

- Use structured logging (`charmbracelet/log`). Never log secrets or sensitive data.
- Log at appropriate levels: Info for normal ops, Warn for recoverable issues and dropped data, Error for failures.
- When dropping data during context cancellation, always log at Warn level.

## 7. Performance

- `regexp.MustCompile` at package level, never inside functions.
- `os.Remove` + `os.IsNotExist(err)` over `os.Stat` then `os.Remove`.
- Cache `[]byte(str)` when passing to both `json.Valid` and `json.Unmarshal`.
- `chan struct{}` for signal-only channels. `filepath.Join` (not `path.Join`) for filesystem paths.

## 8. Testing

- Table-driven tests in `_test.go` files within the same package. Naming: `TestFunctionName_Scenario`.
- Use `lib/testhelpers/` for fixtures (`SetupHTTPMock`, `SetupTestState`).
- Use `any` (not `interface{}`), `require.Error/NoError` (not `assert`), `t.Cleanup` (not `defer`).
- `hashcat` package tests cannot import `testhelpers` (circular dependency) — use local test helpers.
- Use factory functions (not package-level `var`) for test fixtures to prevent cross-test contamination.
- Run `go test -race ./...` to detect data races.

## 9. Linting

- **Formatting**: `gofmt`. **Linting**: `golangci-lint` v2 (`mise x -- golangci-lint run ./...`).
- **gosec nolint style**: Use `//nolint:gosec // G7XX - <reason>` with specific rule ID.
- Keep nolint reasons short so total line stays under 120 chars (`golines` limit).
- When `golines` splits multi-line expressions, place nolint as a standalone comment on the line above.
- See GOTCHAS.md for additional linting edge cases.
