# AGENTS

Standards and architecture for the CipherSwarmAgent project.

@GOTCHAS.md

## Code Quality Policy

- **Zero tolerance for tech debt.** Never dismiss warnings, lint failures, or CI errors as "pre-existing" or "not from our changes." If CI fails, investigate and fix it — regardless of when the issue was introduced. Every session should leave the codebase better than it found it.

## Architecture

### Core Concepts

- **Purpose:** A distributed agent for CipherSwarm, managing hash-cracking tasks at scale across Linux, macOS, and Windows.
- **Entrypoint:** `main.go` initializes the Cobra CLI application defined in `cmd/root.go`.
- **Configuration:** Environment variables, CLI flags (Cobra/Viper), and an auto-generated YAML config file.

### Task Lifecycle & API Contract

The agent is a long-lived CLI client interacting with the CipherSwarm server API:

1. **Registration & Heartbeat:** Register with server, send regular heartbeats.
2. **Polling for Tasks:** Request new tasks from `/api/v1/client/tasks/new`.
3. **Task Execution:** Accept task, download resources, launch hashcat, submit status/cracks.
4. **Completion & Error Handling:** Report exhaustion, submit structured errors, notify on shutdown.

- All API interactions must adhere to the v1 Agent API contract.
- Implement exponential backoff for failed API requests.

### Hashcat Session Files

- **Session file location:** Hashcat writes `.log`, `.pid`, and default `.restore` files to its session directory — NOT the process CWD. On POSIX: `~/.hashcat/sessions/` (legacy) or `$XDG_DATA_HOME/hashcat/sessions/` or `~/.local/share/hashcat/sessions/`. On Windows: the hashcat binary's install directory. Use `hashcatSessionDir(binaryPath)` in `lib/hashcat/session_dir.go` to resolve. The `--restore-file-path` flag only relocates the `.restore` file, not `.log`/`.pid`.
- **Session naming:** All agent-created hashcat sessions use the `sessionPrefix` constant (`"attack-"`) from `lib/hashcat/session_dir.go`. Use this constant — don't hardcode `"attack-"`.
- **Solution reference:** See `docs/solutions/logic-errors/hashcat-session-file-cleanup-wrong-directory.md` for the full investigation, root cause, and prevention strategies.

### Hashcat Output Parsing

- **stdout vs stderr:** Hashcat routes `event_log_warning` (hash parse errors) and `event_log_advice` (summary blocks) to **stdout**. Only `event_log_error` goes to stderr. `--status-json` does NOT produce JSON error objects — only affects periodic status output.
- **Error parser patterns** (`lib/hashcat/errorparser.go`): `ClassifyStderr` classifies both stderr and stdout lines using `FindStringSubmatch` + optional `contextExtractor` functions that populate `ErrorInfo.Context map[string]any`. When adding new patterns, include an extractor to populate well-known keys (`error_type`, `device_id`, `hashfile`, `line_number`, `affected_count`, `total_count`, `terminal`, `backend_api`, `api_error`).
- **Version-specific formats:** v6.x uses `Hashfile '<file>' on line N (<hash>): <error>`, v7.x changed to `Hash parsing error in hashfile: '<file>' on line N (<hash>): <error>`. Machine-readable mode (`--machine-readable`) uses `<file>:<line>:<hash>:<error>`. Patterns must handle both versions.
- **Stdout→StderrMessages routing:** Non-JSON stdout lines are classified by `ClassifyStderr` in `handleStdout()` (`lib/hashcat/session.go`). Error/warning categories are forwarded as `ErrorInfo` (not raw strings) to the `StderrMessages` channel. Consumers: `lib/task/runner.go`, `lib/benchmark/parse.go`. Info/success categories are logged locally only.
- **Exit codes** (`lib/hashcat/exitcode.go`): Constants and classifications are sourced from hashcat `types.h` — not observed behavior. `ExitCodeInfo` includes `Context map[string]any` with `exit_code_name`.
- **Shell exit code normalization:** On Unix, hashcat's negative exit codes (e.g., -11) arrive as unsigned 8-bit (e.g., 245). `normalizeExitCode` in `lib/task/runner.go` converts 245-255 → -11 to -1 before `ClassifyExitCode`.
- **No raw hashcat lines in logs:** `handleStderr` and `classifyAndForwardStdout` log classified metadata (`category`, `severity`) — never raw `line` content, which may contain hashes or file paths.
- **Colon-aware parsing:** Many hash types contain colons (MD5:salt, PBKDF2 `sha256:20000:salt`, Kerberos `krb5asrep$23$user@REALM$hash`). Any regex parsing colon-delimited hashcat output (especially machine-readable `<file>:<line>:<hash>:<error>`) must use non-greedy captures for the file path (`(.+?)`) or anchor on the known numeric line field — greedy `(.+)` will consume hash colons into the file capture group.
- **Machine-readable regex strategy:** The generalized pattern `^(.+?):(\d+):(.+):([^:]+)$` uses non-greedy `(.+?)` for file path, greedy `(.+)` for hash (captures colons in hash types), and `([^:]+)` for error text (no `strparser()` error contains colons). Using `(.+?)` for the hash group breaks colon-heavy hashes like `sha256:20000:salt`.
- **Distinct error_type per failure mode:** Each error pattern's `contextExtractor` must set an `error_type` that accurately describes the specific failure — don't reuse extractors across semantically different patterns (e.g., `kernel_build_failed` vs `kernel_create_failed`, not a shared `kernel_build_failed` for both). Use `extractIntField(errorType, fieldName)` factory for patterns that only need a fixed `error_type` and a single integer capture.
- **Structured error metadata:** `cserrors.WithContext(map[string]any)` merges extracted fields into the API error metadata `other` map. Always pair with `WithClassification` when sending classified errors.
- **Metadata key precedence:** In `SendAgentError`, context fields are copied first, then reserved keys (`platform`, `version`, `category`, `retryable`) are set — so reserved keys always win over context collisions.
- **Error-specific classification in RunTask:** `NewHashcatSession` failures are branched: hash file errors (`ErrHashFileNotReadable`, `ErrHashFileEmpty`, `ErrHashFileWhitespaceOnly`) get `WithClassification("file_access", false)` + `WithContext`; all other failures use `LogAndSendError` without classification. Follow this pattern when adding new classified error paths.

### Device Validation Flow

- **Manager → DeviceManager wiring:** Both `benchmark.Manager` and `task.Manager` hold a `DeviceManager *devices.DeviceManager` field, set in `agent.StartAgent` and `handleReload` (may be nil if enumeration failed). Before creating `hashcat.Params`, each manager calls `validateDevicesForSession()` → `devices.ValidateAndFilterDevices()`, producing `ValidatedDevices` with filtered IDs. `hashcat.Params` has `ValidatedBackendDeviceIDs`, `ValidatedOpenCLDevices`, and `BackendDevicesValidated` fields that `appendDeviceFlags` prefers over raw strings.
- **Benchmark device enrichment:** `handleBenchmarkStdOutLine` and `drainStdout` in `lib/benchmark/parse.go` accept a `*devices.DeviceManager` parameter for optional device-name logging. Pass `nil` when no device manager is available (e.g., in tests). The numeric `result.Device` string must never be replaced — it's used by `createBenchmark` for the API.
- **handleReload device safety:** Always create a fresh `DeviceManager{}` — never reuse across re-enumeration. Set to `nil` on enumeration failure so managers don't use stale device data.
- **Availability parsing:** `parseDeviceOutput` detects "Status...: Skipped" and standalone "* Device #N: Skipped" lines, setting `Device.IsAvailable = false`. `ValidateDeviceIDsDetailed` classifies IDs as valid/unknown/unavailable.

## Go

The project follows standard, idiomatic Go practices (version 1.26+).

### Project Structure

- `cmd/`: Main application entry points using the Cobra framework.
- `lib/`: Core agent logic, decomposed into focused sub-packages:
  - `agent/`: Agent lifecycle — startup, heartbeat loop, task polling, shutdown.
  - `api/`: API client layer — generated client (`client.gen.go`), wrapper (`client.go`), errors (`errors.go`), interfaces (`interfaces.go`), mocks (`mock.go`). Transport chain: `http.Transport` → `CircuitTransport` → `RetryTransport` → `http.Client`.
  - `apierrors/`: Generic API error handler (`Handler`) for log-or-send error handling.
  - `arch/`: OS-specific abstractions (Linux, macOS, Windows). Platform identity comes from `host.InfoStat.OS` (in `UpdateAgentMetadata`), not from `arch` — don't add `GetPlatform()` functions here.
  - `benchmark/`: Benchmark execution, caching, and submission.
  - `config/`: Configuration defaults as exported constants — referenced by `cmd/root.go`.
  - `cracker/`: Hashcat binary discovery, archive extraction, version detection.
  - `devices/`: Hashcat-native device enumeration via `hashcat -I`. `DeviceManager` parses backend devices (OpenCL/CUDA/Metal), tracks availability, and validates device ID selections. `CmdFactory` type enables test injection. `ValidateAndFilterDevices` is the main integration point for task/session setup. Nil `DeviceManager` (enumeration failed) → `getDevicesList` returns empty slice, not an error — no test-session fallback exists.
  - `cserrors/`: Centralized error reporting — `SendAgentError`, `LogAndSendError`, `ErrorOption`.
  - `display/`: User-facing output (status, progress, benchmark results).
  - `downloader/`: File download with checksum verification. Downloads use `grab/v3` with a `Getter` interface for testability. `grabDownloader` implements `Getter`; `downloadWithRetry` handles exponential backoff against any `Getter`. `grab.Response.Err()` blocks until transfer finalizes — always call it before returning from cancellation paths.
  - `hashcat/`: Hashcat session management, parameters, and output parsing.
  - `progress/`: Progress calculation utilities. Exposes `Tracker` interface (`StartTracking(filename, totalSize) → DownloadProgress`) and `DownloadProgress` interface (`Update(bytesComplete)`, `Finish()`). `DefaultProgressBar` wraps `cheggaaa/pb`.
  - `task/`: Task lifecycle — accept, run, status updates, crack submission, downloads.
  - `testhelpers/`: Shared test fixtures, HTTP mocking, and state setup.
  - `zap/`: Zap file monitoring for cracked hashes.
- `agentstate/`: Global agent state, loggers, and synchronized fields.
- `docs/`: Project documentation, including the OpenAPI specification.
  - `docs/plans/`: Working design documents — NOT committed to git.

### Formatting & Linting

- **Formatting:** `gofmt`. **Linting:** `golangci-lint` v2 (`mise x -- golangci-lint run ./...`).
- **gosec nolint style:** Use per-site `//nolint:gosec // G7XX - <reason>` with specific rule ID. gosec runs via golangci-lint only (no standalone binary); `#nosec` annotations are not used.
- See GOTCHAS.md for linting edge cases (`golines`, `contextcheck`, `revive`, `gocritic`).

### Naming Conventions

- **Packages/Files**: `snake_case`. **Interfaces/Structs**: `PascalCase`. **Functions/Methods**: `camelCase`/`PascalCase`. **Variables**: `camelCase`.
- **CLI Flags**: `kebab-case`. Use `Bool`/`String`/`Int`/`Duration` for flags without shorthand — only use `BoolP`/`StringP` variants when providing a short flag letter.
- **Deprecated flag aliases**: Old underscore-style flags (e.g., `--api_token`) are registered as hidden deprecated aliases in `registerDeprecatedAliases()` in `cmd/root.go`. They are NOT bound to Viper — values are bridged to canonical kebab-case flags via `bridgeDeprecatedFlags()` in `PersistentPreRun`. When adding new flags, use kebab-case only — no alias needed.

### Error Handling

- Always check errors. Use `fmt.Errorf` with `%w` to wrap. Use stdlib `errors` only — not `github.com/pkg/errors`.
- Use `fmt.Errorf("%w: %w", sentinel, inner)` (Go 1.20+) to wrap multiple errors — preserves both in the `errors.Is`/`errors.As` chain. Never use `%s` with `.Error()` for wrapped errors.
- Use `defer` for resource cleanup. `panic` is not for normal control flow.
- Never silently correct invalid inputs — always log a warning. Guard against negative values in bit shifts.
- Handle `obj == nil && err == nil` as a separate error case for API responses to prevent nil pointer dereferences.
- In deferred cleanup, use `os.IsNotExist` to skip already-removed files. Include file paths in error messages.
- For data-critical files (cracked hashes, downloads), log `file.Close()` errors instead of discarding.
- **Error reporting:** Use `SendAgentError(ctx, msg, task, severity, opts ...ErrorOption)` for all error reporting. Add metadata via `WithClassification(category, retryable)`. `cserrors.LogAndSendError` delegates to `SendAgentError` (includes platform/version metadata). Always pass a non-nil error — it returns `err` directly. API submission is skipped only when `APIClient` is uninitialized.
- **`LogAndSendError` return value:** `LogAndSendError` returns `err` — always capture or `return` it. Discarding the return value triggers `errcheck` lint failure.
- **Classified vs. generic error reporting:** Use `SendAgentError` with `WithClassification`/`WithContext` only when the error matches a specific known category (e.g., hash-file validation → `file_access`). For unclassified or general failures, use `LogAndSendError` to avoid mislabeling errors with incorrect category/retryability metadata.

### Concurrency

- Use goroutines and channels for async operations. Prefer channel-based communication over mutexes.
- Use `context.Context` for cancellation and deadlines in all long-running or networked operations.
- **Synchronized state:** Cross-goroutine fields in `agentstate.State` use `atomic.Bool` or `sync.RWMutex`. Always use getter/setter methods — never access directly. `APIClient` uses `GetAPIClient()`/`SetAPIClient()` with `sync.RWMutex`.
- **Context propagation:** `StartAgent()` creates a cancellable context threaded through all goroutines. Use `ctx` for stoppable operations; `context.Background()` for must-complete operations (e.g., `AbandonTask`), with `//nolint:contextcheck // must-complete: reason`.
- **Data-loss logging:** When a channel send is skipped due to `ctx.Done()`, always log the dropped value at Warn level (e.g., dropped cracked hashes, process exit status). Silent data loss during shutdown hides bugs.
- **Partial result preservation:** Long-running sessions (benchmarks, tasks) should cache partial results to disk on context cancellation for retry on next agent startup. Use atomic writes (write to temp file, then `os.Rename`) for crash safety.
- **Context-aware sleep:** Use `sleepWithContext(ctx, duration)` (in `lib/agent/agent.go`) instead of `time.Sleep`.
- **Context-aware retry:** Retry loops with backoff must use `time.NewTimer` + `Stop()` in a `select` with `ctx.Done()` (not `time.After` or `time.Sleep`). `time.After` leaks timers on cancellation. See `downloadWithRetry` in `lib/downloader/downloader.go`.
- **Shared transport state:** The circuit breaker instance (`lib/agent/transport_config.go`) survives API client rebuilds via a package-level var passed through `TransportConfig.CircuitBreaker`. When adding similar shared transport state, follow this pattern.
- Run tests with `-race` flag to detect data races.

### Performance

- `regexp.MustCompile` at package level, never inside functions.
- `os.Remove` + `os.IsNotExist(err)` over `os.Stat` then `os.Remove`.
- Cache `[]byte(str)` when passing to both `json.Valid` and `json.Unmarshal`.
- `chan struct{}` for signal-only channels. `filepath.Join` (not `path.Join`) for filesystem paths.
- Configuration defaults live in `lib/config/config.go` as exported constants.

### Logging & Configuration

- Use structured logger (`charmbracelet/log`). Never log secrets.
- **Logger method signature:** `charmbracelet/log` methods (`Warn`, `Info`, etc.) take `func(msg any, keyvals ...any)`. Functions accepting a log callback must match this signature — not `func(msg string, ...)`.
- Use `spf13/viper` for config. Treat `viper.WriteConfig()` failures as non-fatal warnings.
- **Config access:** Read from `agentstate.State` (wired in `SetupSharedState()`), not `viper.Get*()` directly.
- Validate numeric/duration config fields in `SetupSharedState()` — clamp invalid values to defaults with a warning.
- **Server-recommended config validation:** `applyRecommendedSettings` in `lib/agentClient.go` uses `config.ClampDuration`/`config.ClampInt` to cap server values. Never trust server-recommended values without clamping — treat them as external input.

### Tooling

- **Code Generation:** `oapi-codegen` via `mise.toml`. `just generate` runs it against `docs/swagger.json`. After regenerating, run `go mod tidy`.
- **API Client Architecture:** `AgentClient` wraps `ClientWithResponses` (single field), implements `APIClient` interface. All sub-clients must use the generated client — never hand-roll raw HTTP endpoints. Error types live in `errors.go`. Use `errors.As` to extract `*api.APIError`.
- **CI:** `just ci-full` for comprehensive checks (pre-commit, lint, test, SBOM, release, docs). `just ci-check` for the fast subset.
- **Dev tools:** `mise` manages all toolchains via `mise.toml`.
- **Dependencies:** No vendor directory — never run `go mod vendor`. Use `just update-deps`.
- **Docs:** mkdocs installed via mise (`pipx:mkdocs` with `mkdocs-material` bundled). Use `just docs-build`.
- See GOTCHAS.md for code generation edge cases and tooling pitfalls.

### Releasing

- **Process:** Merge to `main`, tag (`git tag vX.Y.Z`), push tag, run `just release` locally.
- **Prereqs:** `GITHUB_TOKEN` with `write:packages` scope; `docker login ghcr.io` for containers.
- **Skip docker:** `mise x -- goreleaser release --clean --skip docker`.

### Dependencies

- Downloads use `cavaliergopher/grab/v3`. `hashicorp/go-getter` was removed (#122) along with its ~78 transitive deps.

### Testing

- Table-driven tests in `_test.go` files within the same package. Naming: `TestFunctionName_Scenario`.
- Mock network/OS interactions. Extract business logic from external-process invocations for independent testing.
- Use `lib/testhelpers/` for fixtures (`SetupHTTPMock`, `SetupTestState`), `error_helpers.go` for test errors.
- Use `any` (not `interface{}`), `require.Error/NoError` (not `assert`), `t.Cleanup` (not `defer`), `atomic.Int32` for mock counters.
- MockClient sub-client accessors return default mocks (not nil) to prevent nil pointer panics.
- When adding or removing `agentstate.State` fields, grep all test helpers and reset functions — including `saveAndRestoreState` in `agent_test.go`, `ResetTestState`, `SetupTestState`, and `SetupMinimalTestState` in `testhelpers/state_helper.go`.
- For cross-platform subprocess tests, use the Go test helper process pattern (`TestHelperProcess` + `os.Args[0]` + env vars) instead of OS-specific binaries like `sleep` or `true`.
- Use `hashcat.NewTestSession(skipStatusUpdates)` (in `lib/hashcat/session_test_helpers.go`) to create mock sessions — never construct `hashcat.Session` struct literals directly from `testhelpers`, as it bypasses constructor invariants.
- `toCmdArgs()` tests in `params_test.go` must pass real file paths for all validated parameters. Use `createTestHashFile(t)` for hash files and `createTestFile(t, dir, name, content)` for wordlists/rules/masks. Dummy paths like `/tmp/hashes.txt` will fail validation.
- Status fixture slices (`RecoveredHashes`, `RecoveredSalts`, `Progress`) must have ≥2 elements (`display.MinStatusFields`). Single-element slices cause silent drops in `handleStatusUpdate` and `display.JobStatus`.
- `MockUpdateAgentWithCapture` captures the request body's `Devices` field for assertion. Response must be the `Agent` struct directly (not wrapped in `{"agent": ...}`) with `Content-Type: application/json` — oapi-codegen's `ParseUpdateAgentResponse` unmarshals into `api.Agent` directly.
- Run `go test -race ./...` to detect data races.

## Git

### Branching Model

- Feature branches for all work. Never commit directly to `main` — all changes go through pull requests.

### Commit Messages

Conventional Commits: `<type>(<scope>): <description>`. Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`. Enforced by `.gitlint` and CI.

### Changelog

`CHANGELOG.md` is auto-generated from commit messages using `git-cliff` (`just changelog`).

## CI/CD & Docker

- **GitHub Actions:** Workflows in `.github/workflows/` automate linting, testing, building, and releases.
- **Docker:** `Dockerfile` for the main container; `Dockerfile.releaser` for GoReleaser pipeline.

## Documentation

- **MkDocs:** Markdown in `docs/`, built with `mkdocs` (Material theme). API docs use OpenAPI v3 spec from the CipherSwarm server repo.

# Agent Rules <!-- tessl-managed -->

@.tessl/RULES.md follow the [instructions](.tessl/RULES.md)
