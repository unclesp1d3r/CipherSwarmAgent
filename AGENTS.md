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

## Go

The project follows standard, idiomatic Go practices (version 1.26+).

### Project Structure

- `cmd/`: Main application entry points using the Cobra framework.
- `lib/`: Core agent logic, decomposed into focused sub-packages:
  - `agent/`: Agent lifecycle — startup, heartbeat loop, task polling, shutdown.
  - `api/`: API client layer — generated client (`client.gen.go`), wrapper (`client.go`), errors (`errors.go`), interfaces (`interfaces.go`), mocks (`mock.go`).
  - `apierrors/`: Generic API error handler (`Handler`) for log-or-send error handling.
  - `arch/`: OS-specific abstractions (Linux, macOS, Windows).
  - `benchmark/`: Benchmark execution, caching, and submission.
  - `config/`: Configuration defaults as exported constants — referenced by `cmd/root.go`.
  - `cracker/`: Hashcat binary discovery, archive extraction, version detection.
  - `cserrors/`: Centralized error reporting — `SendAgentError`, `LogAndSendError`, `ErrorOption`.
  - `display/`: User-facing output (status, progress, benchmark results).
  - `downloader/`: File download with checksum verification.
  - `hashcat/`: Hashcat session management, parameters, and output parsing.
  - `progress/`: Progress calculation utilities.
  - `task/`: Task lifecycle — accept, run, status updates, crack submission, downloads.
  - `testhelpers/`: Shared test fixtures, HTTP mocking, and state setup.
  - `zap/`: Zap file monitoring for cracked hashes.
- `agentstate/`: Global agent state, loggers, and synchronized fields.
- `docs/`: Project documentation, including the OpenAPI specification.

### Formatting & Linting

- **Formatting:** `gofmt`. **Linting:** `golangci-lint` v2 (`mise x -- golangci-lint run ./...`).
- **gosec nolint style:** Use per-site `//nolint:gosec // G7XX - <reason>` with specific rule ID. gosec runs via golangci-lint only (no standalone binary); `#nosec` annotations are not used.
- See GOTCHAS.md for linting edge cases (`golines`, `contextcheck`, `revive`, `gocritic`).

### Naming Conventions

- **Packages/Files**: `snake_case`. **Interfaces/Structs**: `PascalCase`. **Functions/Methods**: `camelCase`/`PascalCase`. **Variables**: `camelCase`.
- **CLI Flags**: `kebab-case`. Use `Bool`/`String`/`Int`/`Duration` for flags without shorthand — only use `BoolP`/`StringP` variants when providing a short flag letter.

### Error Handling

- Always check errors. Use `fmt.Errorf` with `%w` to wrap. Use stdlib `errors` only — not `github.com/pkg/errors`.
- Use `defer` for resource cleanup. `panic` is not for normal control flow.
- Never silently correct invalid inputs — always log a warning. Guard against negative values in bit shifts.
- Handle `obj == nil && err == nil` as a separate error case for API responses to prevent nil pointer dereferences.
- In deferred cleanup, use `os.IsNotExist` to skip already-removed files. Include file paths in error messages.
- For data-critical files (cracked hashes, downloads), log `file.Close()` errors instead of discarding.
- **Error reporting:** Use `SendAgentError(ctx, msg, task, severity, opts ...ErrorOption)` for all error reporting. Add metadata via `WithClassification(category, retryable)`. `cserrors.LogAndSendError` delegates to `SendAgentError` (includes platform/version metadata). Always pass a non-nil error — it returns `err` directly. API submission is skipped only when `APIClient` is uninitialized.

### Concurrency

- Use goroutines and channels for async operations. Prefer channel-based communication over mutexes.
- Use `context.Context` for cancellation and deadlines in all long-running or networked operations.
- **Synchronized state:** Cross-goroutine fields in `agentstate.State` use `atomic.Bool` or `sync.RWMutex`. Always use getter/setter methods — never access directly.
- **Context propagation:** `StartAgent()` creates a cancellable context threaded through all goroutines. Use `ctx` for stoppable operations; `context.Background()` for must-complete operations (e.g., `AbandonTask`), with `//nolint:contextcheck // must-complete: reason`.
- **Data-loss logging:** When a channel send is skipped due to `ctx.Done()`, always log the dropped value at Warn level (e.g., dropped cracked hashes, process exit status). Silent data loss during shutdown hides bugs.
- **Context-aware sleep:** Use `sleepWithContext(ctx, duration)` (in `lib/agent/agent.go`) instead of `time.Sleep`.
- Run tests with `-race` flag to detect data races.

### Performance

- `regexp.MustCompile` at package level, never inside functions.
- `os.Remove` + `os.IsNotExist(err)` over `os.Stat` then `os.Remove`.
- Cache `[]byte(str)` when passing to both `json.Valid` and `json.Unmarshal`.
- `chan struct{}` for signal-only channels. `filepath.Join` (not `path.Join`) for filesystem paths.
- Configuration defaults live in `lib/config/config.go` as exported constants.

### Logging & Configuration

- Use structured logger (`charmbracelet/log`). Never log secrets.
- Use `spf13/viper` for config. Treat `viper.WriteConfig()` failures as non-fatal warnings.
- **Config access:** Read from `agentstate.State` (wired in `SetupSharedState()`), not `viper.Get*()` directly.
- Validate numeric/duration config fields in `SetupSharedState()` — clamp invalid values to defaults with a warning.

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

- `hashicorp/go-getter` pulls ~78 transitive deps (AWS SDK, GCS, gRPC). See #122 for replacement plan.

### Testing

- Table-driven tests in `_test.go` files within the same package. Naming: `TestFunctionName_Scenario`.
- Mock network/OS interactions. Extract business logic from external-process invocations for independent testing.
- Use `lib/testhelpers/` for fixtures (`SetupHTTPMock`, `SetupTestState`), `error_helpers.go` for test errors.
- Use `any` (not `interface{}`), `require.Error/NoError` (not `assert`), `t.Cleanup` (not `defer`), `atomic.Int32` for mock counters.
- MockClient sub-client accessors return default mocks (not nil) to prevent nil pointer panics.
- When removing `agentstate.State` fields, grep all test helpers and reset functions.
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
