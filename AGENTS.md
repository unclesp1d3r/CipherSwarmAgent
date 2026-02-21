# AGENTS

This document outlines the formats, standards, and architecture for the CipherSwarmAgent project, tailored for the Gemini AI model.

## Architecture

### Core Concepts

- **Purpose:** A distributed agent for CipherSwarm, designed to manage and execute hash-cracking tasks at scale across Linux, macOS, and Windows.
- **Entrypoint:** The application starts via `main.go`, which initializes the Cobra CLI application defined in `cmd/root.go`.
- **Configuration:** Configuration is handled through environment variables, CLI flags (via Cobra/Viper), and a YAML config file that is auto-generated on the first run. Key settings include the API token, server URL, data paths, and GPU thresholds.

### Task Lifecycle & API Contract

The agent operates as a long-lived CLI client that interacts with the CipherSwarm server API. It is responsible for:

1. **Registration & Heartbeat:** Registering itself with the server and sending regular heartbeats to signal it's online.
2. **Polling for Tasks:** Periodically requesting new tasks from the `/api/v1/client/tasks/new` endpoint.
3. **Task Execution:**
   - Accepting a task (`POST /tasks/{id}/accept_task`).
   - Downloading resources like hash lists (`GET /attacks/{id}/hash_list`).
   - Launching and monitoring a hashcat process.
   - Submitting status updates (`POST /tasks/{id}/submit_status`).
   - Submitting cracked passwords (`POST /tasks/{id}/submit_crack`).
4. **Completion & Error Handling:**
   - Reporting task exhaustion (`POST /tasks/{id}/exhausted`).
   - Submitting structured errors on failure (`POST /agents/{id}/submit_error`).
   - Gracefully notifying the server on shutdown (`POST /agents/{id}/shutdown`).

- **API Specification:** All API interactions must strictly adhere to the v1 Agent API contract defined by the CipherSwarm server.
- **Reliability:** The agent must implement exponential backoff for failed API requests.

## Go

The project follows standard, idiomatic Go practices (version 1.26+).

### Project Structure

- `cmd/`: Main application entry points using the Cobra framework.
- `lib/`: Core agent logic, including the agent client, task/benchmark managers, and utilities.
  - `api/`: API client layer — generated OpenAPI client (`client.gen.go`), hand-written wrapper (`client.go`), error types (`errors.go`), interfaces (`interfaces.go`), and mocks (`mock.go`). Regenerate with `just generate`.
  - `hashcat/`: Logic for managing Hashcat sessions, parameters, and output parsing.
  - `arch/`: OS-specific abstractions for handling different platforms (Linux, macOS, Windows).
- `shared/`: Global state, logging, and shared data types.
- `docs/`: Project documentation, including the OpenAPI specification.

### Formatting & Linting

- **Formatting:** All Go code must be formatted using `gofmt`.
- **Linting:** We use `golangci-lint` for static analysis. Run checks with `just ci-check`.
- **Note:** Use `mise x -- golangci-lint run ./...` to ensure correct linter version (v2).
- **Gotcha:** `//go:fix inline` directives conflict with `gocheckcompilerdirectives` linter — avoid adding them.
- **Gotcha:** `contextcheck` linter flags functions not propagating context — use `//nolint:contextcheck` when callee doesn't accept context yet.
- **Gotcha:** When removing global gosec exclusions, run `mise x -- golangci-lint run ./...` to find ALL violation sites before adding per-site `//nolint:gosec` comments.
- **gosec nolint style:** Use per-site `//nolint:gosec // G7XX - <reason>` with specific rule ID rather than global exclusions in `.golangci.yml`.
- **Gotcha:** `golines` (max-len 120) splits long lines, moving `//nolint:` off the flagged line. Keep nolint comments short (e.g., `// G704 - trusted URL`) so total line stays under 120 chars.
- **Gotcha:** A blank `//` line between a doc comment and a type/func declaration breaks the linter's comment association — keep doc comments contiguous with their declaration.
- **Gotcha:** `//nolint:revive` does NOT suppress `staticcheck` for the same issue — list all linters (e.g., `//nolint:revive,staticcheck`).
- **Gotcha:** `revive` requires each exported constant in a `const` block to have its own doc comment starting with the constant name (e.g., `// DefaultFoo is...`). A group comment alone doesn't satisfy it.

### Naming Conventions

- **Packages**: `snake_case`
- **Files**: `snake_case` (e.g., `agent_client.go`).
- **Interfaces**: `PascalCase`, often with an `-er` suffix (e.g., `Reader`, `Writer`).
- **Structs**: `PascalCase`.
- **Functions/Methods**: `camelCase` for unexported, `PascalCase` for exported.
- **Variables**: `camelCase`.

### Error Handling

- Errors must always be checked and never ignored.
- Use `fmt.Errorf` with the `%w` verb to wrap errors for context.
- Use stdlib `errors` and `fmt.Errorf` only — do not use `github.com/pkg/errors` (removed from project).
- Use `defer` for resource cleanup (e.g., closing files, terminating processes).
- `panic` should not be used for normal control flow.
- Never silently correct invalid inputs (e.g., negative values) - always log a warning.
- Guard against negative values in bit shift operations to prevent panic.
- When checking `err != nil || obj == nil` for API responses, handle `obj == nil && err == nil` as a separate error case to prevent nil pointer dereferences.
- In deferred cleanup functions (e.g., lock file removal), use `os.IsNotExist` to skip already-removed files and include file paths in error messages.
- **Gotcha:** Generated types with an `Error` field (e.g., `ErrorObject`) can't implement Go's `error` interface (`Error()` method) — use a wrapper type like `api.APIError` instead.
- **Gotcha:** `cserrors.LogAndSendError` returns the `err` parameter directly — always pass a non-nil error in error paths, or callers will see success.
- For data-critical files (cracked hashes, downloads), log `file.Close()` errors instead of discarding with `_ = file.Close()`.

### Concurrency

- Use goroutines and channels for asynchronous operations like monitoring hashcat.
- Protect shared state with mutexes where necessary, but prefer channel-based communication.
- Use `context.Context` for cancellation and deadlines in all long-running or networked operations.
- Run tests with the `-race` flag in CI to detect data races.

### Performance

- Always compile `regexp.MustCompile` at package level, never inside functions.
- Prefer `os.Remove` + `os.IsNotExist(err)` check over `os.Stat` then `os.Remove` — avoids redundant syscall.
- Cache `[]byte(str)` conversions when the same string is passed to both `json.Valid` and `json.Unmarshal`.
- Use `chan struct{}` (not `chan int`) for signal-only channels — zero allocation.
- Configuration defaults live in `lib/config/config.go` as exported constants — `cmd/root.go` references them (no duplication).

### Logging & Configuration

- **Logging:** Use a structured logger (e.g., `charmbracelet/log`). Never log secrets or sensitive data.
- **Configuration:** Use `spf13/viper` to manage configuration from files, environment variables, and CLI flags.
- Treat `viper.WriteConfig()` failures as non-fatal warnings (log + continue) — the in-memory config is correct and a read-only filesystem should not block agent operation.

### Tooling

- **Code Generation:** `oapi-codegen` is declared as a Go tool in `go.mod` — invoke via `go tool oapi-codegen`, not bare binary. `just generate` runs it from `lib/api/config.yaml` against `docs/swagger.json`. After regenerating, run `go mod tidy && go mod vendor`.
- **Gotcha:** oapi-codegen v2 config does NOT support `input-spec` — the spec path must be a positional CLI argument.
- **Gotcha:** `docs/swagger.json` is downloaded from the CipherSwarm server — never modify it locally. Open issues on `unclesp1d3r/CipherSwarm` for spec problems.
- **Gotcha:** `lib/api/client.gen.go` is auto-generated — never manually modify. Regenerate with `just generate`.
- **Gotcha:** oapi-codegen generates a `Client` struct in `lib/api/client.gen.go` — the hand-written aggregate interface is named `APIClient` (with `//nolint:revive` for stutter) to avoid the conflict.
- **Gotcha:** `APIError` in `errors.go` also has `//nolint:revive` for stutter. `SetTaskAbandonedError.Error_` has `//nolint:revive` because the underscore avoids a name collision with the `Error()` method.
- **Gotcha:** Use `exclude-schemas` in `lib/api/config.yaml` when a generated type needs manual customization (e.g., `ErrorObject` excluded so it can implement the `error` interface in `errors.go`).
- **API Client Architecture:** `AgentClient` in `client.go` wraps the generated `ClientWithResponses`, implements `APIClient` interface. Error types (`APIError`, `SetTaskAbandonedError`, `Severity`) live in `errors.go`. Use `errors.As` to extract `*api.APIError` from returned errors.
- **Gotcha:** oapi-codegen's generated `Parse*Response` methods read and close `HTTPResponse.Body` during parsing. Helper functions must use the parsed `Body` byte slice (`resp.Body`), not `resp.HTTPResponse.Body` (already drained and closed).
- **Gotcha:** When an API method returns HTTP 200, always guard `resp.JSON200 == nil` before using it — oapi-codegen silently sets JSON200 to nil if JSON unmarshaling fails.
- **Gotcha:** Do not name directories `gen/` — the user's global gitignore excludes them.
- **Dev Tool Management:** Use `mise` to install and manage development toolchains (e.g., Go, Bun) via `mise.toml`.
- **CI Validation:** Run `just ci-check` to validate all checks pass before committing.
- **Go Modernize:** Use `go fix ./...` (Go 1.26+ built-in) instead of the deprecated `golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize` tool. Dry-run: `go fix -diff ./...`.
- **Vendor Sync:** After `go fix` or dependency changes, run `go mod tidy && go mod vendor` to sync the vendor directory.
- **Gotcha:** `govulncheck` may fail with Go 1.26 if built against an older Go version. Rebuild with `go install golang.org/x/vuln/cmd/govulncheck@latest`.

### Dependencies

- `hashicorp/go-getter` pulls ~78 transitive deps (AWS SDK, GCS, gRPC). See #122 for lightweight replacement plan.
- `shirou/gopsutil/v3` is maintenance-only; v4 is actively developed. See #123 for upgrade plan.

### Testing

- Write table-driven tests for core logic and place them in `_test.go` files within the same package.
- Use mocks for network and OS-level interactions to ensure testability.
- When a function combines external-process invocation (e.g., hashcat) with business logic, extract the business logic into a separate unexported function so it can be tested independently.
- Use `lib/testhelpers/` package for shared test fixtures, HTTP mocking (`SetupHTTPMock`), and state setup (`SetupTestState`).
- Use `any` instead of `interface{}` (enforced by modernize linter).
- Aim for high test coverage on core logic.
- Test naming convention: `TestFunctionName_Scenario` with underscore separation.
- Use `require.Error/NoError` instead of `assert.Error/NoError` for error assertions (testifylint rule).
- Use `atomic.Int32` for thread-safe counters in mock implementations.
- Use `lib/testhelpers/error_helpers.go` for constructing test errors (`NewAPIError`, `NewValidationAPIError`, `NewSetTaskAbandonedError`).
- MockClient sub-client accessors (`Tasks()`, `Agents()`, etc.) return default unconfigured mocks (not nil) to prevent nil pointer panics when code paths call sub-clients the test didn't explicitly mock.
- When removing a field from global state (`agentstate.State`), grep all test helpers, cleanup functions, and reset functions for references.
- Run `go test -race ./...` to detect data races.

## Git

### Branching Model

- **Feature Branches:** All new work (features, fixes, refactors) must be done on a separate branch.
- **Main Branch:** Never commit directly to `main`. All changes must go through a pull request with at least one code review.

### Commit Messages

Commit messages must follow the **Conventional Commits** specification.

- **Format:** `<type>(<scope>): <description>`
- **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.
- **Scope:** A noun describing the affected part of the codebase (e.g., `(cli)`, `(api)`, `(hashcat)`).
- **CI Enforcement:** The `.gitlint` file and CI checks enforce this standard.

### Changelog

The `CHANGELOG.md` is automatically generated from commit messages using `git-chglog`.

## CI/CD & Docker

- **GitHub Actions:** Workflows in `.github/workflows/` automate linting, testing, building, and releases.
- **Docker:**
  - `Dockerfile`: Used for building the main application container.
  - `Dockerfile.releaser`: Used within the GoReleaser pipeline for creating releases.

## Documentation

- **MkDocs:** Project documentation is written in Markdown in the `docs/` directory and built into a static site using `mkdocs`.
- **API Docs:** The API is documented using an OpenAPI v3 spec maintained in the CipherSwarm server repository.
