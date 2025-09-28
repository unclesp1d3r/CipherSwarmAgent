
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

- **API Specification:** All API interactions must strictly adhere to the v1 Agent API contract defined in `docs/swagger.json`.
- **Reliability:** The agent must implement exponential backoff for failed API requests.

## Go

The project follows standard, idiomatic Go practices (version >=1.22).

### Project Structure

- `cmd/`: Main application entry points using the Cobra framework.
- `lib/`: Core agent logic, including the agent client, task/benchmark managers, and utilities.
    - `hashcat/`: Logic for managing Hashcat sessions, parameters, and output parsing.
    - `arch/`: OS-specific abstractions for handling different platforms (Linux, macOS, Windows).
- `shared/`: Global state, logging, and shared data types.
- `docs/`: Project documentation, including the OpenAPI specification.

### Formatting & Linting

- **Formatting:** All Go code must be formatted using `gofmt`.
- **Linting:** We use `golangci-lint` for static analysis. Run checks with `just ci-check`.

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
- Use `defer` for resource cleanup (e.g., closing files, terminating processes).
- `panic` should not be used for normal control flow.

### Concurrency

- Use goroutines and channels for asynchronous operations like monitoring hashcat.
- Protect shared state with mutexes where necessary, but prefer channel-based communication.
- Use `context.Context` for cancellation and deadlines in all long-running or networked operations.
- Run tests with the `-race` flag in CI to detect data races.

### Logging & Configuration

- **Logging:** Use a structured logger (e.g., `charmbracelet/log`). Never log secrets or sensitive data.
- **Configuration:** Use `spf13/viper` to manage configuration from files, environment variables, and CLI flags.

### Testing

- Write table-driven tests for core logic and place them in `_test.go` files within the same package.
- Use mocks for network and OS-level interactions to ensure testability.
- Aim for high test coverage on core logic.

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
- **API Docs:** The API is documented using an OpenAPI v3 spec in `docs/swagger.json`.
