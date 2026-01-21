# Justfile for CipherSwarm Agent

# Use PowerShell on Windows, bash elsewhere
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set shell := ["bash", "-lc"]

# Use mise to manage all dev tools (pre-commit, etc.)
# See .mise.toml for tool versions
mise_exec := "mise exec --"

# Serve documentation locally
@docs:
    {{mise_exec}} pipx run --spec mkdocs-material mkdocs serve

# Run the agent (development)
dev:
    {{mise_exec}} go run main.go

# Install all requirements and build the project
install:
    cd {{justfile_dir()}}
    {{mise_exec}} pipx install mkdocs --force
    {{mise_exec}} pipx inject mkdocs mkdocs-material
    {{mise_exec}} pre-commit install --hook-type commit-msg
    {{mise_exec}} go mod tidy


# Run pre-commit hooks and linting
check: lint
    cd {{justfile_dir()}}
    @{{mise_exec}} pre-commit run -a # Runs all hooks on all files
    @{{mise_exec}} goreleaser check --verbose

# Run lint and code checks
lint:
    @{{mise_exec}} golangci-lint fmt ./...
    @{{mise_exec}} golangci-lint run ./...
    @{{mise_exec}} go vet ./...

# Run tests
test:
    {{mise_exec}} go test ./...
# Test coverage commands
# Run tests with coverage reporting
test-coverage:
    {{mise_exec}} go test -race -coverprofile=coverage.out -covermode=atomic ./...

# Generate and open HTML coverage report (macOS/Linux)
# Note: For Windows, use `just test-coverage-html-win` instead
test-coverage-html: test-coverage
    {{mise_exec}} go tool cover -html=coverage.out -o coverage.html


# Display function-level coverage in terminal
test-coverage-func: test-coverage
    {{mise_exec}} go tool cover -func=coverage.out

# Display package-level coverage summary
test-coverage-package: test-coverage
    {{mise_exec}} go tool cover -func=coverage.out | grep total
# Run all checks and tests (CI)
ci-check: check test


# Run all checks and tests, and build the agent
build: install check test
    {{mise_exec}} go mod tidy
    {{mise_exec}} goreleaser build --clean --auto-snapshot --single-target

update-deps:
    cd {{justfile_dir()}}
    {{mise_exec}} go get -u ./...
    {{mise_exec}} go mod tidy
    {{mise_exec}} go mod verify
    {{mise_exec}} go mod vendor
    {{mise_exec}} go mod tidy
