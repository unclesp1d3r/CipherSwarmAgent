# Justfile for CipherSwarm Agent

# Use PowerShell on Windows, bash elsewhere
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set shell := ["bash", "-lc"]

# Use mise to manage all dev tools (ruby, bun, pre-commit, etc.)
# See .mise.toml for tool versions
mise_exec := "mise exec --"

# Serve documentation locally
@docs:
    #!/usr/bin/env sh
    if [ -f ".venv/Scripts/mkdocs.exe" ]; then
        .venv/Scripts/mkdocs.exe serve
    elif [ -f ".venv/Scripts/mkdocs" ]; then
        .venv/Scripts/mkdocs serve
    else
        .venv/bin/mkdocs serve
    fi

# Run the agent (development)
dev:
    {{mise_exec}} go run main.go

# Install all requirements and build the project
install:
    #!/usr/bin/env sh
    cd {{justfile_dir()}}
    python -m venv .venv
    if [ -f ".venv/Scripts/python.exe" ]; then
        .venv/Scripts/python.exe -m pip install mkdocs-material
    elif [ -f ".venv/Scripts/python" ]; then
        .venv/Scripts/python -m pip install mkdocs-material
    else
        .venv/bin/python -m pip install mkdocs-material
    fi
    {{mise_exec}} bun install
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
    #!/usr/bin/env sh
    {{mise_exec}} go tool cover -html=coverage.out -o coverage.html
    case $(uname -s) in
        Darwin)
            open coverage.html
            ;;
        Linux)
            xdg-open coverage.html
            ;;
        *)
            echo "Coverage report generated at: coverage.html"
            ;;
    esac

# Generate and open HTML coverage report (Windows PowerShell)
# Note: This recipe uses PowerShell native commands and works when Just runs under pwsh.exe
test-coverage-html-win: test-coverage
    {{mise_exec}} go tool cover -html=coverage.out -o coverage.html
    Start-Process coverage.html

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
    {{mise_exec}} bun update
