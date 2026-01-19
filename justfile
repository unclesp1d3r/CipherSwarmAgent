# Justfile for CipherSwarm Agent

# Use PowerShell on Windows, bash elsewhere
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set shell := ["bash", "-lc"]

# Serve documentation locally
@docs:
    uv run mkdocs serve

# Run the agent (development)
dev:
    go run main.go

# Install all requirements and build the project
install:
    cd {{justfile_dir()}}
    uv pip install mkdocs-material
    uv pip install pre-commit
    uv run pre-commit install --hook-type commit-msg
    go mod tidy


# Run pre-commit hooks and linting
check: lint
    @uv run pre-commit run -a # Runs all hooks on all files
    @goreleaser check --verbose

# Run lint and code checks
lint:
    cd {{justfile_dir()}}
    @golangci-lint fmt ./...
    @golangci-lint run ./...
    @go vet ./...

# Run tests
test:
    go test ./...

# Test coverage commands
# Run tests with coverage reporting
test-coverage:
    go test -race -coverprofile=coverage.out -covermode=atomic ./...

# Generate and open HTML coverage report (macOS/Linux)
# Note: For Windows, use `just test-coverage-html-win` instead
[unix]
test-coverage-html: test-coverage
    #!/usr/bin/env sh
    go tool cover -html=coverage.out -o coverage.html
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
[windows]
test-coverage-html: test-coverage
    go tool cover -html=coverage.out -o coverage.html
    Start-Process coverage.html

# Display function-level coverage in terminal
test-coverage-func: test-coverage
    go tool cover -func=coverage.out

# Display package-level coverage summary
test-coverage-package: test-coverage
    go tool cover -func=coverage.out | grep total

# Run all checks and tests (CI)
ci-check: check test


# Run all checks and tests, and build the agent
build: install check test
    cd {{justfile_dir()}}
    go mod tidy
    goreleaser build --clean --auto-snapshot --single-target

update-deps:
    cd {{justfile_dir()}}
    go get -u ./...
    go mod tidy
    go mod verify
    go mod vendor
    go mod tidy

    pnpm update -r
