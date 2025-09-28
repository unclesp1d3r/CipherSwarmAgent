# Justfile for CipherSwarm Agent

# Set PowerShell as the shell for Windows
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set shell := ["pwsh.exe", "-NoLogo", "-Command"]

# Serve documentation locally
@docs:
    .venv/Scripts/Activate.ps1; mkdocs serve

# Run the agent (development)
dev:
    go run main.go

# Install all requirements and build the project
install:
    cd {{justfile_dir()}}
    python -m venv .venv
    .venv/Scripts/Activate.ps1; pip install mkdocs-material
    pnpm install
    pre-commit install --hook-type commit-msg
    go mod tidy


# Run pre-commit hooks and linting
check: lint
    cd {{justfile_dir()}}
    @pre-commit run -a # Runs all hooks on all files
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

# Run all checks and tests (CI)
ci-check:
    cd {{justfile_dir()}}
    @pre-commit run # Same as just check, but only runs on staged files
    @just lint
    @just test

# Run all checks and tests, and build the agent
build:
    cd {{justfile_dir()}}
    just install
    go mod tidy
    just check
    just test
    goreleaser build --clean --auto-snapshot --single-target

update-deps:
    cd {{justfile_dir()}}
    go get -u ./...
    go mod tidy
    go mod verify
    go mod vendor
    go mod tidy

    pnpm update -r
