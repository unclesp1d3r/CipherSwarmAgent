# Justfile for CipherSwarm Agent

# Set PowerShell as the shell for Windows
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set shell := ["pwsh.exe", "-NoLogo", "-Command"]

# Serve documentation locally
@docs:
    uv run mkdocs serve

# Run the agent (development)
dev:
    go run main.go

# Install all requirements and build the project
install:
    cd {{justfile_dir()}}
    uv venv --no-project --clear
    pipx install mkdocs-material --include-deps
    pipx install pre-commit
    pnpm install
    uv run pre-commit install --hook-type commit-msg
    go mod tidy


# Run pre-commit hooks and linting
check: lint
    cd {{justfile_dir()}}
    @uv run pre-commit run -a # Runs all hooks on all files
    @goreleaser check --verbose

# Lint the justfile itself
lint-just:
    just --fmt --check --unstable

# Format Go code
fmt-go:
    gofmt -s -w .

# Run Go vet
vet-go:
    go vet ./...

# Run gosec security scanner
lint-gosec:
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    gosec ./...

# Run golangci-lint
lint-golangci:
    golangci-lint run ./...

# Run all Go linting
lint-go: fmt-go vet-go lint-gosec lint-golangci

# Run Go tests
test-go:
    go test ./...

# Run lint and code checks
lint: lint-go

# Run tests
test:
    go test ./...

# Run all checks and tests (CI)
ci-check:
    cd {{justfile_dir()}}
    @uv run pre-commit run # Same as just check, but only runs on staged files
    @just lint
    @just test

# Run all checks and tests, and build the agent
build: install check test
    goreleaser build --clean --auto-snapshot --single-target

update-deps:
    cd {{justfile_dir()}}
    go get -u ./...
    go mod tidy
    go mod verify
    go mod vendor
    go mod tidy

    pnpm update -r
    uv run pre-commmit autoupdate
