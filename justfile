# Justfile for CipherSwarm Agent

# Use PowerShell on Windows, bash elsewhere
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set shell := ["bash", "-lc"]

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
    go run main.go

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
