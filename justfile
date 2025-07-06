# Justfile for CipherSwarm Agent

# Serve documentation locally
@docs:
    source .venv/bin/activate && mkdocs serve

# Run the agent (development)
dev:
    go run main.go

# Install all requirements and build the project
install:
    cd {{justfile_dir()}}
    python3 -m venv .venv
    source .venv/bin/activate && pip install mkdocs-material
    pnpm install
    pre-commit install --hook-type commit-msg
    go mod tidy


# Run pre-commit hooks and linting
check:
    cd {{justfile_dir()}}
    @pre-commit run -a # Runs all hooks on all files
    @just lint
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

build:
    cd {{justfile_dir()}}
    just install
    go mod tidy
    just check
    just test
    go build -o cipherswarm-agent

update-deps:
    cd {{justfile_dir()}}
    go get -u ./...
    go mod tidy
    go mod verify
    go mod vendor
    go mod tidy

    pnpm update -r
