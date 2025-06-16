# Justfile for CipherSwarm Agent

# Serve documentation locally
@docs:
    source .venv/bin/activate && mkdocs serve

# Run the agent (development)
dev:
    go run main.go

# Install all requirements and build the project
install:
    python3 -m venv .venv
    source .venv/bin/activate && pip install mkdocs-material
    go mod tidy
    go build -o cipherswarm-agent

# Run lint and code checks
check:
    go fmt ./...
    go vet ./...

# Run tests
test:
    go test ./...

# Run all checks and tests (CI)
ci-check:
    just check
    just test 
