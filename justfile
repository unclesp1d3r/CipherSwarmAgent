# Justfile for CipherSwarm Agent

# Serve documentation locally
# Usage: just docs

@docs:
    source .venv/bin/activate && mkdocs serve

# Run the agent (development)
# Usage: just dev

dev:
    go run main.go

# Install all requirements and build the project
# Usage: just install

install:
    python3 -m venv .venv
    source .venv/bin/activate && pip install mkdocs-material
    go mod tidy
    go build -o cipherswarm-agent

# Run lint and code checks
# Usage: just check

check:
    go fmt ./...
    go vet ./...
    golint ./...

# Run tests
# Usage: just test

test:
    go test ./...

# Run all checks and tests (CI)
# Usage: just ci-check

ci-check:
    just check
    just test 
