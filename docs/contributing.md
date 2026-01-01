# Contributing

We welcome contributions! To contribute:

1. Fork the repository
2. Create a feature branch
3. Push your changes
4. Submit a pull request

## Development Setup

Before contributing, set up your development environment to ensure code quality checks pass.

### Prerequisites

- Go 1.22 or higher
- Git
- [uv](https://github.com/astral-sh/uv) - Python package manager
- [just](https://github.com/casey/just) - Command runner

### Installing just

**macOS:**
```bash
brew install just
```

**Linux (Ubuntu/Debian):**
```bash
# Using snap
sudo snap install just

# Or using cargo (if Rust is installed)
cargo install just

# Or download from GitHub releases
curl -L https://github.com/casey/just/releases/latest/download/just-1.36.0-x86_64-unknown-linux-musl.tar.gz | tar xz && sudo mv just /usr/local/bin/
```

**Windows:**
```powershell
# Using Chocolatey
choco install just

# Or using Scoop
scoop install just

# Or using winget
winget install --id Casey.Just
```

### Setting Up the Development Environment

1. Clone and enter the repository:
```bash
git clone https://github.com/unclesp1d3r/cipherswarm-agent.git
cd cipherswarm-agent
```

2. Install development dependencies:
```bash
just install
```

This command will:
- Install Python packages (mkdocs-material, pre-commit) using uv
- Set up pre-commit hooks for commit message validation
- Ensure Go modules are properly configured

### Running Quality Checks

Before pushing changes, run the CI checks locally to avoid blocked PRs:

```bash
just ci-check
```

This runs:
- Code formatting with `gofmt`
- Linting with `golangci-lint`
- Go vet checks
- Pre-commit hooks
- All tests

### Additional Development Commands

- `just lint` - Run only linting and formatting checks
- `just test` - Run tests only
- `just check` - Run linting and pre-commit hooks
- `just docs` - Serve documentation locally for preview
- `just build` - Build the agent with GoReleaser

## Commit Style

- Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
  - `<type>(<scope>): <description>`
  - Example: `feat(cli): add support for custom config path`
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- Scope: Use a noun (e.g., `(cli)`, `(api)`, `(deps)`)
- Description: Imperative, ≤72 characters, no period

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE).
