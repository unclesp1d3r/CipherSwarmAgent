# Commit Message Style for project

Use Conventional Commits: `<type>(<scope>): <description>`

- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- **Scopes** (required): `cmd`, `lib`, `api`, `hashcat`, `downloader`, `task`, `agentstate`, `docs`, `test`, `ci`, `deps`, etc.
- **Description**: imperative, capitalized, ≤72 chars, no period
- **Body** (optional): blank line, bullet list, explain what/why
- **Footer** (optional): blank line, issue refs (`Closes #123`) or `BREAKING CHANGE:`
- **Breaking changes**: add `!` after type/scope or use `BREAKING CHANGE:`

Examples:

- `feat(cmd): Add kebab-case CLI flags with deprecated aliases`
- `fix(downloader): Handle context cancellation during retry sleep`
- `docs(api): Update OpenAPI spec for new endpoints`
- `chore(deps): Update golangci-lint to v2.11`
