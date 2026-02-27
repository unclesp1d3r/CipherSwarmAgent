---
inclusion: always
---

# Commit Message Style for CipherSwarmAgent

## Format

All commits must follow [Conventional Commits](https://www.conventionalcommits.org):

```text
<type>(<scope>): <description>

<optional body>

<optional footer>
```

## Type

One of: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.

## Scope

Use a noun in parentheses (e.g., `(cli)`, `(api)`, `(benchmark)`, `(deps)`).

## Description

- Imperative mood ("add", not "added").
- No period at the end.
- 72 characters max, clear and specific.

## Body (optional)

- Start after a blank line.
- Use itemized lists for multiple changes.
- Explain what/why, not how.

## Footer (optional)

- Start after a blank line.
- Use for issue refs (`Closes #123`) or breaking changes (`BREAKING CHANGE:`).

## Breaking Changes

Add `!` after type/scope (e.g., `feat(api)!: ...`) or use `BREAKING CHANGE:` in footer.

## Examples

- `feat(cli): add support for custom config path`
- `fix(api): handle nil pointer in hashcat session`
- `docs: update README with install instructions`
- `refactor(benchmark): simplify cache persistence logic`
- `perf(hashcat): cache compiled regex at package level`
