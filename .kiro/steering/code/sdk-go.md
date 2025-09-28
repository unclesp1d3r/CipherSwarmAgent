---
inclusion: fileMatch
fileMatchPattern: 'lib/sdk/**/*.go'
---

# Go SDK Development Rules

## 1. Project Structure & Layout

- Follow Go module conventions ([go.dev](mdc:https:/go.dev/doc/modules/layout)):
    - Place commands in `cmd/`, core packages in `pkg/` or root, and internal-only code in `internal/`.
    - Use clear, idiomatic package names; avoid stutter (e.g., `sdk.Client`, not `sdk.SDKClient`).
    - Keep public APIs minimal; prefer unexported helpers.

## 2. Idiomatic Go & API Design

- Use Go idioms: interfaces for abstractions, structs for data, and functional options for configuration ([speakeasy.com](mdc:https:/www.speakeasy.com/docs/languages/golang/methodology-go)).
- Prefer context-aware methods (`ctx context.Context` as first arg for network calls).
- Return concrete types, not interfaces, from constructors.
- Avoid global state; use dependency injection for testability.
- Design for composability and extensibility.

## 3. Error Handling

- Always return errors as the last return value; never panic for normal errors.
- Use Go's `errors` package for wrapping and annotating errors.
- Provide clear, actionable error messages; document error types.
- For SDKs, define sentinel errors for common failure modes.

## 4. Testing & Reliability

- Cover all public APIs with table-driven unit tests.
- Use Go's `testing` package; avoid external test frameworks unless necessary.
- Provide integration tests for API calls (mocking remote endpoints where possible).
- Ensure all code passes `go vet`, `golint`, and `go test ./...`.

## 5. Documentation & Developer Experience

- Document all exported types, functions, and methods with GoDoc comments.
- Provide usage examples in GoDoc and a `README.md`.
- Favor discoverability: intuitive method names, clear parameter docs, and minimal setup.
- Include a quickstart and troubleshooting section in docs ([auth0.com](mdc:https:/auth0.com/blog/guiding-principles-for-building-sdks)).
- Version the SDK using semantic versioning; document breaking changes.

## 6. Performance & Security

- Avoid unnecessary allocations; benchmark critical paths.
- Never log or expose sensitive data (e.g., tokens, secrets).
- Use secure defaults for all network and crypto operations.

## 7. Packaging & Distribution

- Tag releases with semantic versions.
- Keep dependencies minimal and up-to-date.
- Provide a `go.mod` and `go.sum` for reproducible builds.

## 8. Community & Contribution

- Use Conventional Commits for all changes.
- Provide a `CONTRIBUTING.md` and issue templates.
- Respond to issues and PRs promptly; document support policy.

---

### References

- [Go Module Layout](mdc:https:/go.dev/doc/modules/layout)
- [Speakeasy Go SDK Methodology](mdc:https:/www.speakeasy.com/docs/languages/golang/methodology-go)
- [SDK Best Practices](mdc:https:/www.speakeasy.com/blog/sdk-best-practices)
- [Auth0 SDK Principles](mdc:https:/auth0.com/blog/guiding-principles-for-building-sdks)
