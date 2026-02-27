---
inclusion: fileMatch
fileMatchPattern: lib/api/**/*.go
---

# API Client Development Rules

Rules for the API client layer in `lib/api/`. The client is generated from `docs/swagger.json` using oapi-codegen.

## 1. Code Generation

- **Generated file**: `lib/api/client.gen.go` — never modify manually. Regenerate with `just generate`.
- **Config**: `lib/api/config.yaml` defines oapi-codegen settings.
- oapi-codegen v2 config does NOT support `input-spec` — the spec path is a positional CLI argument.
- After regenerating, always run `go mod tidy`.
- Use `exclude-schemas` in config when a generated type needs manual customization (e.g., `ErrorObject` excluded so it can implement the `error` interface).

## 2. Client Architecture

- `AgentClient` wraps `ClientWithResponses` (single field), implements the `APIClient` aggregate interface.
- Sub-clients: `Tasks()`, `Attacks()`, `Agents()`, `Auth()`.
- All sub-clients must use the generated client — never hand-roll raw HTTP endpoints.
- `APIClient` interface is defined in `lib/api/interfaces.go`.

## 3. Naming & Nolint

- oapi-codegen generates a `Client` struct — the hand-written aggregate interface is named `APIClient` (with `//nolint:revive` for stutter).
- `APIError` and `SetTaskAbandonedError.Error_` also have `//nolint:revive`.
- These nolint directives can be stripped by `golines` — verify they survive after running formatters.

## 4. Error Handling

- Error types live in `lib/api/errors.go`. Use `errors.As` to extract `*api.APIError`.
- Generated types with an `Error` field (e.g., `ErrorObject`) can't implement Go's `error` interface — use the `APIError` wrapper.
- oapi-codegen's `Parse*Response` methods read and close `HTTPResponse.Body` during parsing. Use the parsed `Body` byte slice (`resp.Body`), not `resp.HTTPResponse.Body` (already drained and closed).
- When an API method returns HTTP 200, always guard `resp.JSON200 == nil` — oapi-codegen silently sets it to nil if JSON unmarshaling fails.

## 5. Testing

- Mock implementations live in `lib/api/mock.go`.
- MockClient sub-client accessors return default mocks (not nil) to prevent nil pointer panics.
- Use `lib/testhelpers/` for HTTP mocking (`SetupHTTPMock`) and state setup.

## 6. Spec Management

- `docs/swagger.json` is downloaded from the CipherSwarm server — never modify it locally.
- Open issues on `unclesp1d3r/CipherSwarm` for spec problems.
- Download latest: `just gen-api-download` (fetches from `unclesp1d3r/CipherSwarm/main/swagger/v1/swagger.json`).
