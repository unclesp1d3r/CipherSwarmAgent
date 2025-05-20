# Phase 1: Replace External CipherSwarm Agent SDK with Insourced SDK

## Objective

Eliminate the dependency on `github.com/unclesp1d3r/cipherswarm-agent-sdk-go` by insourcing a fully compatible SDK, generated and maintained within this repository. The insourced SDK will be versioned as **v1**, matching the Agent API v1 as defined in `/docs/swagger.json`.

---

## Task List

### 1. Preparation & Analysis

1. **Inventory SDK Usage**

    - [x] Identify all code importing or referencing `cipherswarm-agent-sdk-go` (see: `lib/`, `cmd/root.go`).
    - [x] List all used types, models, and client methods (e.g., `components`, `operations`, `sdkerrors`, `CipherSwarmAgentSDK`).

2. **Review API Contract**
    - [x] Thoroughly review `/docs/swagger.json` for all endpoints, schemas, and error handling requirements.
    - [x] Note all required request/response types and authentication mechanisms.

---

### 2. SDK Extraction & Implementation

3. **Create SDK Module**

    - [ ] Create a new directory: `lib/sdk/v1/` (versioned for API v1; future versions will use `v2/`, etc.).
    - [ ] Scaffold the following packages:
        - `lib/sdk/v1/client` — API client logic
        - `lib/sdk/v1/models/components` — All OpenAPI component types
        - `lib/sdk/v1/models/operations` — All operation/request/response types
        - `lib/sdk/v1/models/sdkerrors` — Error types and helpers
    - [ ] **Version the SDK as v1, matching the Agent API v1.**

4. **Port Types and Models**

    - [ ] Copy or regenerate all Go structs/enums from the current SDK (matching `/docs/swagger.json`).
    - [ ] Ensure all field tags, types, and required/optional fields match the OpenAPI spec.
    - [ ] Implement error types and helpers for API error handling.

5. **Implement API Client**
    - [ ] Implement a `CipherSwarmAgentSDK` client struct with methods for all required endpoints:
        - `GET /configuration`
        - `GET /tasks/new`
        - `POST /tasks/{id}/accept_task`
        - `GET /attacks/{id}`
        - `GET /attacks/{id}/hash_list`
        - `POST /tasks/{id}/submit_crack`
        - `POST /tasks/{id}/submit_status`
        - `POST /tasks/{id}/exhausted`
        - `POST /agents/{id}/submit_benchmark`
        - `POST /agents/{id}/submit_error`
        - `POST /agents/{id}/heartbeat`
        - `POST /agents/{id}/shutdown`
    - [ ] Implement authentication (Bearer token) and retry logic per `x-speakeasy-retries`.
    - [ ] Ensure all request/response parsing matches the OpenAPI schemas.

---

### 3. Integration & Refactor

6. **Replace SDK Imports**

    - [ ] Update all imports in the codebase to use the new `lib/sdk/v1` packages.
    - [ ] Refactor all usages of types, models, and client methods to the new SDK.
    - [ ] Remove all references to the external SDK in `go.mod` and `go.sum`.

7. **Validation & Testing**
    - [ ] Run all existing tests (`just test`, `just ci-check`).
    - [ ] Add/expand tests for the new SDK client (unit and integration, as feasible).
    - [ ] Validate that all API interactions are 100% compatible with the Agent API v1 (per `/docs/swagger.json`).
    - [ ] Confirm error handling, retries, and authentication work as expected.

---

### 4. Cleanup

8. **Remove External SDK**

    - [ ] Remove `github.com/unclesp1d3r/cipherswarm-agent-sdk-go` from `go.mod` and `go.sum`.
    - [ ] Ensure no references remain in the codebase.

9. **Document Migration**
    - [ ] Update `README.md` and any developer docs to reference the new insourced SDK.
    - [ ] Note the removal of the external dependency in the changelog.
    - [ ] Create a `docs/sdk_v1_usage.md` file to document the new SDK's usage and capabilities and itegrate with mkdocs-material.
    - [ ] Create a `docs/sdk_v1_troubleshooting.md` file to document common issues and their solutions and integrate with mkdocs-material.

---

## Context & References

-   **API Contract:** `/docs/swagger.json` (defines Agent API v1)
-   **SDK Version:** The insourced SDK will be versioned as **v1** to match the API.
-   **SDK Directory:** All new SDK code will reside under `lib/sdk/v1/`.
-   **Current SDK Usage:** See all `lib/` and `cmd/root.go` imports and usages.
-   **Required Endpoints & Models:** See `.cursor/rules/architecture/core-rules.mdc` and OpenAPI spec.
-   **Testing:** All changes must pass `just test` and `just ci-check`.

---

**Completion Criteria:**

-   All code uses the new insourced SDK.
-   All tests pass.
-   No references to the external SDK remain.
-   API compatibility is 100% with Agent API v1.
