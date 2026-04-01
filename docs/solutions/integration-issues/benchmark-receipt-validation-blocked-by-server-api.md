---
title: "Benchmark receipt validation requires server-side API changes before agent implementation"
category: integration-issues
date: 2026-03-30
resolved: 2026-03-31
tags:
  - api-contract
  - cross-repo-dependency
  - benchmark
  - swagger
  - resolved
severity: resolved
components:
  - lib/benchmark/manager.go
  - lib/benchmark/cache.go
  - lib/api/interfaces.go
  - lib/api/client.go
  - docs/swagger.json
related_issues:
  - "unclesp1d3r/CipherSwarmAgent#139"
  - "unclesp1d3r/CipherSwarm#823"
---

# Benchmark Receipt Validation Blocked by Server API

## Problem

The agent's `sendBenchmarkResults()` in `lib/benchmark/manager.go` treats any
HTTP 204 from the server's `submit_benchmark` endpoint as full success:

```go
if res.StatusCode() == http.StatusNoContent {
    return nil
}
```

There is no way to verify whether the server actually received and processed
all submitted benchmarks. If the server silently drops entries (validation
failures, DB constraints, partial processing errors), the agent marks
everything as `Submitted=true` and the results are unrecoverable.

Issue [#139](https://github.com/unclesp1d3r/CipherSwarmAgent/issues/139)
requested adding receipt validation, but the feature requires a coordinated
API change across two repositories.

## Root Cause

The `submit_benchmark` endpoint (`POST /api/v1/client/agents/{id}/submit_benchmark`)
returns only `204 No Content` with no body. The OpenAPI spec defines no receipt
schema. Since `docs/swagger.json` in the agent repo is **downloaded from the
CipherSwarm server and must never be modified locally** (per AGENTS.md and
GOTCHAS.md), the agent cannot add a receipt response type without the server
publishing one first.

Checking the server project (`../CipherSwarm/swagger/v1/swagger.json`)
confirmed the endpoint still only returns 204. No server-side branches,
issues, or commits existed for this feature.

## Investigation Steps

1. Read issue #139 details via `gh issue view`.
2. Read `lib/benchmark/manager.go` — confirmed `sendBenchmarkResults()` only
   checks for 204 with no receipt parsing.
3. Read `lib/benchmark/cache.go` — understood caching/retry system with
   `Submitted` flag and atomic writes.
4. Read `lib/api/interfaces.go` and `lib/api/client.go` — understood the
   generated API client architecture.
5. Read `docs/swagger.json` — confirmed only 204 response defined.
6. Recognized that the initial spec's proposal to modify swagger.json locally
   violates project rules.
7. Checked `../CipherSwarm/swagger/v1/swagger.json` — confirmed server still
   returns 204 only.
8. Searched server repo for existing work (branches, issues, commits) — none
   found.

## Solution

1. **Created server-side issue** —
   [unclesp1d3r/CipherSwarm#823](https://github.com/unclesp1d3r/CipherSwarm/issues/823)
   requesting the server add a `BenchmarkReceipt` schema and `200` response to
   the `submit_benchmark` endpoint.
2. **Added blocker comment** on agent issue #139.
3. **Assigned to milestone v0.7.2** on both repos.
4. **Documented agent-side implementation plan** for when server changes land:
   - Regenerate client from updated swagger (`just generate && go mod tidy`).
   - Add `BenchmarkReceipt` type and `validateReceipt()` in
     `lib/benchmark/receipt.go`.
   - Update `sendBenchmarkResults()` to parse 200 responses, fall back to 204
     for backward compatibility.
   - Only mark benchmarks as submitted when receipt validation passes.

## Prevention: Cross-Repo API Coordination

### Pre-Implementation Checklist

Before writing agent code for any feature that requires new or modified API
endpoints:

- [ ] API contract designed (endpoint path, method, request/response bodies,
      error responses).
- [ ] Server issue created in `unclesp1d3r/CipherSwarm`.
- [ ] Server PR merged and `swagger.json` updated.
- [ ] Agent `docs/swagger.json` downloaded from server.
- [ ] Agent code regenerated (`just generate`, `go mod tidy`).
- [ ] Agent issue/PR references server issue as blocker.

### Key Rules

1. **`docs/swagger.json` is read-only.** It is downloaded from the CipherSwarm
   server. Local edits will be overwritten by the next `just generate` cycle
   and cause type mismatches that only surface at runtime.

2. **Server-first, agent-second.** The spec change must land in
   `unclesp1d3r/CipherSwarm` before the agent can consume it. The only
   exception is coordinated development where both PRs are in-flight — and even
   then, the agent PR must not merge before the server PR.

3. **Do not hand-write raw HTTP calls.** If a generated client method does not
   exist, the spec has not been updated. Go back to the server repo.

4. **Track dependencies explicitly.** Every agent issue/PR depending on a
   server API change must reference the server issue by full URL and include a
   checklist item for server completion.

## Resolution (2026-03-31)

Server issue `CipherSwarm#823` was completed — the `submit_benchmark` endpoint
now returns HTTP 200 with a `BenchmarkReceipt` JSON body containing
`received_count`, `processed_count`, `failed_count`, and optional `message`.

Agent-side implementation:

1. **Regenerated client** — `docs/swagger.json` updated from server, `just generate`
   produced `BenchmarkReceipt` type and `SubmitBenchmarkResponse.JSON200` field.
2. **Created `lib/benchmark/receipt.go`** — `validateReceipt()` validates receipt
   counts, logs warnings for mismatches and partial failures. Advisory-only to
   avoid infinite retry loops (count mismatches are permanent for the same data).
3. **Updated `sendBenchmarkResults()`** — switch on status code: 200 with receipt
   validation (nil JSON200 returns `errBadResponse`), 204 for backward compat.
4. **Added tests** — `receipt_test.go` (9 table-driven cases), updated
   `manager_test.go` mocks from 204 to 200 with receipt JSON.

Key design decisions:
- Count mismatch is advisory (warn, not error) — prevents infinite retry loops
  since the server may legitimately deduplicate entries.
- Nil JSON200 on HTTP 200 returns error — protocol violation, not silently accepted.
- Negative counts return `errBadResponse` — guards against malformed server responses.

## Cross-References

- [AGENTS.md — Code Generation](../../AGENTS.md): `just generate` runs
  oapi-codegen against `docs/swagger.json`
- [GOTCHAS.md — Code Generation](../../GOTCHAS.md): swagger.json rules,
  oapi-codegen pitfalls
- [docs/solutions/logic-errors/hashcat-session-file-cleanup-wrong-directory.md](../logic-errors/hashcat-session-file-cleanup-wrong-directory.md):
  Related solution document pattern
