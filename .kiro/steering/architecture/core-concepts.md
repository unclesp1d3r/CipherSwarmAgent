---
inclusion: always
---

# CipherSwarmAgent: Core Concepts & Structure

## Project Overview

- **Purpose:** Distributed agent for CipherSwarm, managing and executing hash-cracking tasks at scale.
- **Language:** Go (>=1.26)
- **Entrypoint:** `main.go` → `cmd/root.go` (Cobra CLI)
- **Cross-platform:** Designed for Linux, macOS, and Windows operation.

## Directory Layout

- `cmd/` — CLI entrypoint and command registration (Cobra)
- `lib/` — Core agent logic, decomposed into focused sub-packages
  - `agent/` — Agent lifecycle: startup, heartbeat loop, task polling, shutdown
  - `api/` — API client layer: generated client (`client.gen.go`), wrapper (`client.go`), errors, interfaces, mocks
  - `apierrors/` — Generic API error handler (`Handler`) for log-or-send error handling
  - `arch/` — OS-specific abstractions (device detection, binary handling)
  - `benchmark/` — Benchmark execution, caching, and submission
  - `config/` — Configuration defaults as exported constants
  - `cracker/` — Hashcat binary discovery and archive extraction
  - `cserrors/` — Centralized error reporting (`SendAgentError`, `LogAndSendError`)
  - `display/` — User-facing output (status, progress, benchmark results)
  - `downloader/` — File download with checksum verification
  - `hashcat/` — Hashcat session management, parameterization, and result parsing
  - `progress/` — Progress calculation utilities
  - `task/` — Task lifecycle: accept, run, status updates, crack submission
  - `testhelpers/` — Shared test fixtures, HTTP mocking, and state setup
  - `zap/` — Zap file monitoring for cracked hashes
  - Top-level files: `agentClient.go`, `dataTypes.go`, `errorUtils.go`, `crackerUtils.go`
- `agentstate/` — Global agent state, loggers, and synchronized fields (`atomic.Bool`, `sync.RWMutex`)
- `docs/` — Project documentation (MkDocs Material), OpenAPI specification
- `.github/` — Issue templates and CI workflows
- `Dockerfile` — Container build for agent deployment
- `Dockerfile.releaser` — Container for GoReleaser pipeline
- `mise.toml` — Dev toolchain management
- `justfile` — Command runner configuration

## Configuration

- **Environment variables** and **CLI flags** (via Cobra/Viper)
- Auto-generates YAML config file on first run.
- Key options: API token, server URL, data paths, GPU thresholds, debug flags, fault tolerance settings.
- Config access: read from `agentstate.State` (wired in `SetupSharedState()`), not `viper.Get*()` directly.

## Extensibility & Modularity

- Modular structure for new attack modes, device types, or resource handling.
- OS-specific logic is abstracted in `lib/arch/`.
- Shared state and logging are centralized in `agentstate/`.
- API client uses oapi-codegen for generation from `docs/swagger.json`.

## Contribution & Maintenance

- Follows Conventional Commits (enforced by `.gitlint` and CI).
- Automated CI (lint, test, changelog) via `just ci-check` / `just ci-full`.
- Dev toolchains managed by `mise`.
- Not production-ready (pre-v1.0).
