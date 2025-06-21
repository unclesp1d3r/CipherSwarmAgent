# CipherSwarmAgent Cursor Rules

These guide Skirmish when modifying or updating the Go agent codebase

## === 1. Core Design Rules ===

general:

- All API interactions must match the v1 Agent API contract in `docs/swagger.json` exactly. Breaking changes are prohibited.
- The agent is a long-lived CLI client responsible for:
  - Registering itself
  - Checking in (heartbeat)
  - Receiving and executing cracking tasks
  - Submitting benchmark, crack results, and status updates
- Each agent handles one task at a time. No task queueing or parallel execution is allowed.

## === 2. API Contract ===

network:

- API base path: `/api/v1/client/`
- Authentication via `Authorization: Bearer <token>`
- Endpoints to support:
  - `GET /configuration` – fetch config settings
  - `GET /tasks/new` – poll for new task
  - `POST /tasks/{id}/accept_task`
  - `GET /attacks/{id}` – fetch attack config
  - `GET /attacks/{id}/hash_list` – download hash list
  - `POST /tasks/{id}/submit_crack` – submit cracked result
  - `POST /tasks/{id}/submit_status` – submit status
  - `POST /tasks/{id}/exhausted` – report task exhaustion
  - `POST /agents/{id}/submit_benchmark` – send benchmark results
  - `POST /agents/{id}/submit_error` – send structured error
  - `POST /agents/{id}/heartbeat` – heartbeat
  - `POST /agents/{id}/shutdown` – notify of shutdown
- Response parsing must conform to the schemas defined in `contracts/v1_api_swagger.json`.

## === 3. Hashcat Execution ===

hashcat:

- The agent must support launching hashcat via CLI, capturing stdout/stderr, and parsing real-time output.
- Status updates must parse lines from `--status` JSON or standard output and transform them into the `TaskStatus` schema.
- Cracked results must be deduplicated before submission.
- Benchmarking must support both `--benchmark` and `--benchmark-all` as determined by configuration.

## === 4. Configuration and Persistence ===

config:

- Use local file-based configuration (e.g., JSON or YAML) for:
  - Agent token
  - Agent ID
  - Assigned server URL
  - Preferred backend devices or OpenCL types
- Allow override via CLI flags and environment variables.
- Configuration fetched from `/configuration` may override local defaults, but local overrides should take precedence unless explicitly allowed.

## === 5. Reliability and Error Handling ===

resilience:

- Implement exponential backoff for all failed API requests (see `x-speakeasy-retries` in `contracts/v1_api_swagger.json`).
- Network or API errors should be logged and retried when safe.
- Fatal errors should be reported to `/submit_error` with full metadata.
- A shutdown routine should gracefully notify the server.

## === 6. Compatibility and Modularity ===

design:

- Code must be modular and testable. Separate:
  - API client
  - Task manager
  - Hashcat runner
  - Status parser
- Minimize coupling between internal logic and transport. The agent should be testable without live API calls.

## === 7. Task Lifecycle ===

task_lifecycle:

- Tasks must follow the state flow:
      1. `GET /tasks/new`
      2. If found, `POST /tasks/{id}/accept_task`
      3. Download and configure resources
      4. Start hashcat and begin periodic `submit_status`
      5. As hashes are cracked, `submit_crack`
      6. On success or keyspace exhaustion, call `/exhausted`
      7. If unrecoverable failure, call `/submit_error`
- Agent must skip tasks if it lacks benchmark support for the hash type (use local cache of benchmark map).

## === 8. Benchmarks ===

benchmarking:

- Benchmark results must include `hash_type`, `runtime`, `hash_speed`, `device`
- Must support both native and packaged hashcat modes
- Results are sent to `/submit_benchmark` as part of initial setup or user-triggered rebenchmark

## === 9. Logging and Telemetry ===

logging:

- Use structured logs with timestamp, component, level, and message
- Optional: support log rotation or upload if needed in future phases

## === 10. Future-Proofing ===

future:

- Avoid hard-coding hashcat binary paths or formats
- Preserve compatibility with external configuration of wordlists, rules, masks
- Implement version-checking logic to allow auto-upgrade support later (pull from `/check_for_cracker_update`)
