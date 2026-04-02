# Ubiquitous Language

## Device Detection & Enumeration

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **DeviceManager** | A read-only registry of compute devices discovered by running `hashcat -I` | device list, device registry, enumerator |
| **Device** | A single compute unit (GPU/CPU) enumerated by hashcat, identified by a numeric ID | hardware, card, accelerator |
| **DeviceConfig** | A value type that encapsulates device selection state and owns the resolution logic for hashcat session parameters | device settings, device preferences |
| **Backend** | The compute API that hashcat uses to talk to a device — one of OpenCL, CUDA, Metal, or HIP | driver, API, framework |
| **Capability** | An optional device property parsed from `hashcat -I` output (e.g., processors, clock, memory) | spec, attribute, feature |
| **Device Enumeration** | The process of running `hashcat -I` and parsing its text output into structured Device records | device detection, device discovery, device scanning |

## Device Selection & Validation

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Enabled IDs** | The set of numeric device IDs the agent should pass to hashcat via `--backend-devices` | selected devices, active devices, configured devices |
| **Validated Devices** | The result of checking Enabled IDs against the DeviceManager, filtering out unknown and unavailable IDs | filtered devices, resolved devices |
| **3-Tier Resolution** | The DeviceConfig logic that produces the `--backend-devices` flag value: validated IDs when DM present, empty when all invalid, raw string when DM is nil | fallback chain, device fallback, resolution cascade |
| **Nil DeviceManager** | The state where hashcat -I failed or hasn't run — DeviceConfig forwards raw server strings without validation | enumeration failure, no devices, unknown state |
| **Unavailable Device** | A device that exists in the enumerated set but has `IsAvailable = false` (hashcat marked it as Skipped) | skipped device, disabled device, offline device |

## Benchmark & Parsing

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Benchmark** | A hashcat speed test that measures hash-cracking throughput per device per hash type | speed test, performance test |
| **Benchmark Result** | A parsed output line from `hashcat --machine-readable --benchmark` containing device ID, hash type, runtime, and speed | benchmark entry, benchmark line, benchmark record |
| **DeviceName** | The human-readable name of a device (e.g., "NVIDIA GeForce RTX 3090") populated from DeviceManager lookup — display-only, never sent to the API | device label, friendly name |
| **Machine-Readable Output** | Hashcat's colon-delimited output format (`device:hashtype:name:runtime:hashtime:speed`) enabled by `--machine-readable` | raw output, text output |
| **Capability Detection** | Running `hashcat --hash-info --machine-readable` to discover supported hash types without executing benchmarks | hash type discovery, supported types scan |

## Agent Lifecycle

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **Agent** | A long-lived CLI client that registers with the CipherSwarm server, polls for tasks, and executes hashcat sessions | client, worker, node |
| **Task** | A server-assigned hash-cracking job with specific attack parameters, hash file, and device constraints | job, work unit, assignment |
| **Heartbeat** | A periodic signal sent to the server to report the agent's current activity and receive state changes | ping, keepalive, health check |
| **Config Reload** | The process of re-fetching server configuration mid-run, re-enumerating devices, and recreating managers with fresh DeviceConfig | refresh, reconfigure, hot reload |

## Server Configuration

| Term | Definition | Aliases to avoid |
|------|-----------|-----------------|
| **BackendDevices** | The server-provided comma-separated string of device IDs for the `--backend-devices` hashcat flag | backend device string, device list string |
| **OpenCLDevices** | The server-provided comma-separated string of device type IDs for the `--opencl-device-types` hashcat flag | OpenCL types, device types |
| **agentConfig** | The server data-transfer object that carries raw configuration strings — not the same as DeviceConfig | server config, raw config |

## Relationships

- A **DeviceManager** contains zero or more **Devices**, each with a unique numeric ID
- A **DeviceConfig** references one optional **DeviceManager** (nil when **Device Enumeration** failed)
- A **DeviceConfig** is created from **BackendDevices** + **OpenCLDevices** strings (from **agentConfig**) and a **DeviceManager**
- Each **Manager** (benchmark or task) holds exactly one **DeviceConfig**
- **3-Tier Resolution** produces the hashcat `--backend-devices` flag from a **DeviceConfig**
- A **Benchmark Result** may be enriched with a **DeviceName** when a **DeviceManager** is available
- **Capability Detection** produces placeholder **Benchmark Results** that are later replaced by real **Benchmarks**
- A **Config Reload** creates a fresh **DeviceManager** and new **DeviceConfig** for both managers

## Example dialogue

> **Dev:** "What happens when the server sends `backend_device: '1,2,3'` but device 2 is skipped by hashcat?"
>
> **Domain expert:** "The **DeviceConfig** parses the string into **Enabled IDs** `[1,2,3]`. When the benchmark **Manager** calls `ResolvedBackendDevices()`, the **3-Tier Resolution** validates against the **DeviceManager** and finds device 2 is an **Unavailable Device**. It returns `'1,3'` — only the **Validated Devices**."
>
> **Dev:** "And if **Device Enumeration** failed entirely?"
>
> **Domain expert:** "Then we have a **Nil DeviceManager**. The **DeviceConfig** falls back to forwarding the raw **BackendDevices** string — but only if it passes format validation. If the server sent `'OpenCL'` instead of numeric IDs, it gets rejected and hashcat auto-detects."
>
> **Dev:** "How does the **DeviceName** get into a **Benchmark Result**?"
>
> **Domain expert:** "When parsing **Machine-Readable Output**, the benchmark parser looks up the device ID in the **DeviceManager** via `GetDevice()`. If found, it sets the **DeviceName** field. This is display-only — the API submission uses the numeric ID."

## Flagged ambiguities

- **"device"** was used to mean both a physical compute unit (**Device**) and the numeric ID selecting it (**Enabled IDs**). These are distinct: a **Device** is the parsed representation with name, type, and capabilities; an **Enabled ID** is just a number from server config.
- **"backend devices"** referred to both the raw server string (**BackendDevices**) and the validated ID set produced by resolution (**Validated Devices**). The raw string is untrusted server input; the validated set has been checked against the **DeviceManager**.
- **"validation"** was used for both format validation (regex check on raw strings) and device validation (checking IDs against enumerated devices). Format validation happens in `ResolvedBackendDevices()`; device validation happens in `Validate()` and `WarnInvalidDevices()`.
- **"config"** was overloaded between **agentConfig** (server DTO with raw strings) and **DeviceConfig** (agent-side value type with resolution logic). These are separate types at different abstraction levels — agentConfig is input, DeviceConfig is computed state.
