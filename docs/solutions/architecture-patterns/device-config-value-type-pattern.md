---
title: "Replace platform-specific device detection with DeviceConfig value type"
category: architecture-patterns
tags: [device-detection, hashcat, refactoring, value-type, cross-platform, input-validation]
module: lib/devices, lib/benchmark, lib/hashcat, lib/agent, lib/task
symptom: "Platform-specific GetDevices() (lspci, system_profiler, WMI) produced inconsistent device data that did not match what hashcat actually sees; device selection was scattered across 5+ files with duplicated string fields"
root_cause: "Device detection used OS-level commands instead of hashcat's own -I enumeration, and device selection state (BackendDevices/OpenCLDevices strings) was duplicated across manager structs with no single owner"
date: 2026-04-01
---

# DeviceConfig Value Type Pattern

## Problem

Device detection and selection had two structural problems:

1. **Platform-specific detection**: `lib/arch/darwin.go`, `linux.go`, and `windows.go` each had a `GetDevices()` function that shelled out to OS commands (`system_profiler`, `lspci`, `wmic`) and parsed output with regex. These were brittle, incomplete (no HIP support), and produced device names that didn't match hashcat's view.

2. **Scattered selection state**: `BackendDevices string` and `OpenCLDevices string` were duplicated on both `benchmark.Manager` and `task.Manager`. Each manager had its own `validateDevicesForSession()` method. `hashcat.Params` carried 5 device-related fields (`BackendDevices`, `OpenCLDevices`, `ValidatedBackendDeviceIDs`, `ValidatedOpenCLDevices`, `BackendDevicesValidated`) with a 3-tier resolution function. Every param construction site (5 locations) repeated an 8-line ceremony.

## Root Cause

No single type owned device selection. Raw server strings flowed unchecked from API config through managers into hashcat command lines. The `resolveBackendDevicesFlag()` function in `params.go` encoded validation awareness in the wrong layer (argument serialization).

## Solution

### DeviceConfig Value Type

A new `DeviceConfig` value type in `lib/devices/device_config.go` owns all device selection logic:

```go
type DeviceConfig struct {
    rawBackendDevices string
    rawOpenCLDevices  string
    dm                *DeviceManager
    enabledIDs        []int
}
```

Constructed via `NewDeviceConfig(rawBackend, rawOpenCL, dm)`. All fields unexported. The contained `*DeviceManager` is read-only after creation.

### 3-Tier Resolution

`ResolvedBackendDevices()` applies this decision tree:

- **DeviceManager nil** (enumeration failed): Forward raw server string only if it matches `^\d+(?:\s*,\s*\d+)*$`; reject non-numeric strings with a warning
- **DeviceManager present, no IDs configured**: Return `""` (hashcat auto-detects)
- **DeviceManager present, IDs configured**: Validate against enumerated devices, return only valid IDs

### Before/After

**Agent wiring (before):**

```go
benchmarkMgr.BackendDevices = cfg.Config.BackendDevices
benchmarkMgr.OpenCLDevices = cfg.Config.OpenCLDevices
taskMgr.BackendDevices = cfg.Config.BackendDevices
taskMgr.OpenCLDevices = cfg.Config.OpenCLDevices
taskMgr.DeviceManager = deviceMgr
benchmarkMgr.DeviceManager = deviceMgr
```

**Agent wiring (after):**

```go
dc := devices.NewDeviceConfig(cfg.Config.BackendDevices, cfg.Config.OpenCLDevices, deviceMgr)
benchmarkMgr.DeviceConfig = dc
taskMgr.DeviceConfig = dc
dc.WarnInvalidDevices(agentstate.Logger.Warn)
```

**Param construction (before — 8 lines, repeated 5 times):**

```go
validated := m.validateDevicesForSession()
jobParams := hashcat.Params{
    BackendDevices:            m.BackendDevices,
    OpenCLDevices:             m.OpenCLDevices,
    ValidatedBackendDeviceIDs: validated.BackendDeviceIDs,
    ValidatedOpenCLDevices:    validated.OpenCLDeviceTypes,
    BackendDevicesValidated:   m.DeviceManager != nil,
}
```

**Param construction (after — 2 lines):**

```go
jobParams := hashcat.Params{
    BackendDevices: m.DeviceConfig.ResolvedBackendDevices(),
    OpenCLDevices:  m.DeviceConfig.ResolvedOpenCLDevices(),
}
```

### Additional Improvements

- **Device Capabilities**: `Device.Capabilities map[string]string` parsed from `hashcat -I` output (processors, clock, memory, version, driver) across CUDA, HIP, Metal, OpenCL
- **HIP backend**: Added to backend section header regex
- **Benchmark regex**: Replaced `strings.Split(line, ":")` with compiled `benchmarkLineRe` using named submatch constants and structured float validation
- **Security hardening**: Raw server strings validated against `deviceIDListPattern` regex before forwarding to hashcat
- **Deep copy**: `GetAllDevices()` and `GetDevice()` deep-copy the `Capabilities` map to prevent external mutation
- **`WarnInvalidDevices()`**: Fire-and-forget method for startup diagnostics, replacing the misleading pattern of calling `Validate()` and discarding the return value

## Prevention Guidelines

1. **Single-owner principle**: Any piece of configuration must have exactly one owning type. Other consumers receive it via a value-type struct — never by copying raw fields.
2. **Never trust external data**: Server-provided strings must be validated at the boundary. Use the validate-and-warn pattern: parse, log warning for invalid values, proceed with safe default.
3. **Derive, never duplicate**: If a fact can be determined from existing state (e.g., `dm != nil`), expose it as a method, not a stored boolean field.
4. **Deep-copy reference-type fields**: Accessor methods returning maps or slices must return copies, not the original. Use a `copyDevice()` helper for structs with `map` fields.
5. **Platform-aware test paths**: Use `t.TempDir()` and `runtime.GOOS` guards. Never hardcode Unix-style paths in tests — `/nonexistent/path` is not absolute on Windows (no drive letter).

## Cross-References

- **Issue**: [#84](https://github.com/unclesp1d3r/CipherSwarmAgent/issues/84) — Refactor device detection to use hashcat native enumeration
- **PR**: [#178](https://github.com/unclesp1d3r/CipherSwarmAgent/pull/178) — Implementation PR
- **AGENTS.md**: Device Validation Flow section documents `DeviceConfig` wiring and resolution
- **UBIQUITOUS_LANGUAGE.md**: Defines canonical terms for Device, DeviceManager, DeviceConfig, Enabled IDs, Validated Devices, 3-Tier Resolution
- **Related**: `docs/solutions/architecture-patterns/hashcat-error-pattern-expansion-strategy.md` — colon-aware regex strategies
- **Related**: `docs/solutions/logic-errors/hashcat-session-file-cleanup-wrong-directory.md` — platform-specific path resolution
- **GOTCHAS.md**: `CmdFactory` injection pattern for subprocess tests, `charmbracelet/log` callback signature
