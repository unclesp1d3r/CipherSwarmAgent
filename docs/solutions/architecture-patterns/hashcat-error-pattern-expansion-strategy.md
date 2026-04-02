---
title: Hashcat Error Pattern Expansion Strategy
category: architecture-patterns
date: 2026-04-01
tags: [errorparser, regex, hashcat, classification, machine-readable, pre-execution-validation]
module: lib/hashcat
symptom: Unclassified hashcat errors falling through to ErrorCategoryUnknown with SeverityMinor
root_cause: Missing regex patterns for hashcat 7.x error messages; machine-readable pattern limited to 14 of 48 parser errors
---

# Hashcat Error Pattern Expansion Strategy

## Problem

The error parser (`lib/hashcat/errorparser.go`) had 27 patterns but missed ~26 message formats from hashcat 7.x source code. Unrecognized errors fell through to `ErrorCategoryUnknown` / `SeverityMinor`, losing classification metadata sent to the server. The machine-readable pattern used a fixed alternation of 14 `strparser()` strings, missing LUKS, hccapx, TrueCrypt/VeraCrypt, and CryptoAPI errors.

## Root Cause

Patterns were added reactively based on observed output rather than systematically from hashcat source. The machine-readable pattern was brittle — each new parser error required updating the alternation.

## Solution

### 1. Source-driven pattern identification

Examined hashcat 7.x source files (`src/backend.c`, `src/hashes.c`, `src/selftest.c`, `src/rp.c`, `src/shared.c`, `src/pidfile.c`, `src/restore.c`, `src/combinator.c`, `src/straight.c`, `src/autotune.c`) to identify all `event_log_error` (stderr) and `event_log_warning` (stdout) format strings. This produced the complete list of 26 missing patterns.

### 2. Machine-readable generalization

Replaced the fixed 14-string alternation with `^(.+?):(\d+):(.+):([^:]+)$`:

- `(.+?)` — non-greedy file path (stops at first `:<digits>:`)
- `(\d+)` — line number anchor
- `(.+)` — **greedy** hash capture (must be greedy to capture colons in hash types like `sha256:20000:salt`)
- `([^:]+)` — error text after the last colon (safe because no `strparser()` error contains colons)

**Critical learning:** Using `(.+?)` (non-greedy) for the hash group breaks colon-heavy hashes. The third group MUST be greedy.

### 3. `extractIntField` factory

Five duplicate extractors (`extractTemperatureContext`, `extractDeviceMemoryContext`, `extractDeviceWarningContext`, `extractHashCountContext`, `extractPidContext`) all followed the same pattern: set `error_type`, parse `submatch[1]` as int. Consolidated into one factory:

```go
func extractIntField(errorType, fieldName string) contextExtractor {
    return func(_ string, submatch []string) map[string]any {
        ctx := map[string]any{"error_type": errorType}
        if val, err := strconv.Atoi(submatch[1]); err == nil {
            ctx[fieldName] = val
        }
        return ctx
    }
}
```

### 4. Distinct error_type per failure mode

Each pattern must have a semantically accurate `error_type`. Reusing extractors across different failure modes (e.g., `kernel_build_failed` for both build and create failures) produces misleading server-side metadata. Split into `kernel_build_failed` and `kernel_create_failed`.

### 5. Pre-execution validation

Replaced `os.Stat` with `os.Open` + read loop for hash file validation:

- Catches permission errors that `os.Stat` misses
- Reads until EOF (not just first 4KB) to detect whitespace-only files
- Added `ErrHashFileWhitespaceOnly` sentinel with sub-classified error reporting

## Prevention

- When adding new error patterns, check hashcat source `event_log_error`/`event_log_warning` calls — don't rely only on observed output.
- Pattern ordering: specific patterns MUST appear before general ones (e.g., `Hashfile ... File changed during runtime` before generic `Hashfile ...` v6.x pattern).
- Use `extractIntField` factory for patterns with a single numeric capture group.
- Each pattern gets its own `error_type` — never share extractors across semantically different failure modes.
- Permission-denial tests (`os.Chmod(0o000)`) must skip on both Windows AND root/elevated privileges.

## References

- PR: #177
- Issue: #86
- Files: `lib/hashcat/errorparser.go`, `lib/hashcat/params.go`, `lib/task/manager.go`
- Hashcat source: `src/shared.c` (PA_000-PA_047 strparser strings)
