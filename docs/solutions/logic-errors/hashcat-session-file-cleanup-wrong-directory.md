---
title: Hashcat session .log and .pid files accumulate without cleanup
category: logic-errors
date: 2026-03-16
tags:
  - hashcat
  - session-files
  - file-cleanup
  - startup
  - cross-platform
  - os-isnotexist
module: lib/hashcat
symptom: Hashcat .log and .pid files accumulate in ~/.hashcat/sessions/ across task runs and agent restarts, consuming disk space indefinitely
root_cause: Cleanup used CWD-relative paths instead of hashcat's actual session directory; os.IsNotExist guard silently masked the wrong-directory error
resolution_type: two-phase
severity: medium
affected_files:
  - lib/hashcat/session.go
  - lib/hashcat/session_dir.go
  - lib/hashcat/session_dir_cleanup_test.go
  - lib/agent/agent.go
  - lib/hashcat/params.go
---

# Hashcat Session File Cleanup: Wrong Directory Bug

## Problem

Hashcat `.log` and `.pid` files accumulated indefinitely in the session directory (`~/.hashcat/sessions/` or `~/.local/share/hashcat/sessions/`). Despite cleanup code existing in `Session.Cleanup()`, files were never actually removed.

## Root Cause

Two distinct failures:

### 1. Per-task cleanup targeted the wrong directory

Hashcat does **not** write session files to the process working directory. It writes them to `folder_config->session_dir` (from hashcat source `pidfile.c`/`folder.c`), which resolves to:

1. `~/.hashcat/sessions/` (if `~/.hashcat` exists)
2. `$XDG_DATA_HOME/hashcat/sessions/` (if set)
3. `~/.local/share/hashcat/sessions/` (default fallback)

The original cleanup used bare relative paths: `os.Remove("attack-123.log")`. This resolved against CWD, not the session directory. `os.Remove` returned "file not found", and `os.IsNotExist` silently swallowed it. The file in `~/.hashcat/sessions/` was never touched.

**Key insight:** `os.IsNotExist` guards can mask wrong-path bugs. The file appears "already cleaned" when it was never found at all.

### 2. No startup cleanup for crash-orphaned files

If the agent was killed (SIGKILL, OOM, power loss), `Cleanup()` never ran. No startup sweep existed, so files accumulated permanently across restarts.

## Solution

### Fix 1: Absolute paths for per-task cleanup (PR #160)

`NewHashcatSession` now resolves the real session directory and stores absolute paths:

```go
sessionName := sessionPrefix + id
sessDir := hashcatSessionDir(binaryPath)

return &Session{
    sessionLogFile: filepath.Join(sessDir, sessionName+".log"),
    sessionPidFile: filepath.Join(sessDir, sessionName+".pid"),
}, nil
```

### Fix 2: Startup orphan cleanup (PR #163)

`CleanupOrphanedSessionFiles()` runs at agent startup, scanning for stale `attack-*.log` and `attack-*.pid` files:

```go
func cleanupOrphanedInDir(dir string) {
    entries, err := os.ReadDir(dir)
    // ...
    for _, entry := range entries {
        if !isRegularFile(entry) { continue }           // skip symlinks
        if !strings.HasPrefix(name, sessionPrefix) { continue }  // only agent files
        if !strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".pid") { continue }
        os.Remove(filepath.Join(dir, name))
    }
}
```

Safety properties:

- `isRegularFile()` rejects symlinks/directories (with `DirEntry.Type()` fallback for unknown types)
- Windows skipped entirely (session dir = binary install dir, too broad)
- Errors logged but never propagated (cleanup failure cannot block startup)
- `sessionPrefix` constant (`"attack-"`) extracted to deduplicate across 3 files

## Investigation Steps

1. Observed `.log`/`.pid` files accumulating in `~/.hashcat/sessions/` despite cleanup code
2. Inspected `Session.Cleanup()` — found `os.Remove` using relative paths
3. Examined hashcat source (`pidfile.c`, `folder.c`) — confirmed session dir is platform-specific, not CWD
4. Identified the mismatch: agent's `os.Remove` targeted CWD, hashcat wrote to `~/.hashcat/sessions/`
5. `os.IsNotExist` guard silently masked the failure — appeared to succeed when it never found the file
6. Designed two-phase fix: absolute paths for per-task + startup sweep for crash orphans

## Prevention Strategies

1. **Never assume CWD for hashcat artifacts.** Always use `hashcatSessionDir()` to resolve the session directory.
2. **Treat `os.IsNotExist` as a signal, not a silencer.** When cleanup "succeeds" because the file doesn't exist, the path may be wrong. Log the resolved path at Debug level.
3. **Extract repeated string literals immediately.** The `"attack-"` prefix in 3+ places was a shotgun-surgery risk — now the `sessionPrefix` constant.
4. **Handle `DirEntry.Type() == 0` (unknown).** Some filesystems return unknown type — fall back to `entry.Info()`. See `isRegularFile()` in `session_dir.go`.
5. **Skip symlink tests on Windows.** `os.Symlink` requires elevated privileges — use `runtime.GOOS == "windows"` guard.

## Cross-References

- **Issue:** [#138](https://github.com/unclesp1d3r/CipherSwarmAgent/issues/138) — original bug report
- **PR #160:** Per-task cleanup with absolute paths (merged)
- **PR #163:** Startup orphan cleanup (merged)
- **AGENTS.md:** "Hashcat Session Files" section
- **GOTCHAS.md:** `DirEntry.Type()` unknown type, `os.Symlink` Windows skip, `errcheck` discarded errors
- **Hashcat source:** `pidfile.c` (`folder_config->session_dir`), `folder.c` (directory resolution)

## Key Files

| File                         | Role                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------ |
| `lib/hashcat/session_dir.go` | `hashcatSessionDir()`, `CleanupOrphanedSessionFiles()`, `isRegularFile()`, `sessionPrefix` |
| `lib/hashcat/session.go`     | `sessionLogFile`/`sessionPidFile` fields, `Cleanup()` removal                              |
| `lib/agent/agent.go`         | Wires startup cleanup into `StartAgent()`                                                  |
