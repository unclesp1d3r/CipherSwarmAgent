# Unit Testing Implementation Plan for CipherSwarmAgent

This checklist identifies high-value unit tests to implement, organized by module. Each item includes context and rationale to support implementation. Follow Go best practices (see below).

---

## General Go Testing Best Practices

- Use table-driven tests for core logic
- Place tests in the same package, with `_test.go` suffix
- Use mocks for network and OS interactions
- Run with `go test -cover`
- Cover error paths and edge cases

---

## Checklist: Recommended Unit Tests

### lib/clientUtils.go

- [ ] `findHashcatBinary` — Test with various path scenarios (found, not found, not executable)
- [ ] `isExecAny` — Test file permission edge cases
- [ ] `getCurrentHashcatVersion` — Mock binary presence and version output
- [ ] `CheckForExistingClient` — Test with/without PID file, running/stale PID
- [ ] `CreateLockFile` — Test file creation and error handling
- [ ] `CreateDataDirs` — Test directory creation, missing/invalid paths
- [ ] `downloadHashList` — Mock API, test file writing and error paths
- [ ] `removeExistingFile` — Test file removal, error handling
- [ ] `writeResponseToFile` — Test file writing, error handling
- [ ] `appendChecksumToURL` — Test URL parsing and query param logic
- [ ] `extractHashcatArchive` — Mock file ops, test backup/extract logic
- [ ] `moveArchiveFile` — Test file move, error handling
- [ ] `base64ToHex` — Test base64/hex conversion, blank input
- [ ] `resourceNameOrBlank` — Test nil and non-nil resource

### lib/fileUtils.go

- [ ] `downloadFile` — Mock download, test checksum logic, error paths
- [ ] `fileExistsAndValid` — Test with/without checksum, file present/absent
- [ ] `downloadAndVerifyFile` — Mock download, test checksum verification
- [ ] `cleanupTempDir` — Test directory removal, error handling
- [ ] `writeCrackedHashToFile` — Test file writing, error handling

### lib/hashcat/params.go

- [ ] `Params.Validate` — Table-driven tests for all attack modes, invalid configs
- [ ] `validateDictionaryAttack` — Test missing/blank wordlist
- [ ] `validateMaskAttack` — Test mask/masklist logic
- [ ] `validateHybridAttack` — Test missing mask/wordlist
- [ ] `Params.maskArgs` — Test custom charset logic, edge cases
- [ ] `Params.toCmdArgs` — Test argument generation for all modes, missing files
- [ ] `Params.toRestoreArgs` — Test restore arg generation

### lib/hashcat/session.go

- [ ] `Session.Start` — Mock process, test error paths
- [ ] `Session.attachPipes` — Test pipe errors
- [ ] `Session.startTailer` — Mock tail, test error handling
- [ ] `Session.handleTailerOutput` — Test line parsing, error cases
- [ ] `Session.handleStdout` — Test JSON and non-JSON output
- [ ] `Session.handleStderr` — Test stderr handling
- [ ] `Session.Kill` — Test process kill logic
- [ ] `Session.Cleanup` — Test file cleanup logic
- [ ] `Session.CmdLine` — Test command string
- [ ] `NewHashcatSession` — Test session creation, error paths
- [ ] `createOutFile` — Test file creation, permission errors
- [ ] `createTempFile` — Test temp file creation, permission errors
- [ ] `createCharsetFiles` — Test charset file creation, error handling

### lib/crackerUtils.go

- [ ] `setNativeHashcatPath` — Mock binary, test config update
- [ ] `UpdateCracker` — Mock API, test update logic
- [ ] `validateHashcatDirectory` — Test directory/binary presence

### lib/errorUtils.go

- [ ] `logAndSendError` — Test error logging/reporting
- [ ] `handleConfigurationError` — Test error type handling
- [ ] `handleAPIError` — Test error type handling
- [ ] `handleHeartbeatError` — Test error type handling
- [ ] `handleStatusUpdateError` — Test error type handling
- [ ] `handleSDKError` — Test status code handling
- [ ] `handleTaskNotFound` — Test session kill/cleanup
- [ ] `handleTaskGone` — Test session kill
- [ ] `handleGetZapsError` — Test error type handling
- [ ] `handleResponseStream` — Test zap file writing
- [ ] `SendAgentError` — Mock API, test error sending
- [ ] `handleSendError` — Test error type handling
- [ ] `handleAcceptTaskError` — Test error type handling
- [ ] `handleTaskError` — Test error type handling

### lib/taskManager.go

- [ ] `AcceptTask` — Mock API, test nil/error cases
- [ ] `markTaskExhausted` — Mock API, test nil/error cases
- [ ] `AbandonTask` — Mock API, test nil/error cases
- [ ] `RunTask` — Mock session, test error paths

---

## Context for Implementation

- **Mocks:** Use Go interfaces and test helpers to mock file I/O, OS, and network dependencies.
- **Table-driven tests:** Use for validation and argument generation logic.
- **Error paths:** Cover all error returns, not just happy paths.
- **CI:** Integrate with `just test` and `just ci-check`.
- **Reference:** See Go best practices in `code/go` Cursor Rule.

---

This checklist is a living document. Expand as new logic is added or refactored.
