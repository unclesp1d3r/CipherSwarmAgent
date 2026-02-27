# Implementation Plan: Enhanced Task Monitoring and Recovery System

## Overview

This implementation plan breaks down the Enhanced Task Monitoring and Recovery System into discrete, actionable coding tasks. The system extends the existing CipherSwarmAgent with comprehensive monitoring, persistence, and recovery capabilities while maintaining full compatibility with the v1 Agent API contract.

The implementation follows a phased approach:

1. Core infrastructure (monitoring, persistence, recovery packages)
2. Integration with existing task management
3. Configuration and state management
4. Testing and validation

Each task builds incrementally on previous work, with checkpoints to validate functionality before proceeding.

## Tasks

- [ ] 1. Set up monitoring package infrastructure

  - [ ] 1.1 Create monitoring package structure and core types

    - Create `lib/monitoring/` directory
    - Implement `types.go` with `SystemMetrics`, `GPUMetrics`, `Alert`, `AlertType`, and `AlertSeverity` types
    - Implement `config.go` with `Config` struct for monitoring configuration
    - Add configuration constants to `lib/config/config.go` for monitoring defaults
    - _Requirements: 1.2, 4.1_

  - [ ] 1.2 Implement metrics collector

    - Implement `collector.go` with `Collector` struct and metrics collection logic
    - Add platform-specific GPU metrics collection (Linux, macOS, Windows build tags)
    - Implement CPU, memory, and disk space collection using standard library
    - Add goroutine-safe metrics caching with timestamp tracking
    - _Requirements: 1.2, 1.3_

  - \[ \]\* 1.3 Write property test for metrics collection interval

    - **Property 2: Monitoring metrics collection interval**
    - **Validates: Requirements 1.2**

  - [ ] 1.4 Implement alert manager

    - Implement `alerts.go` with alert generation and threshold evaluation logic
    - Add configurable threshold checking for GPU temperature, memory, disk space
    - Implement alert severity calculation based on threshold violations
    - Create buffered alert channel (size 100) for non-blocking alert delivery
    - _Requirements: 1.3, 4.2_

  - \[ \]\* 1.5 Write property test for threshold violation triggers

    - **Property 3: Threshold violation triggers action**
    - **Validates: Requirements 1.3, 4.2**

  - [ ] 1.6 Implement monitoring manager

    - Implement `manager.go` with `Manager` struct coordinating collectors and alerts
    - Add `StartMonitoring` and `StopMonitoring` methods with context support
    - Implement `GetCurrentMetrics` for on-demand metrics retrieval
    - Add goroutine for periodic metrics collection with configurable interval
    - Implement proper cleanup and goroutine cancellation on stop
    - _Requirements: 1.2, 1.3, 1.6_

  - \[ \]\* 1.7 Write unit tests for monitoring manager

    - Test monitoring lifecycle (start, collect, stop)
    - Test alert generation with mock metrics
    - Test concurrent access to metrics
    - Test context cancellation and cleanup
    - _Requirements: 1.2, 1.3_

- [ ] 2. Checkpoint - Validate monitoring package

  - Ensure all monitoring tests pass
  - Verify metrics collection works on target platforms
  - Ask the user if questions arise

- [ ] 3. Set up persistence package infrastructure

  - [ ] 3.1 Create persistence package structure and core types

    - Create `lib/persistence/` directory
    - Implement `types.go` with `TaskState`, `TaskProgress`, `MonitoringSummary`, `TaskHistoryEntry`, and `HistoryFilters` types
    - Add JSON struct tags for all persistence types
    - Add configuration constants to `lib/config/config.go` for persistence defaults
    - _Requirements: 3.1, 3.2, 5.1_

  - [ ] 3.2 Implement state store with atomic file operations

    - Implement `store.go` with file-based state storage
    - Add atomic file write using temp file + rename pattern
    - Implement state file path generation with agent-specific directories
    - Add file locking to prevent concurrent write conflicts
    - _Requirements: 3.1, 3.2, 3.7_

  - \[ \]\* 3.3 Write property test for state persistence round-trip

    - **Property 1: Task state persistence round-trip**
    - **Validates: Requirements 3.1, 3.2**

  - [ ] 3.4 Implement state manager operations

    - Implement `state.go` with `SaveTaskState`, `LoadTaskState`, `UpdateProgress` methods
    - Add `GetIncompleteTasksOnStartup` to scan for incomplete tasks
    - Implement `CleanupTaskState` for terminal task cleanup
    - Add `SaveMonitoringSnapshot` for periodic monitoring data persistence
    - Implement error handling with graceful degradation (log but continue)
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.6_

  - \[ \]\* 3.5 Write property test for incomplete task discovery

    - **Property 9: Incomplete tasks discovered on startup**
    - **Validates: Requirements 2.6, 3.3**

  - \[ \]\* 3.6 Write property test for terminal state cleanup

    - **Property 10: Terminal task states trigger cleanup**
    - **Validates: Requirements 3.5**

  - \[ \]\* 3.7 Write property test for agent-specific directories

    - **Property 12: Agent-specific state directories**
    - **Validates: Requirements 3.7**

  - [ ] 3.8 Implement history store with SQLite

    - Implement `history.go` with SQLite-based history storage
    - Create `task_history` table schema with indexes
    - Implement `SaveTaskHistory` to record completed tasks
    - Implement `GetTaskHistory` with filter support (date range, status, attack ID)
    - Add history rotation logic based on retention days and size limits
    - _Requirements: 5.1, 5.3, 5.4, 5.5_

  - \[ \]\* 3.9 Write property test for task completion history

    - **Property 4: Task completion generates history**
    - **Validates: Requirements 1.4, 5.1**

  - \[ \]\* 3.10 Write property test for history rotation

    - **Property 16: History storage rotation**
    - **Validates: Requirements 5.3**

  - [ ] 3.11 Implement persistence manager

    - Implement `manager.go` coordinating state and history operations
    - Add `NewManager` with state directory and history database initialization
    - Implement proper resource cleanup and database connection management
    - Add mutex protection for concurrent access
    - _Requirements: 3.1, 3.2, 5.1_

  - \[ \]\* 3.12 Write unit tests for persistence manager

    - Test state save/load with temp directories
    - Test atomic file operations
    - Test history storage and queries
    - Test cleanup operations
    - Test error handling and graceful degradation
    - _Requirements: 3.1, 3.2, 3.6_

- [ ] 4. Checkpoint - Validate persistence package

  - Ensure all persistence tests pass
  - Verify state files are created correctly
  - Verify history database operations work
  - Ask the user if questions arise

- [ ] 5. Set up recovery package infrastructure

  - [ ] 5.1 Create recovery package structure and core types

    - Create `lib/recovery/` directory
    - Implement `types.go` with `FailureType`, `Strategy`, `RecoveryAction` types
    - Add configuration constants to `lib/config/config.go` for recovery defaults
    - _Requirements: 2.1, 2.3, 2.4_

  - [ ] 5.2 Implement exponential backoff calculator

    - Implement `backoff.go` with `BackoffCalculator` struct
    - Add `NextDelay` method implementing exponential backoff with max limit
    - Add `Reset` method to restart backoff sequence
    - _Requirements: 2.1_

  - \[ \]\* 5.3 Write property test for exponential backoff

    - **Property 5: Network failure triggers exponential backoff**
    - **Validates: Requirements 2.1**

  - \[ \]\* 5.4 Write unit tests for backoff calculator

    - Test exponential growth of delays
    - Test maximum delay enforcement
    - Test reset functionality
    - _Requirements: 2.1_

  - [ ] 5.5 Implement recovery strategies

    - Implement `strategy.go` with predefined recovery strategies
    - Add network failure strategy (max retries, backoff config)
    - Add process crash strategy (restart delay, max attempts)
    - Add resource threshold strategy (pause/resume logic)
    - _Requirements: 2.1, 2.3, 2.5_

  - [ ] 5.6 Implement network failure recovery handler

    - Implement `handlers.go` with `HandleNetworkFailure` method
    - Add hashcat process pause logic
    - Implement exponential backoff retry loop with context support
    - Add server task validation after network restoration
    - Implement task resumption after successful reconnection
    - Add error reporting via `cserrors.LogAndSendError` after max retries
    - _Requirements: 2.1, 2.2_

  - \[ \]\* 5.7 Write property test for task resumption validation

    - **Property 6: Task resumption validates server state**
    - **Validates: Requirements 2.2, 2.7, 3.4**

  - [ ] 5.8 Implement process crash recovery handler

    - Add `HandleProcessCrash` method to `handlers.go`
    - Implement exit code and stderr capture
    - Add failure count tracking and max retry checking
    - Implement process restart with saved state and restore point
    - Add error reporting for unrecoverable crashes
    - _Requirements: 2.3, 2.4_

  - \[ \]\* 5.9 Write property test for process crash restart

    - **Property 7: Process crash triggers restart with limit**
    - **Validates: Requirements 2.3, 2.4**

  - [ ] 5.10 Implement resource threshold recovery handler

    - Add `HandleResourceThreshold` method to `handlers.go`
    - Implement GPU temperature monitoring and pause/resume logic
    - Add memory threshold handling
    - Add disk space threshold handling
    - Implement temperature-based resume with configurable delta
    - _Requirements: 2.5_

  - \[ \]\* 5.11 Write property test for temperature throttling

    - **Property 8: Temperature throttling round-trip**
    - **Validates: Requirements 2.5**

  - [ ] 5.12 Implement recovery manager

    - Implement `manager.go` coordinating recovery operations
    - Add `NewManager` with dependencies (persistence, monitoring)
    - Implement `AttemptTaskRecovery` for general recovery coordination
    - Add `ShouldRetryTask` for retry decision logic
    - Integrate with existing `cserrors` package for error reporting
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - \[ \]\* 5.13 Write unit tests for recovery manager

    - Test network failure recovery flow
    - Test process crash recovery flow
    - Test resource threshold handling
    - Test max retry enforcement
    - Test error reporting integration
    - _Requirements: 2.1, 2.3, 2.5_

- [ ] 6. Checkpoint - Validate recovery package

  - Ensure all recovery tests pass
  - Verify backoff calculations are correct
  - Verify recovery handlers work as expected
  - Ask the user if questions arise

- [ ] 7. Extend configuration system

  - [ ] 7.1 Add monitoring configuration constants

    - Add monitoring defaults to `lib/config/config.go`
    - Include `DefaultMonitoringEnabled`, `DefaultMonitoringIntervalSeconds`
    - Include `DefaultGPUTempThreshold`, `DefaultMemoryThresholdPercent`, `DefaultDiskSpaceThresholdGB`
    - _Requirements: 4.1_

  - [ ] 7.2 Add recovery configuration constants

    - Add recovery defaults to `lib/config/config.go`
    - Include `DefaultRecoveryMaxRetries`, `DefaultNetworkBackoffStartSeconds`, `DefaultNetworkBackoffMaxSeconds`
    - Include `DefaultProcessRestartDelaySeconds`, `DefaultTemperatureResumeDelta`
    - _Requirements: 2.1, 2.3, 2.5_

  - [ ] 7.3 Add persistence configuration constants

    - Add persistence defaults to `lib/config/config.go`
    - Include `DefaultPersistenceEnabled`, `DefaultStateDirectory`, `DefaultHistoryRetentionDays`
    - Include `DefaultHistoryMaxSizeMB`, `DefaultCleanupOnCompletion`
    - _Requirements: 3.1, 5.3_

  - [ ] 7.4 Extend agentstate.State with new fields

    - Add monitoring, persistence, and recovery manager fields to `agentstate/agentstate.go`
    - Add atomic fields for monitoring configuration (enabled, interval, thresholds)
    - Add atomic fields for recovery configuration (max retries, backoff settings)
    - Add atomic fields for persistence configuration (enabled, retention, cleanup)
    - Add string fields for state directory paths
    - _Requirements: 1.2, 2.1, 3.1, 4.1_

  - [ ] 7.5 Implement configuration loading in cmd/root.go

    - Add Viper defaults for all monitoring, recovery, and persistence settings
    - Add CLI flags for key configuration options (monitoring enabled, intervals, thresholds)
    - Bind CLI flags to Viper configuration keys
    - Add environment variable support with `CIPHERSWARMAGENT_` prefix
    - _Requirements: 4.1, 4.6_

  - \[ \]\* 7.6 Write property test for configuration defaults

    - **Property 13: Configuration defaults applied**
    - **Validates: Requirements 4.1**

  - \[ \]\* 7.7 Write property test for configuration override precedence

    - **Property 15: Configuration override precedence**
    - **Validates: Requirements 4.6**

  - [ ] 7.8 Implement configuration validation in SetupSharedState

    - Add validation for monitoring interval (clamp to 1-60 seconds)
    - Add validation for GPU temperature threshold (clamp to 50-100°C)
    - Add validation for memory threshold (clamp to 50-95%)
    - Add validation for recovery max retries (clamp to 1-10)
    - Log warnings for invalid values and apply defaults
    - Store validated values in `agentstate.State` atomic fields
    - _Requirements: 4.1_

  - \[ \]\* 7.9 Write unit tests for configuration validation

    - Test default application for missing values
    - Test clamping of out-of-range values
    - Test warning logs for invalid configuration
    - Test CLI flag override precedence
    - _Requirements: 4.1, 4.6_

- [ ] 8. Checkpoint - Validate configuration system

  - Ensure configuration loads correctly
  - Verify defaults are applied
  - Verify CLI flags override config file
  - Ask the user if questions arise

- [ ] 9. Integrate monitoring with task management

  - [ ] 9.1 Extend task.Manager with monitoring integration

    - Add monitoring, persistence, and recovery manager fields to `lib/task/Manager`
    - Update `NewManager` to accept monitoring, persistence, and recovery dependencies
    - Add `EnhancedTaskStatus` type with monitoring data
    - Add `RecoveryInfo` type for recovery metadata
    - _Requirements: 1.1, 1.2, 1.4_

  - [ ] 9.2 Implement RunTaskWithMonitoring method

    - Create `RunTaskWithMonitoring` method wrapping existing `RunTask` logic
    - Add task state persistence on task acceptance
    - Start monitoring before hashcat execution
    - Integrate status update loop with monitoring metrics
    - Add monitoring data to status update payloads
    - Stop monitoring on task completion
    - Save task history on completion
    - _Requirements: 1.1, 1.2, 1.4, 1.5_

  - \[ \]\* 9.3 Write property test for monitoring log creation

    - **Property 24: Monitoring log creation**
    - **Validates: Requirements 1.1**

  - \[ \]\* 9.4 Write property test for status update format compatibility

    - **Property 19: Status update schema compliance**
    - **Validates: Requirements 1.5, 6.2**

  - [ ] 9.5 Implement PauseTask and ResumeTask methods

    - Add `PauseTask` method to pause hashcat process
    - Add `ResumeTask` method to resume paused hashcat process
    - Update task state on pause/resume
    - Integrate with recovery manager for resource threshold handling
    - _Requirements: 2.5_

  - [ ] 9.6 Implement GetTaskStatus with monitoring data

    - Add `GetTaskStatus` method returning `EnhancedTaskStatus`
    - Include current monitoring metrics in status
    - Include recovery information (failure count, last failure)
    - _Requirements: 1.2, 2.4_

  - [ ] 9.7 Integrate recovery handlers with task execution

    - Add error handling for network failures during status updates
    - Call `recovery.HandleNetworkFailure` on API errors
    - Add error handling for hashcat process crashes
    - Call `recovery.HandleProcessCrash` on unexpected process exit
    - Add monitoring alert handling
    - Call `recovery.HandleResourceThreshold` on threshold violations
    - _Requirements: 2.1, 2.3, 2.5_

  - \[ \]\* 9.8 Write property test for persistence failure graceful degradation

    - **Property 11: Persistence failures don't block execution**
    - **Validates: Requirements 3.6**

  - \[ \]\* 9.9 Write integration tests for task monitoring

    - Test complete task lifecycle with monitoring
    - Test status updates include monitoring data
    - Test task pause/resume functionality
    - Test recovery integration
    - _Requirements: 1.1, 1.2, 1.4, 2.1, 2.3, 2.5_

- [ ] 10. Checkpoint - Validate task monitoring integration

  - Ensure task execution works with monitoring
  - Verify status updates include monitoring data
  - Verify pause/resume functionality
  - Ask the user if questions arise

- [ ] 11. Implement startup recovery logic

  - [ ] 11.1 Add incomplete task recovery to agent startup

    - Modify `lib/agent/agent.go` `StartAgent` function
    - Call `persistence.GetIncompleteTasksOnStartup` on agent start
    - For each incomplete task, verify task is still active via API
    - Resume valid incomplete tasks using `recovery.AttemptTaskRecovery`
    - Abandon tasks that are no longer active on server
    - Log recovery attempts and outcomes
    - _Requirements: 2.6, 3.3, 3.4_

  - \[ \]\* 11.2 Write unit tests for startup recovery

    - Test incomplete task discovery
    - Test server validation of incomplete tasks
    - Test task resumption flow
    - Test abandonment of invalid tasks
    - _Requirements: 2.6, 3.3, 3.4_

- [ ] 12. Implement heartbeat enhancement

  - [ ] 12.1 Add monitoring data to heartbeat payload

    - Modify heartbeat logic in `lib/agent/agent.go`
    - Include current task ID and status in heartbeat
    - Include system health metrics from monitoring manager
    - Maintain backward compatibility with existing heartbeat format
    - _Requirements: 1.6_

  - \[ \]\* 12.2 Write property test for heartbeat task status inclusion

    - **Property 23: Heartbeat includes task status**
    - **Validates: Requirements 1.6**

  - \[ \]\* 12.3 Write unit tests for enhanced heartbeat

    - Test heartbeat includes task status when task is running
    - Test heartbeat without task status when no task is running
    - Test heartbeat includes system metrics
    - _Requirements: 1.6_

- [ ] 13. Implement API compatibility validation

  - \[ \]\* 13.1 Write property test for API endpoint compatibility

    - **Property 18: API endpoint compatibility**
    - **Validates: Requirements 6.1**

  - \[ \]\* 13.2 Write property test for Bearer token authentication

    - **Property 20: Bearer token authentication**
    - **Validates: Requirements 6.3**

  - \[ \]\* 13.3 Write property test for error report format compliance

    - **Property 21: Error report format compliance**
    - **Validates: Requirements 6.4**

  - \[ \]\* 13.4 Write property test for shutdown notification

    - **Property 22: Shutdown notification**
    - **Validates: Requirements 6.6**

  - \[ \]\* 13.5 Write integration tests for API compatibility

    - Test all API endpoints match swagger.json specification
    - Test status update payloads validate against schema
    - Test error reporting uses correct format
    - Test authentication headers are correct
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 14. Implement history and analytics features

  - [ ] 14.1 Add CLI command for task history viewing

    - Add `history` subcommand to `cmd/root.go`
    - Implement flags for filtering (date range, status, attack ID, limit)
    - Query history database using `persistence.GetTaskHistory`
    - Format and display history entries in table format
    - _Requirements: 5.2_

  - [ ] 14.2 Add CLI command for history export

    - Add `export` subcommand under `history` command
    - Implement JSON export format
    - Implement CSV export format
    - Add output file flag
    - _Requirements: 5.4_

  - \[ \]\* 14.3 Write property test for history export format validity

    - **Property 17: History export format validity**
    - **Validates: Requirements 5.4**

  - [ ] 14.4 Implement benchmark history storage

    - Modify benchmark submission logic in `lib/benchmark/`
    - Store benchmark results in history database
    - Include timestamp, hash type, device, and performance metrics
    - _Requirements: 5.5_

  - \[ \]\* 14.5 Write property test for benchmark history storage

    - **Property 25: Benchmark history storage**
    - **Validates: Requirements 5.5**

  - \[ \]\* 14.6 Write unit tests for history CLI commands

    - Test history viewing with various filters
    - Test JSON export format
    - Test CSV export format
    - Test benchmark history storage
    - _Requirements: 5.2, 5.4, 5.5_

- [ ] 15. Implement per-device threshold support

  - [ ] 15.1 Add per-device threshold configuration

    - Extend monitoring configuration to support device-specific thresholds
    - Add YAML schema for per-device thresholds map
    - Implement threshold lookup by device ID in alert manager
    - Fall back to global threshold if device-specific not configured
    - _Requirements: 4.4_

  - \[ \]\* 15.2 Write property test for per-device thresholds

    - **Property 14: Per-device thresholds applied correctly**
    - **Validates: Requirements 4.4**

  - \[ \]\* 15.3 Write unit tests for per-device thresholds

    - Test device-specific threshold application
    - Test fallback to global threshold
    - Test multi-GPU systems with mixed thresholds
    - _Requirements: 4.4_

- [ ] 16. Implement custom monitoring rules

  - [ ] 16.1 Add custom rule configuration support

    - Define custom rule schema in YAML configuration
    - Implement rule evaluation engine in monitoring manager
    - Support basic comparison operators (>, \<, ==, >=, \<=)
    - Support logical operators (AND, OR)
    - _Requirements: 4.3_

  - \[ \]\* 16.2 Write property test for custom rule evaluation

    - **Property 26: Custom monitoring rules evaluation**
    - **Validates: Requirements 4.3**

  - \[ \]\* 16.3 Write unit tests for custom rules

    - Test rule parsing from configuration
    - Test rule evaluation with various metrics
    - Test alert generation from custom rules
    - _Requirements: 4.3_

- [ ] 17. Checkpoint - Validate all features

  - Ensure all unit tests pass
  - Ensure all property tests pass (minimum 100 iterations each)
  - Verify cross-platform compatibility
  - Ask the user if questions arise

- [ ] 18. Add test helpers and mocks

  - [ ] 18.1 Create monitoring test helpers

    - Add `SetupTestMonitoring` to `lib/testhelpers/`
    - Add mock monitoring manager for testing
    - Add mock metrics generator for testing
    - _Requirements: Testing infrastructure_

  - [ ] 18.2 Create persistence test helpers

    - Add `SetupTestPersistence` to `lib/testhelpers/`
    - Add mock persistence manager for testing
    - Add test state file generators
    - _Requirements: Testing infrastructure_

  - [ ] 18.3 Create recovery test helpers

    - Add `SetupTestRecovery` to `lib/testhelpers/`
    - Add mock recovery manager for testing
    - Add failure scenario generators
    - _Requirements: Testing infrastructure_

- [ ] 19. Documentation and examples

  - [ ] 19.1 Update configuration documentation

    - Document all new configuration options in docs/
    - Add example YAML configurations
    - Document CLI flags for monitoring and recovery
    - _Requirements: Documentation_

  - [ ] 19.2 Add monitoring and recovery examples

    - Create example configurations for different use cases
    - Document recovery scenarios and expected behavior
    - Add troubleshooting guide for common issues
    - _Requirements: Documentation_

  - [ ] 19.3 Update API documentation

    - Document enhanced status update format
    - Document monitoring data fields
    - Document backward compatibility guarantees
    - _Requirements: Documentation_

- [ ] 20. Final validation and cleanup

  - [ ] 20.1 Run full test suite

    - Run `go test -race ./...` to detect data races
    - Run `go test -cover ./...` and verify >80% coverage
    - Run all property tests with 100+ iterations
    - Run integration tests on all platforms
    - _Requirements: All_

  - [ ] 20.2 Run linting and formatting

    - Run `golangci-lint run ./...` and fix all issues
    - Run `gofmt` on all new files
    - Verify no gosec warnings (or properly annotated)
    - _Requirements: Code quality_

  - [ ] 20.3 Performance validation

    - Run benchmarks for monitoring overhead
    - Run benchmarks for persistence operations
    - Verify monitoring overhead is \<1% CPU
    - Verify state updates complete in \<10ms
    - _Requirements: Performance_

  - [ ] 20.4 Cross-platform validation

    - Test on Linux (Ubuntu latest)
    - Test on macOS (latest)
    - Test on Windows (latest)
    - Verify GPU metrics collection on each platform
    - _Requirements: Cross-platform compatibility_

- [ ] 21. Final checkpoint

  - All tests pass on all platforms
  - All linting checks pass
  - Performance benchmarks meet targets
  - Documentation is complete
  - Ready for code review

## Notes

- Tasks marked with `*` are optional property-based and unit tests that can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation throughout implementation
- Property tests validate universal correctness properties across randomized inputs
- Unit tests validate specific examples, edge cases, and integration points
- The implementation maintains full backward compatibility with existing v1 Agent API
- All new packages follow existing Go idioms and project structure conventions
- Configuration follows existing Viper-based system with CLI flag and environment variable support
- Error handling integrates with existing `cserrors` package for consistent error reporting
