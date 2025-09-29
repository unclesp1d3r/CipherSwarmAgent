# Project Structure

This document explains the organization and architecture of the CipherSwarm Agent codebase.

## Overview

The CipherSwarm Agent is built with Go 1.22+ and follows a modular architecture for maintainability and testability. The project structure separates concerns into logical modules and provides clear interfaces between components.

## Directory Layout

```text
CipherSwarmAgent/
├── cmd/                    # CLI entrypoint and command registration
├── lib/                    # Core agent logic and utilities
│   ├── agent/             # Agent lifecycle management
│   ├── arch/              # OS-specific abstractions
│   ├── config/            # Configuration management
│   ├── cracker/           # Hashcat binary management
│   ├── cserrors/          # Structured error handling
│   ├── downloader/        # File download management
│   ├── hashcat/           # Hashcat integration and session management
│   ├── progress/          # Progress tracking and monitoring
│   ├── sdk/               # Internal CipherSwarm API SDK
│   └── zap/               # Shared crack file management
├── shared/                 # Global state and shared types
├── docs/                   # Documentation (this directory)
├── .github/               # GitHub workflows and templates
├── .chglog/               # Changelog configuration
├── .cursor/               # Cursor editor configuration
├── .devcontainer/         # VS Code dev container
├── .kiro/                 # Kiro AI assistant configuration
│   ├── hooks/             # Agent hooks for automation
│   ├── specs/             # Feature specifications
│   │   └── enhanced-task-monitoring/  # Enhanced monitoring system spec
│   └── steering/          # AI steering rules
├── Dockerfile             # Container build for agent
├── Dockerfile.releaser    # Container for releases
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── justfile               # Command runner configuration
├── main.go                # Application entrypoint
├── mkdocs.yml             # Documentation configuration
├── package.json           # Node.js dependencies for tooling
└── README.md              # Project overview
```

## Core Modules

### 1. Main Entrypoint (`main.go`)

The application's entry point that uses Charmbracelet Fang for enhanced CLI execution.

```go
package main

import (
    "context"
    "os"
    
    "github.com/charmbracelet/fang"
    "github.com/unclesp1d3r/cipherswarmagent/cmd"
)

func main() {
    if err := fang.Execute(context.Background(), cmd.RootCmd); err != nil {
        os.Exit(1)
    }
}
```

### 2. Command Interface (`cmd/`)

#### `cmd/root.go`

- **Purpose**: Cobra CLI command definition and configuration
- **Key Functions**:
  - Command-line flag parsing
  - Configuration binding (Viper)
  - Agent lifecycle management
  - Signal handling for graceful shutdown

**Key Components**:

- `rootCmd`: Main Cobra command definition
- `initConfig()`: Configuration initialization
- `startAgent()`: Main agent execution loop
- Flag definitions for all configuration options

### 3. Core Library (`lib/`)

The main business logic of the agent, organized by functional area:

#### `lib/agentClient.go`

- **Purpose**: Primary agent logic and server communication
- **Key Functions**:
  - `AuthenticateAgent()`: Server authentication
  - `GetAgentConfiguration()`: Fetch server configuration
  - `UpdateAgentMetadata()`: Send agent info to server
  - `SendHeartBeat()`: Periodic health check
  - `DownloadFiles()`: Attack resource downloads

#### `lib/taskManager.go`

- **Purpose**: Task lifecycle management
- **Key Functions**:
  - `GetNewTask()`: Poll for available tasks
  - `AcceptTask()`: Accept and prepare task
  - `RunTask()`: Execute task with Hashcat
  - `markTaskExhausted()`: Mark task complete

#### `lib/benchmarkManager.go`

- **Purpose**: Device benchmarking and capability detection
- **Key Functions**:
  - `UpdateBenchmarks()`: Run performance benchmarks
  - `sendBenchmarkResults()`: Submit results to server
  - `runBenchmarkTask()`: Execute benchmark session

#### `lib/errorUtils.go`

- **Purpose**: Centralized error handling and reporting
- **Key Functions**:
  - `SendAgentError()`: Report errors to server
  - `handleAPIError()`: API error processing
  - `logAndSendError()`: Combined logging and reporting

#### `lib/fileUtils.go`

- **Purpose**: File operations and download management
- **Key Functions**:
  - `downloadFile()`: Secure file downloads with checksums
  - `fileExistsAndValid()`: File validation
  - `writeCrackedHashToFile()`: Result file management

#### `lib/agent/agent.go`

- **Purpose**: Agent lifecycle management and coordination
- **Key Functions**:
  - `StartAgent()`: Main agent initialization and startup
  - `startHeartbeatLoop()`: Heartbeat management
  - `startAgentLoop()`: Main agent processing loop
  - `processTask()`: Task processing coordination

#### `lib/crackerUtils.go`

- **Purpose**: Hashcat binary management
- **Key Functions**:
  - `UpdateCracker()`: Download/update Hashcat binaries
  - `setNativeHashcatPath()`: Configure native binary usage

#### `lib/runners.go`

- **Purpose**: Task execution and monitoring
- **Key Functions**:
  - `runAttackTask()`: Main task runner
  - `handleStdOutLine()`: Process Hashcat output
  - `handleCrackedHash()`: Process found hashes

#### `lib/outputs.go`

- **Purpose**: User interface and logging output
- **Key Functions**:
  - `DisplayStartup()`: Startup messages
  - `DisplayNewTask()`: Task information display
  - Various status and progress displays

#### `lib/dataTypes.go`

- **Purpose**: Core data structures and type definitions
- **Key Types**:
  - `agentConfig`: Configuration structure
  - `benchmarkResult`: Performance data
  - Type conversion utilities

### 4. SDK Implementation (`lib/sdk/`)

Internal idiomatic SDK for CipherSwarm API interactions:

#### `lib/sdk/client.go`

- **Purpose**: Main SDK client with service-oriented design
- **Key Types**:
  - `Client`: Main client with Agent, Task, and Attack services
  - `ClientOption`: Configuration options using functional options pattern
- **Key Functions**:
  - `NewClient()`: Create configured client with options
  - `WithTimeout()`, `WithRetryConfig()`: Configuration options

#### `lib/sdk/client_test.go`

- **Purpose**: Comprehensive unit tests for SDK client
- **Coverage**: Client creation, options, service initialization, error handling

### 5. Configuration Management (`lib/config/`)

Advanced configuration management system:

#### `lib/config/config.go`

- **Purpose**: Multi-source configuration management
- **Key Functions**:
  - `InitConfig()`: Initialize configuration from files, env vars, and CLI flags
  - `SetupSharedState()`: Configure shared state from configuration
  - `SetDefaultConfigValues()`: Set sensible defaults

### 6. Agent Management (`lib/agent/`)

Agent lifecycle and coordination:

#### `lib/agent/agent.go`

- **Purpose**: Main agent orchestration and lifecycle management
- **Key Functions**:
  - `StartAgent()`: Complete agent initialization and startup
  - Signal handling and graceful shutdown
  - Heartbeat and task processing loops

### 7. Error Handling (`lib/cserrors/`)

Structured error handling and reporting:

#### `lib/cserrors/errors.go`

- **Purpose**: Centralized error management with server reporting
- **Features**: Structured error types, severity levels, context preservation

### 8. File Management (`lib/downloader/`, `lib/cracker/`)

Secure file operations and binary management:

#### `lib/downloader/downloader.go`

- **Purpose**: Secure file downloads with checksum verification
- **Features**: Progress tracking, retry logic, integrity validation

#### `lib/cracker/cracker.go`

- **Purpose**: Hashcat binary management and updates
- **Features**: Binary downloads, version management, platform detection

### 9. Hashcat Integration (`lib/hashcat/`)

Specialized module for Hashcat process management:

#### `lib/hashcat/session.go`

- **Purpose**: Hashcat process lifecycle management
- **Key Types**:
  - `Session`: Represents a running Hashcat instance
- **Key Functions**:
  - `NewHashcatSession()`: Create configured session
  - `Start()`: Launch Hashcat process
  - `Kill()`: Terminate process gracefully
  - `Cleanup()`: Resource cleanup

#### `lib/hashcat/params.go`

- **Purpose**: Hashcat parameter configuration
- **Key Types**:
  - `Params`: Attack configuration structure
- **Key Functions**:
  - `Validate()`: Parameter validation
  - `toCmdArgs()`: Command-line argument generation
  - Attack mode-specific parameter handling

#### `lib/hashcat/types.go`

- **Purpose**: Hashcat data structure definitions
- **Key Types**:
  - `Status`: Real-time status information
  - `Result`: Cracked hash results
  - `StatusDevice`: GPU/CPU device status

### 10. Progress Tracking (`lib/progress/`)

Real-time progress monitoring and tracking:

#### `lib/progress/progress_tracking.go`

- **Purpose**: Download and task progress monitoring
- **Features**: Real-time progress bars, concurrent tracking, terminal-friendly display

#### `lib/progress/utils.go`

- **Purpose**: Progress tracking utilities and helpers

### 11. ZAP Integration (`lib/zap/`)

Shared crack file management:

#### `lib/zap/zap.go`

- **Purpose**: ZAP (Zero Application Performance) file management
- **Features**: Shared crack file handling, multi-agent coordination

### 12. OS Abstractions (`lib/arch/`)

Platform-specific functionality for cross-platform support:

#### `lib/arch/linux.go`

- Linux-specific implementations
- Device detection via system tools
- Native package manager integration

#### `lib/arch/darwin.go`

- macOS-specific implementations
- Apple Silicon and Intel support
- Homebrew integration support

#### `lib/arch/windows.go`

- Windows-specific implementations
- PowerShell-based device detection
- Windows package manager support

**Common Interface**:

- `GetDevices()`: Device enumeration
- `GetHashcatVersion()`: Version detection
- `Extract7z()`: Archive extraction
- `GetDefaultHashcatBinaryName()`: Platform binary names

### 13. Legacy Core Files

#### `lib/agentClient.go`

- **Purpose**: Primary agent logic and server communication (being enhanced)
- **Key Functions**:
  - `AuthenticateAgent()`: Server authentication using SDK
  - `GetAgentConfiguration()`: Fetch server configuration
  - `UpdateAgentMetadata()`: Send agent info to server
  - `SendHeartBeat()`: Periodic health check with enhanced state handling

#### `lib/taskManager.go`

- **Purpose**: Task lifecycle management (being enhanced with monitoring)
- **Key Functions**:
  - `GetNewTask()`: Poll for available tasks
  - `AcceptTask()`: Accept and prepare task
  - `RunTask()`: Execute task with enhanced monitoring

#### `lib/benchmarkManager.go`

- **Purpose**: Device benchmarking and capability detection
- **Features**: Performance benchmarks, device detection, capability reporting

### 14. Shared State (`shared/`)

#### `shared/shared.go`

- **Purpose**: Global application state and configuration
- **Key Types**:
  - `agentState`: Runtime state management with enhanced monitoring support
  - `activity`: Current agent activity enum
- **Global Variables**:
  - `State`: Shared agent state with enhanced configuration
  - `Logger`: Application logger with structured logging
  - `ErrorLogger`: Error-specific logger

## Architecture Patterns

### 1. Modular Design

Each major functional area is separated into its own module:

- **Separation of Concerns**: Clear boundaries between functionality
- **Testability**: Modules can be tested independently
- **Maintainability**: Changes are localized to relevant modules

### 2. Interface-Based Design

Key interfaces abstract platform-specific functionality:

- **OS Abstractions**: Platform-specific code isolated in `arch/`
- **Hashcat Integration**: Clean interface to external process
- **Network Operations**: Abstracted API communication

### 3. Configuration Management

Multi-layered configuration system:

- **Command-line flags** (highest priority)
- **Environment variables**
- **Configuration files**
- **Default values** (lowest priority)

### 4. Error Handling

Centralized error management:

- **Structured Errors**: Custom error types with context
- **Error Reporting**: Automatic server notification
- **Graceful Degradation**: Non-fatal error recovery

### 5. State Management

Global state management with clear ownership:

- **Shared State**: Global configuration and runtime state
- **Local State**: Module-specific state management
- **Immutable Configuration**: Runtime configuration is read-only

## Data Flow

### 1. Startup Sequence

```mermaid
graph TD
    A[main.go] --> B[cmd/root.go]
    B --> C[Configuration Loading]
    C --> D[Authentication]
    D --> E[Benchmarking]
    E --> F[Main Loop]
```

### 2. Task Execution Flow

```mermaid
graph TD
    A[Poll for Tasks] --> B[Accept Task]
    B --> C[Download Files]
    C --> D[Create Hashcat Session]
    D --> E[Start Execution]
    E --> F[Monitor Progress]
    F --> G[Report Results]
    G --> H[Cleanup]
```

### 3. Error Handling Flow

```mermaid
graph TD
    A[Error Occurs] --> B[Log Locally]
    B --> C[Report to Server]
    C --> D{Fatal Error?}
    D -->|Yes| E[Shutdown]
    D -->|No| F[Continue Operation]
```

## Testing Structure

### Unit Tests

- **File Pattern**: `*_test.go`
- **Coverage**: Core logic and utilities
- **Mocking**: External dependencies mocked
- **Examples**:
  - `lib/agentClient_test.go`
  - `lib/clientUtils_test.go`

### Integration Tests

- **Purpose**: Test component interactions
- **Scope**: API communication, file operations
- **Environment**: Controlled test environment

### Benchmark Tests

- **Purpose**: Performance testing
- **Scope**: Critical path operations
- **Metrics**: CPU, memory, and network usage

## Build and Release

### Development Build

```bash
# Local development
go build -o cipherswarm-agent

# With build info
go build -ldflags "-X main.version=dev -X main.commit=$(git rev-parse HEAD)"
```

### Release Build

- **GoReleaser**: Automated release builds
- **Cross-compilation**: Multiple OS/architecture support
- **Packaging**: Binaries, packages (deb/rpm), and Docker images
- **Distribution**: GitHub releases and container registries

### Docker Build

- **Multi-stage**: Separate build and runtime stages
- **Base Images**: Hashcat-enabled base images
- **Variants**: Standard and POCL (CPU-only) versions

## Development Guidelines

### Code Organization

1. **Single Responsibility**: Each function has one clear purpose
2. **Clear Naming**: Functions and variables have descriptive names
3. **Error Handling**: All errors are handled appropriately
4. **Documentation**: Public APIs have Go doc comments

### Adding New Features

1. **Design**: Consider where new functionality belongs
2. **Interfaces**: Define clean interfaces for new components
3. **Testing**: Add unit tests for new functionality
4. **Documentation**: Update relevant documentation

### Platform Support

When adding platform-specific code:

1. **Abstraction**: Use the `arch/` package pattern
2. **Interface**: Define common interfaces
3. **Fallbacks**: Provide sensible defaults
4. **Testing**: Test on all supported platforms

## Dependencies

### Core Dependencies

- **Cobra**: CLI framework and command parsing
- **Viper**: Configuration management with multi-source support
- **Charmbracelet Log**: Structured logging with enhanced formatting
- **Charmbracelet Fang**: Enhanced CLI execution framework
- **Internal SDK**: Idiomatic CipherSwarm API client (replacing external SDK)
- **Shirou gopsutil**: System and process utilities for cross-platform monitoring
- **Hashicorp go-getter**: Secure file downloading with multiple protocols
- **Cheggaaa pb**: Progress bar library for download tracking

### Build Dependencies

- **GoReleaser**: Release automation and cross-platform builds
- **Just**: Command runner for development tasks
- **MkDocs Material**: Documentation generation with enhanced theming
- **UV**: Python package manager for documentation tooling
- **Pre-commit**: Git hooks for code quality
- **Commitlint**: Conventional commit message validation
- **golangci-lint**: Comprehensive Go linting

### Optional Dependencies

- **Hashcat**: Hash cracking engine (bundled in Docker)
- **7zip**: Archive extraction

## Security Considerations

### Secure Coding Practices

1. **Input Validation**: All external input is validated
2. **Safe File Operations**: Path traversal protection
3. **Secure Communications**: TLS for all API calls
4. **Credential Handling**: No credentials in logs or memory dumps

### Threat Model

- **Network Attacks**: TLS and authentication protect API communication
- **File System Attacks**: Restricted file operations and validation
- **Process Attacks**: Secure process management and cleanup

## Current Development Status

### Completed Features

- ✅ **Basic Agent Functionality**: Core task processing and API communication
- ✅ **Cross-Platform Support**: Linux, macOS, and Windows compatibility
- ✅ **Configuration Management**: Multi-source configuration with Viper
- ✅ **Hashcat Integration**: Process management and result parsing
- ✅ **Docker Support**: Containerized deployment with pre-built images
- ✅ **SDK Foundation**: Basic internal SDK structure implemented

### In Progress (Enhanced Task Monitoring)

- 🚧 **Idiomatic SDK**: Replacing external SDK with internal implementation
- 🚧 **Real-time Monitoring**: System metrics collection and threshold management
- 🚧 **Automatic Recovery**: Network failure and process crash recovery
- 🚧 **State Persistence**: Task state management and recovery on restart
- 🚧 **Enhanced Error Handling**: Structured error reporting with context

### Planned Features

- 📋 **Task History Analytics**: Performance tracking and trend analysis
- 📋 **Advanced Monitoring**: Per-device thresholds and custom rules
- 📋 **Configuration Reload**: Runtime configuration updates without restart
- 📋 **Language Migration Support**: Preparation for future language migration

## Contributing

### Getting Started

1. **Fork**: Fork the repository on GitHub
2. **Clone**: Clone your fork locally
3. **Setup**: Run `just install` to set up development environment
4. **Branch**: Create a feature branch
5. **Develop**: Make your changes following the guidelines
6. **Test**: Run `just ci-check` to verify changes
7. **Submit**: Create a pull request

### Code Review Process

1. **Automated Checks**: CI runs tests and linting
2. **Manual Review**: Maintainers review code and design
3. **Feedback**: Address review comments
4. **Merge**: Approved changes are merged

For more detailed contributing information, see [Contributing](contributing.md).

## Next Steps

- Review [Configuration](configuration.md) for setup options
- Check [Usage](usage.md) for operational guidance
- See [Contributing](contributing.md) to help improve the project
