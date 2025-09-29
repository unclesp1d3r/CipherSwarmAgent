# CipherSwarmAgent Project Structure Guidelines

## Architecture Overview

CipherSwarmAgent follows a modular, layered architecture designed for maintainability, testability, and cross-platform compatibility.

## Directory Structure

### Root Level

- `main.go` - Application entrypoint, delegates to cmd package
- `go.mod/go.sum` - Go module definition and dependencies
- `Dockerfile` - Container build configuration
- `justfile` - Task automation and build commands

### Core Directories

#### `cmd/`

- **Purpose**: CLI interface and command registration
- **Technology**: Cobra CLI framework
- **Key Files**:
  - `root.go` - Main command setup and configuration
- **Guidelines**: Keep CLI logic thin, delegate to lib packages

#### `lib/`

- **Purpose**: Core business logic and utilities
- **Structure**: Organized by functional domain
- **Key Components**:
  - `agentClient.go` - Main agent orchestration and server communication
  - `benchmarkManager.go` - Benchmark collection and management
  - `dataTypes.go` - Core data structures and types
  - `constants.go` - Application constants
  - `outputs.go` - Output formatting and display
  - `runners.go` - Task execution coordination
  - `taskManager.go` - Task lifecycle management
  - `testManager.go` - Testing utilities and helpers

#### `lib/` Subdirectories

##### `lib/agent/`

- Agent-specific logic and state management
- Agent registration and lifecycle

##### `lib/arch/`

- OS-specific abstractions and implementations
- Device detection and binary handling
- Platform compatibility layer

##### `lib/config/`

- Configuration management and parsing
- Environment variable and CLI flag handling
- Configuration file operations

##### `lib/hashcat/`

- Hashcat integration and session management
- Parameter construction and validation
- Output parsing and result extraction

##### `lib/sdk/`

- API client implementation
- HTTP communication and serialization
- Request/response handling

##### `lib/progress/`

- Progress tracking and reporting
- Status update management

##### `lib/downloader/`

- File download and resource management
- Hash list and wordlist handling

##### `lib/cracker/`

- Cracking task coordination
- Result processing and deduplication

##### `lib/cserrors/`

- Custom error types and handling
- Error reporting and classification

##### `lib/zap/`

- Logging configuration and utilities
- Structured logging setup

#### `shared/`

- **Purpose**: Global state and shared utilities
- **Key Files**: `shared.go` - Application-wide state and configuration

#### `docs/`

- **Purpose**: Documentation and specifications
- **Key Files**:
  - API documentation and swagger specifications
  - Implementation plans and design documents
  - Usage and configuration guides

## Code Organization Principles

### Separation of Concerns

- **CLI Layer**: Command parsing and user interaction
- **Business Logic**: Core agent functionality and task management
- **Integration Layer**: External service communication (API, hashcat)
- **Platform Layer**: OS-specific implementations

### Dependency Management

- Use dependency injection where possible
- Minimize coupling between packages
- Abstract external dependencies behind interfaces

### Error Handling

- Use custom error types in `lib/cserrors/`
- Implement structured error reporting
- Provide context-rich error messages

### Testing Structure

- Unit tests alongside source files (`*_test.go`)
- Integration tests in separate test packages
- Mock implementations for external dependencies

## Module Guidelines

### New Package Creation

- Create packages based on functional domains, not technical layers
- Each package should have a clear, single responsibility
- Avoid circular dependencies between lib packages

### Interface Design

- Define interfaces in consuming packages, not implementing packages
- Keep interfaces small and focused
- Use interfaces to enable testing and modularity

### Configuration Handling

- Centralize configuration in `lib/config/`
- Support multiple configuration sources (file, env, CLI)
- Validate configuration at startup

### Logging Standards

- Use structured logging via `lib/zap/`
- Include relevant context in log messages
- Use appropriate log levels (debug, info, warn, error)

## File Naming Conventions

### Go Files

- Use descriptive names that indicate purpose
- Group related functionality in single files when appropriate
- Separate test files with `_test.go` suffix

### Configuration Files

- Use lowercase with hyphens for multi-word names
- Include file extension that indicates format (`.yml`, `.json`)

### Documentation Files

- Use uppercase for root-level documentation (`README.md`)
- Use lowercase for package-level documentation

## Import Organization

### Import Groups (in order)

1. Standard library imports
2. Third-party imports
3. Local project imports

### Import Aliases

- Use meaningful aliases for commonly used packages
- Avoid single-letter aliases except for well-known cases
- Be consistent across the codebase

## Future Structure Considerations

### Extensibility

- Design for plugin architecture support
- Consider interface-based extension points
- Plan for configuration-driven behavior

### Scalability

- Structure for potential microservice decomposition
- Design for horizontal scaling patterns
- Consider event-driven architecture elements
