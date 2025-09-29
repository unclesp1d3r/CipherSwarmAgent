# CipherSwarmAgent Technical Guidelines

## Technology Stack

### Core Language
- **Go 1.22+** - Primary development language
- **Rationale**: Cross-platform compatibility, excellent concurrency, strong standard library

### Key Dependencies

#### CLI Framework
- **Cobra** - Command-line interface construction
- **Viper** - Configuration management
- **Usage**: Provides structured CLI with subcommands and flag handling

#### HTTP Client
- **Standard `net/http`** - HTTP client implementation
- **Custom SDK**: Built on standard library for API communication

#### Logging
- **Zap** - Structured, high-performance logging
- **Configuration**: Centralized in `lib/zap/` package

#### Testing
- **Standard `testing`** - Unit and integration tests
- **Testify** (if needed) - Assertion helpers and mocking

## Development Standards

### Code Quality

#### Formatting and Style
- Use `gofmt` for consistent formatting
- Follow standard Go naming conventions
- Use `golangci-lint` for comprehensive linting
- Maintain consistent import organization

#### Documentation
- Document all exported functions and types
- Use Go doc comments format
- Include usage examples for complex APIs
- Maintain up-to-date README and docs

#### Error Handling
- Use custom error types in `lib/cserrors/`
- Wrap errors with context using `fmt.Errorf`
- Implement structured error reporting to server
- Log errors with appropriate context

### API Integration

#### HTTP Client Standards
- Implement exponential backoff for retries
- Use context for request cancellation and timeouts
- Handle rate limiting and server errors gracefully
- Parse responses according to swagger schema

#### Authentication
- Support Bearer token authentication
- Implement token refresh if needed
- Secure token storage and handling

#### Request/Response Handling
- Use structured types for all API interactions
- Validate responses against expected schemas
- Handle partial failures and edge cases
- Implement proper content-type handling

### Hashcat Integration

#### Process Management
- Use `os/exec` for hashcat process control
- Implement proper process cleanup and signal handling
- Capture stdout/stderr for parsing
- Handle process failures and timeouts

#### Output Parsing
- Parse JSON status output when available
- Fall back to text parsing for older hashcat versions
- Implement real-time status extraction
- Handle malformed or incomplete output

#### Resource Management
- Manage temporary files and directories
- Clean up resources on task completion or failure
- Handle disk space and memory constraints
- Implement proper file locking if needed

## Configuration Management

### Configuration Sources (Priority Order)
1. Command-line flags
2. Environment variables
3. Configuration file
4. Server-provided configuration
5. Default values

### Configuration Structure
- Use structured configuration with validation
- Support nested configuration sections
- Implement configuration merging and overrides
- Provide clear error messages for invalid config

### File Formats
- **Primary**: YAML for human readability
- **Alternative**: JSON for programmatic generation
- Auto-generate default configuration on first run

## Testing Strategy

### Unit Testing
- Test all public functions and methods
- Use table-driven tests for multiple scenarios
- Mock external dependencies (API, filesystem, processes)
- Achieve high test coverage for critical paths

### Integration Testing
- Test API client against mock server
- Test hashcat integration with sample data
- Test configuration loading and validation
- Test error handling and recovery scenarios

### Test Organization
- Place tests alongside source code
- Use build tags for integration tests
- Implement test helpers for common setup
- Use golden files for complex output validation

## Performance Considerations

### Memory Management
- Avoid memory leaks in long-running processes
- Use streaming for large file operations
- Implement proper resource cleanup
- Monitor memory usage in production

### Concurrency
- Use goroutines for non-blocking operations
- Implement proper synchronization with channels/mutexes
- Handle context cancellation throughout the stack
- Avoid race conditions in shared state

### Network Efficiency
- Implement connection pooling for HTTP clients
- Use compression when appropriate
- Batch operations when possible
- Handle network timeouts gracefully

## Security Guidelines

### Input Validation
- Validate all external input (API responses, config files)
- Sanitize file paths and command arguments
- Implement bounds checking for numeric inputs
- Use allowlists for enumerated values

### Process Security
- Run with minimal required privileges
- Validate hashcat binary before execution
- Sanitize command-line arguments
- Implement secure temporary file handling

### Data Handling
- Protect sensitive configuration data
- Implement secure logging (avoid logging secrets)
- Handle authentication tokens securely
- Clean up sensitive data from memory

## Build and Deployment

### Build Configuration
- Use Go modules for dependency management
- Support cross-compilation for target platforms
- Implement version embedding in binaries
- Use build tags for platform-specific code

### CI/CD Integration
- Automated testing on multiple platforms
- Linting and code quality checks
- Security scanning of dependencies
- Automated release builds

### Deployment Patterns
- Support standalone binary deployment
- Provide Docker container images
- Include systemd service files for Linux
- Support Windows service installation

## Monitoring and Observability

### Logging Standards
- Use structured logging with consistent fields
- Include correlation IDs for request tracking
- Log at appropriate levels (debug, info, warn, error)
- Implement log rotation and retention

### Metrics Collection
- Track key performance indicators
- Monitor resource utilization
- Collect task execution statistics
- Implement health check endpoints

### Error Reporting
- Report structured errors to server
- Include relevant context and stack traces
- Implement error categorization
- Provide actionable error messages

## Future Technical Considerations

### Extensibility
- Design plugin interfaces for new functionality
- Support configuration-driven behavior
- Implement event-driven architecture patterns
- Plan for API versioning and compatibility

### Scalability
- Design for horizontal scaling
- Implement efficient resource utilization
- Support load balancing and failover
- Plan for distributed coordination if needed

### Maintenance
- Implement auto-update mechanisms
- Support configuration migration
- Provide diagnostic and troubleshooting tools
- Plan for backward compatibility requirements
