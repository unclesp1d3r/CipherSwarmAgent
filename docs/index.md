# CipherSwarm Agent

The CipherSwarm Go Agent is a high-performance component of the CipherSwarm ecosystem. It is designed to efficiently manage and execute distributed hash-cracking tasks. Built with Go, this agent provides a robust solution for scaling and managing cryptographic computations across the CipherSwarm network.

> [!WARNING]
> This project is currently under active development and is not ready for production. Please use it with caution. Do not trust anything until v1.0.0 is released since the API may change at any time.

## Features

- **Command-Line Interface**: Utilizes the Cobra library for easy configuration and operation through command-line commands.
- **Enhanced Task Management**: Streamlines the distribution and execution of hash-cracking tasks with comprehensive monitoring and recovery capabilities.
- **Real-Time Monitoring**: System metrics collection (CPU, memory, GPU temperature, disk space) with configurable thresholds and automatic throttling.
- **Automatic Recovery**: Built-in recovery mechanisms for network failures, process crashes, and resource threshold violations with exponential backoff.
- **Task State Persistence**: Robust task state management with JSON-based persistence and automatic recovery on agent restart.
- **Scalable and High-Performance**: Optimized for performance and scalability, handling heavy computational tasks efficiently.
- **Secure Communication**: Ensures safe and reliable communication with the CipherSwarm server for task distribution and result submission.
- **Cross-Platform Support**: Native support for Linux, macOS, and Windows with platform-specific optimizations.
- **Docker Support**: Pre-built Docker images with Hashcat and dependencies included.
- **Flexible Configuration**: Environment variables, CLI flags, and YAML configuration file support with runtime reload capabilities.
- **Idiomatic SDK**: Internal SDK implementation providing better control over API interactions and enhanced error handling.

## Quick Start

### Prerequisites

- Go 1.24 or higher
- Git (for cloning the repository)
- Docker (optional for running the agent in a container)
- A [CipherSwarm](https://github.com/unclesp1d3r/CipherSwarm) server to connect to

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/unclesp1d3r/cipherswarm-agent.git
cd cipherswarm-agent
```

1. **Build the agent:**

```bash
just install
```

1. **Run the agent:**

```bash
export API_TOKEN=your_api_token
export API_URL=https://cipherswarm.example.com:3000
./cipherswarm-agent
```

### Docker Quick Start

```bash
docker pull ghcr.io/unclesp1d3r/cipherswarmagent:latest

docker run -e API_TOKEN=your_api_token \
           -e API_URL=https://cipherswarm.example.com:3000 \
           ghcr.io/unclesp1d3r/cipherswarmagent:latest
```

## Architecture Overview

The CipherSwarm Agent follows a modular, enhanced architecture with comprehensive monitoring and recovery capabilities:

- **CLI Interface** (`cmd/`): Command-line entrypoint using Cobra with enhanced configuration options
- **Core Logic** (`lib/`): Main agent functionality and utilities with enhanced task management
- **SDK Implementation** (`lib/sdk/`): Internal idiomatic SDK for CipherSwarm API interactions
- **Agent Management** (`lib/agent/`): Agent lifecycle management and coordination
- **Configuration** (`lib/config/`): Advanced configuration management with runtime reload
- **Hashcat Integration** (`lib/hashcat/`): Session management, parameter handling, and result parsing
- **OS Abstractions** (`lib/arch/`): Platform-specific device detection and binary handling
- **Monitoring** (`lib/progress/`): Real-time progress tracking and system monitoring
- **Error Handling** (`lib/cserrors/`): Structured error handling and reporting
- **File Management** (`lib/downloader/`, `lib/cracker/`): Secure file operations and hashcat binary management
- **ZAP Integration** (`lib/zap/`): Shared crack file management
- **Shared State** (`shared/`): Global configuration and logging with enhanced state management

## Getting Help

- Check the [Installation Guide](installation.md) for detailed setup instructions
- Review the [Configuration](configuration.md) documentation for all available options
- See [Usage](usage.md) for common operations and workflows
- Read the [Contributing](contributing.md) guide if you want to help improve the project

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](https://github.com/unclesp1d3r/CipherSwarmAgent/blob/main/LICENSE) file for details.

## Acknowledgments

- The CipherSwarm Team and community for their support and inspiration
- The creators and maintainers of the Cobra library and GoReleaser for their fantastic tools
- The developers and contributors to the [PhatCrack](https://github.com/lachlan2k/phatcrack) project for hints and ideas
