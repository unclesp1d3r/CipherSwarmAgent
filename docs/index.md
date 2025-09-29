# CipherSwarm Agent

The CipherSwarm Go Agent is a high-performance component of the CipherSwarm ecosystem. It is designed to efficiently manage and execute distributed hash-cracking tasks. Built with Go, this agent provides a robust solution for scaling and managing cryptographic computations across the CipherSwarm network.

> [!WARNING]
> This project is currently under active development and is not ready for production. Please use it with caution. Do not trust anything until v1.0.0 is released since the API may change at any time.

## Features

- **Command-Line Interface**: Utilizes the Cobra library for easy configuration and operation through command-line commands.
- **Efficient Task Management**: Streamlines the distribution and execution of hash-cracking tasks across distributed systems.
- **Scalable and High-Performance**: Optimized for performance and scalability, handling heavy computational tasks efficiently.
- **Secure Communication**: Ensures safe and reliable communication with the CipherSwarm server for task distribution and result submission.
- **Cross-Platform Support**: Designed for Linux, macOS, and Windows operation.
- **Docker Support**: Pre-built Docker images with Hashcat and dependencies included.
- **Flexible Configuration**: Environment variables, CLI flags, and YAML configuration file support.

## Quick Start

### Prerequisites

- Go 1.22 or higher
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

The CipherSwarm Agent follows a modular architecture:

- **CLI Interface** (`cmd/`): Command-line entrypoint using Cobra
- **Core Logic** (`lib/`): Main agent functionality and utilities
- **Hashcat Integration** (`lib/hashcat/`): Session management and result parsing
- **OS Abstractions** (`lib/arch/`): Platform-specific device detection and binary handling
- **Utilities** (`lib/utils/`): Reusable components like progress tracking
- **Shared State** (`shared/`): Global configuration and logging

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
