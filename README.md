![GitHub](https://img.shields.io/github/license/unclesp1d3r/CipherSwarmAgent)
![GitHub issues](https://img.shields.io/github/issues/unclesp1d3r/CipherSwarmAgent)
![GitHub Repo stars](https://img.shields.io/github/stars/unclesp1d3r/CipherSwarmAgent?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/unclesp1d3r/CipherSwarmAgent)
![Maintenance](https://img.shields.io/maintenance/yes/2024)
[![LoC](https://tokei.rs/b1/github/unclesp1d3r/CipherSwarmAgent?category=code)](https://github.com/unclesp1d3r/CipherSwarmAgent)
[![wakatime](https://wakatime.com/badge/github/unclesp1d3r/CipherSwarmAgent.svg)](https://wakatime.com/badge/github/unclesp1d3r/CipherSwarmAgent)

# CipherSwarm Agent

The CipherSwarm Go Agent is a high-performance component of the CipherSwarm ecosystem, designed to manage and execute
distributed hash cracking tasks efficiently. Built in Go, this agent provides a robust solution for scaling and managing
cryptographic computations across the CipherSwarm network.

## Features

-   **Command-Line Interface**: Utilizes the Cobra library for easy configuration and operation through command-line
    commands.
-   **Efficient Task Management**: Streamlines the distribution and execution of hash cracking tasks across distributed
    systems.
-   **Scalable and High-Performance**: Optimized for performance and scalability, handling heavy computational tasks with
    ease.
-   **Secure Communication**: Ensures secure and reliable communication with the CipherSwarm server for task distribution
    and result submission.

> [!CAUTION]
> This project is currently under active development and is not yet ready for production use. Please use it with caution. Do not trust anything until v1.0.0 is released, since the API may change at any time.

## Getting Started

Follow these instructions to set up and run the CipherSwarm Agent in your environment.

### Prerequisites

-   Go 1.22 or higher
-   Git (for cloning the repository)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/unclesp1d3r/cipherswarm-agent.git
cd cipherswarm-agent
```

1. Build the agent using Go:

```bash
go build -o cipherswarm-agent
```

### Configuration

Use the `init` command to set up the agent's configuration:

```bash
./cipherswarm-agent init
```

Follow the prompts to configure the agent, including setting up the server URL and agent credentials or settings.

### Running the Agent

To start the agent, simply run:

```bash
./cipherswarm-agent
```

This will activate the agent, connecting it to the CipherSwarm network to begin receiving and processing tasks.

## Contributing

We welcome contributions! To contribute to the CipherSwarm Go Agent, please fork the repository, create a feature
branch, push your changes, and submit a pull request.

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

-   The CipherSwarm Team and community for their support and inspiration.
-   The creators and maintainers of the Cobra library and GoReleaser for their fantastic tools.
