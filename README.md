![GitHub](https://img.shields.io/github/license/unclesp1d3r/CipherSwarmAgent)
![GitHub issues](https://img.shields.io/github/issues/unclesp1d3r/CipherSwarmAgent)
![GitHub last commit](https://img.shields.io/github/last-commit/unclesp1d3r/CipherSwarmAgent)
![Maintenance](https://img.shields.io/maintenance/yes/2024)
[![Maintainability](https://api.codeclimate.com/v1/badges/9c76ebe483ef3b1eff8d/maintainability)](https://codeclimate.com/github/unclesp1d3r/CipherSwarmAgent/maintainability)
[![wakatime](https://wakatime.com/badge/github/unclesp1d3r/CipherSwarmAgent.svg)](https://wakatime.com/badge/github/unclesp1d3r/CipherSwarmAgent)
[![Go Report Card](https://goreportcard.com/badge/github.com/unclesp1d3r/cipherswarmagent)](https://goreportcard.com/report/github.com/unclesp1d3r/cipherswarmagent)

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
> This project is currently under active development and is not yet ready for production use. Please use it with
> caution. Do not trust anything until v1.0.0 is released, since the API may change at any time.

## Getting Started

Follow these instructions to set up and run the CipherSwarm Agent in your environment.

### Prerequisites

-   Go 1.22 or higher
-   Git (for cloning the repository)
-   Docker (optional, for running the agent in a container)
-   A [CipherSwarm](https://github.com/unclesp1d3r/CipherSwarm) server to connect to (e.g., a local or remote instance)

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

The easiest way to configure the agent is by passing the required parameters as environment variables. The following are the available configuration options:

-   API_TOKEN: The API token for the CipherSwarm server. This token is provided when the agent is added in the CipherSwarm server.
-   API_URL: The URL of the CipherSwarm server. This is the URL where the CipherSwarm server is running, e.g., <https://cipherswarm.example.com:3000>.

The agent will automatically create a configuration file in the same directory as the agent (`cipherswarmagent.yaml`) with the provided configuration options, along with default options that can be modified as needed.

### Running the Agent

To start the agent, simply run:

```bash
./cipherswarm-agent
```

This will activate the agent, connecting it to the CipherSwarm network to begin receiving and processing tasks.

### Docker

The easiest way to run the CipherSwarm Agent is by using Docker. To build the Docker image, run:

```bash
docker pull ghcr.io/unclesp1d3r/cipherswarmagent:latest

docker run -d -e API_TOKEN=your_api_token -e API_URL=https://cipherswarm.example.com:3000 unclesp1d3r/cipherswarm-agent
```

This will start the agent in a Docker container, connecting it to the CipherSwarm network, with hashcat and other dependencies pre-installed.

## Contributing

We welcome contributions! To contribute to the CipherSwarm Go Agent, please fork the repository, create a feature
branch, push your changes, and submit a pull request.

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

-   The CipherSwarm Team and community for their support and inspiration.
-   The creators and maintainers of the Cobra library and GoReleaser for their fantastic tools.
-   The developers and contributors to the [PhatCrack](https://github.com/lachlan2k/phatcrack) project, which gave us hints and ideas for this project.
