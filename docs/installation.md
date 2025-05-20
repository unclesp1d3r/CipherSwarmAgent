# Installation

## Prerequisites

-   Go 1.22 or higher
-   Git
-   Docker (optional)
-   Access to a CipherSwarm server (local or remote)

## Clone the Repository

```bash
git clone https://github.com/unclesp1d3r/cipherswarm-agent.git
cd cipherswarm-agent
```

## Build the Agent

```bash
go build -o cipherswarm-agent
```

## Docker Usage

You can run the agent in a container:

```bash
docker pull ghcr.io/unclesp1d3r/cipherswarmagent:latest

docker run -e API_TOKEN=your_api_token -e API_URL=https://cipherswarm.example.com:3000 ghcr.io/unclesp1d3r/cipherswarmagent:latest
```
