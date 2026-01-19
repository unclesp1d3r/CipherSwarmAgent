# Installation

This guide covers multiple ways to install and run the CipherSwarm Agent.

## Prerequisites

Before installing the CipherSwarm Agent, ensure you have:

- **CipherSwarm Server**: A running [CipherSwarm](https://github.com/unclesp1d3r/CipherSwarm) server instance
- **API Token**: An agent API token from your CipherSwarm server
- **Hashcat** (optional): For native installation; included in Docker images

### System Requirements

- **Supported OS**: Linux, macOS, Windows
- **Architecture**: x86_64 (amd64), ARM64
- **Memory**: Minimum 512MB RAM
- **Storage**: At least 1GB free space for task files and results

## Installation Methods

### Method 1: Pre-built Binaries (Recommended)

Download the latest release for your platform:

#### Linux x86_64

```bash
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/CipherSwarmAgent_Linux_x86_64.tar.gz
tar -xzf CipherSwarmAgent_Linux_x86_64.tar.gz
chmod +x cipherswarm-agent
```

#### macOS (Intel)

```bash
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/CipherSwarmAgent_Darwin_x86_64.tar.gz
tar -xzf CipherSwarmAgent_Darwin_x86_64.tar.gz
chmod +x cipherswarm-agent
```

#### macOS (Apple Silicon)

```bash
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/CipherSwarmAgent_Darwin_arm64.tar.gz
tar -xzf CipherSwarmAgent_Darwin_arm64.tar.gz
chmod +x cipherswarm-agent
```

#### Windows x86_64

Windows is not well supported at this time, but efforts are being made to improve it.

```powershell
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/CipherSwarmAgent_Windows_x86_64.zip -OutFile CipherSwarmAgent_Windows_x86_64.zip
Expand-Archive -Path CipherSwarmAgent_Windows_x86_64.zip -DestinationPath .
cipherswarm-agent.exe
```

### Method 2: From Source

Requirements for building from source:

- **Go 1.22 or higher**
- **Git**
- **Just** command runner (optional but recommended)
- **Bun** (for JavaScript tooling like commitlint/pre-commit hooks)

```bash
# Clone the repository
git clone https://github.com/unclesp1d3r/CipherSwarmAgent.git
cd CipherSwarmAgent

# Install dependencies and build (using just)
just install

# Or build manually
go mod tidy
go build -o cipherswarm-agent
```

### Method 3: Docker (Easiest)

The Docker method includes Hashcat and all dependencies pre-installed:

```bash
# Pull the latest image
docker pull ghcr.io/unclesp1d3r/cipherswarmagent:latest

# Run with environment variables
docker run -d \
  --name cipherswarm-agent \
  -e API_TOKEN=your_api_token \
  -e API_URL=https://your-server.com:3000 \
  ghcr.io/unclesp1d3r/cipherswarmagent:latest
```

Available Docker tags:

- `latest`: Latest stable release
- `pocl`: POCL (Portable Computing Language) variant for CPU-only systems
- `v0.5.x`: Specific version tags
- `v0.5.x-pocl`: Version-specific POCL variants

### Method 4: Package Managers

#### Linux Package Managers

```bash
# Debian/Ubuntu (.deb)
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/cipherswarm-agent_x.x.x_linux_amd64.deb
sudo dpkg -i cipherswarm-agent_x.x.x_linux_amd64.deb

# Red Hat/CentOS (.rpm)
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/cipherswarm-agent_x.x.x_linux_amd64.rpm
sudo rpm -i cipherswarm-agent_x.x.x_linux_amd64.rpm

# Arch Linux
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/cipherswarm-agent_x.x.x_linux_amd64.pkg.tar.xz
sudo pacman -U cipherswarm-agent_x.x.x_linux_amd64.pkg.tar.xz
```

## Post-Installation Setup

### 1. Verify Installation

```bash
# Check version
./cipherswarm-agent --version

# View help
./cipherswarm-agent --help
```

### 2. Set Required Configuration

The agent requires two essential configuration values:

```bash
# Set via environment variables
export API_TOKEN=your_api_token
export API_URL=https://your-cipherswarm-server.com:3000

# Or via command line flags
./cipherswarm-agent --api_token your_api_token --api_url https://your-server.com:3000
```

### 3. Create Configuration File (Optional)

On first run, the agent creates a configuration file at `cipherswarmagent.yaml`:

```bash
# Run once to generate config file
./cipherswarm-agent

# Edit the generated configuration
nano cipherswarmagent.yaml
```

### 4. Install Hashcat (For Native Installation)

If not using Docker, install Hashcat:

#### Linux

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install hashcat

# Red Hat/CentOS
sudo dnf install hashcat

# Arch Linux
sudo pacman -S hashcat
```

#### macOS

```bash
# Using Homebrew
brew install hashcat
```

#### Windows

Download from [hashcat.net](https://hashcat.net/hashcat/) and add to PATH.

## Docker Compose Setup

For production deployments, use Docker Compose:

```yaml
# docker-compose.yml
version: '3.8'

services:
  cipherswarm-agent:
    image: ghcr.io/unclesp1d3r/cipherswarmagent:latest
    container_name: cipherswarm-agent
    restart: unless-stopped
    environment:
      - API_TOKEN=your_api_token
      - API_URL=https://your-server.com:3000
      - DATA_PATH=/data
      - GPU_TEMP_THRESHOLD=80
    volumes:
      - ./data:/data
      - ./config:/config
    # Uncomment for GPU access
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: all
    #           capabilities: [gpu]
```

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f cipherswarm-agent
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Ensure the binary is executable (`chmod +x cipherswarm-agent`)

2. **API connection failed**: Verify the API URL and token are correct

3. **Hashcat not found**: Install Hashcat or use the Docker version

4. **GPU not detected**: Check GPU drivers and ensure container has GPU access

### Getting Help

- Check the [Configuration](configuration.md) guide for detailed setup options
- Review [Usage](usage.md) for operational guidance
- Open an issue on [GitHub](https://github.com/unclesp1d3r/CipherSwarmAgent/issues) for bugs or feature requests

## Next Steps

After installation, proceed to:

1. [Configuration](configuration.md) - Configure the agent for your environment
2. [Usage](usage.md) - Learn how to operate the agent
3. [Project Structure](project_structure.md) - Understand the codebase (for developers)
