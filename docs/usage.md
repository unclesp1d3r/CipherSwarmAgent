# Usage

This guide covers the day-to-day operation of the CipherSwarm Agent, including starting, monitoring, and troubleshooting the agent.

## Basic Operations

### Starting the Agent

Once configured, start the agent with:

```bash
# Basic startup
./cipherswarm-agent

# With specific config file
./cipherswarm-agent --config /path/to/config.yaml

# With environment variables
API_TOKEN=your_token API_URL=https://server.com ./cipherswarm-agent

# With command line flags
./cipherswarm-agent --api_token your_token --api_url https://server.com:3000
```

### Stopping the Agent

The agent responds to standard interrupt signals:

```bash
# Graceful shutdown
Ctrl+C

# Or send SIGTERM
kill -TERM <pid>

# Force stop (not recommended)
kill -KILL <pid>
```

During graceful shutdown, the agent:

1. Notifies the server it's going offline
2. Completes current task processing (if safe to interrupt)
3. Cleans up temporary files
4. Removes lock files

### Command Line Interface

#### Available Commands and Flags

```bash
# Show help
./cipherswarm-agent --help

# Show version
./cipherswarm-agent --version

# Core configuration flags
./cipherswarm-agent \
  --api_token, -a <token>           # API authentication token
  --api_url, -u <url>              # CipherSwarm server URL
  --config <path>                  # Custom config file path
  --data_path, -p <path>           # Data storage directory

# Performance tuning flags
./cipherswarm-agent \
  --gpu_temp_threshold, -g <temp>  # GPU temperature limit (°C)
  --status_timer, -t <seconds>     # Status update interval
  --sleep_on_failure, -s <duration> # Retry delay after failures

# Hashcat integration flags
./cipherswarm-agent \
  --always_use_native_hashcat, -n # Force native Hashcat binary
  --files_path, -f <path>          # Attack files directory

# Debugging flags
./cipherswarm-agent \
  --debug, -d                      # Enable debug logging
  --extra_debugging, -e            # Very verbose debugging

# ZAP (shared cracking) flags
./cipherswarm-agent \
  --write_zaps_to_file, -w         # Write ZAPs to shared directory
  --zap_path, -z <path>            # ZAP files directory
  --retain_zaps_on_completion, -r  # Keep ZAP files after tasks
```

## Agent Lifecycle and States

### Agent States

The agent operates in several states:

- **Starting**: Initial startup and configuration loading
- **Authenticating**: Connecting to and authenticating with server
- **Benchmarking**: Running initial device benchmarks
- **Waiting**: Idle, checking for new tasks
- **Cracking**: Actively processing a hash-cracking task
- **Updating**: Downloading updated Hashcat binaries
- **Stopping**: Graceful shutdown in progress
- **Error**: Encountered a fatal error

### Task Lifecycle

1. **Task Discovery**: Agent polls server for available tasks
2. **Task Acceptance**: Agent accepts a task and downloads required files
3. **Task Execution**: Agent runs Hashcat with specified parameters
4. **Progress Reporting**: Agent sends periodic status updates
5. **Result Submission**: Agent reports cracked hashes as they're found
6. **Task Completion**: Agent marks task as complete or exhausted

## Monitoring and Observability

### Log Output

The agent produces structured logs with different levels:

```bash
# Example log output
INFO Using config file: cipherswarmagent.yaml
INFO CipherSwarm Agent starting up
INFO Authenticated with CipherSwarm API
INFO Sent agent metadata to server
INFO Agent is active and checking for tasks
INFO No new task available
INFO [Task 123] Accepted new task
INFO [Task 123] Starting attack: Dictionary
INFO [Task 123] Progress: 15.2% complete
INFO [Task 123] Found hash: 5d41402abc4b2a76b9719d911017c592:hello
INFO [Task 123] Task completed successfully
```

### Log Levels

- **DEBUG**: Detailed execution information (use `--debug` flag)
- **INFO**: General operational information
- **WARN**: Non-fatal issues that should be noted
- **ERROR**: Errors that affect operation but don't stop the agent
- **FATAL**: Critical errors that cause agent shutdown

### Monitoring File Structure

The agent creates several files for monitoring:

```text
data/
├── lock.pid              # Agent process ID
├── hashcat.pid           # Hashcat process ID (when running)
├── output/               # Task output files
├── hashlists/           # Downloaded hash lists
├── files/               # Attack files (wordlists, rules, masks)
├── zaps/                # Shared crack files (if enabled)
└── restore/             # Hashcat restore files
```

### Health Checks

Check agent health:

```bash
# Check if agent is running
ps aux | grep cipherswarm-agent

# Check lock file
cat data/lock.pid

# Check recent log output
tail -f /var/log/cipherswarm-agent.log  # if using systemd
```

## Development and Testing

### Development Commands (Just)

If you have the source code and `just` installed:

```bash
# Run agent in development mode
just dev

# Install dependencies and build
just install

# Run linting and checks
just check

# Run tests
just test

# Run full CI checks
just ci-check

# Serve documentation locally
just docs
```

### Manual Development Setup

```bash
# Clone and build
git clone https://github.com/unclesp1d3r/CipherSwarmAgent.git
cd CipherSwarmAgent
go mod tidy
go build -o cipherswarm-agent

# Run tests
go test ./...

# Run with debugging
go run main.go --debug --extra_debugging
```

## Common Workflows

### First-Time Setup

1. **Get API token** from your CipherSwarm server admin

2. **Install the agent** (see [Installation](installation.md))

3. **Configure basic settings**:

    ```bash
    export API_TOKEN="your_token"
    export API_URL="https://your-server.com:3000"
    ```

4. **Test connection**:

    ```bash
    ./cipherswarm-agent --debug
    ```

5. **Monitor initial benchmarking** (may take several minutes)

6. **Verify agent appears** in server's agent list

### Routine Operations

#### Checking Agent Status

```bash
# Quick status check
ps aux | grep cipherswarm-agent

# Detailed status from logs
tail -20 /var/log/cipherswarm-agent.log
```

#### Restarting Agent

```bash
# Graceful restart
pkill -TERM cipherswarm-agent
./cipherswarm-agent

# Or with systemd
sudo systemctl restart cipherswarm-agent
```

#### Updating Agent

```bash
# Stop current agent
pkill -TERM cipherswarm-agent

# Download new version
wget https://github.com/unclesp1d3r/CipherSwarmAgent/releases/latest/download/...

# Replace binary and restart
mv cipherswarm-agent cipherswarm-agent.old
chmod +x new-cipherswarm-agent
mv new-cipherswarm-agent cipherswarm-agent
./cipherswarm-agent
```

### Performance Tuning

#### GPU Temperature Management

```bash
# Conservative temperature limit
./cipherswarm-agent --gpu_temp_threshold 70

# Higher performance limit (ensure adequate cooling)
./cipherswarm-agent --gpu_temp_threshold 85
```

#### Status Update Frequency

```bash
# More frequent updates (higher server load)
./cipherswarm-agent --status_timer 1

# Less frequent updates (lower server load)
./cipherswarm-agent --status_timer 10
```

#### Memory and Storage Optimization

```bash
# Use shared storage for large files
./cipherswarm-agent \
  --files_path /mnt/shared/wordlists \
  --zap_path /mnt/shared/zaps \
  --write_zaps_to_file

# Clean up completed tasks aggressively
./cipherswarm-agent --retain_zaps_on_completion false
```

## Troubleshooting

### Common Issues and Solutions

#### Agent Won't Start

#### API Connection Failed

```bash
# Test API connectivity
curl -H "Authorization: Bearer your_token" https://your-server.com:3000/api/v1/client/configuration

# Check DNS resolution
nslookup your-server.com

# Check firewall/network
telnet your-server.com 3000
```

#### Permission Errors

```bash
# Fix binary permissions
chmod +x cipherswarm-agent

# Fix data directory permissions
mkdir -p data
chmod 750 data

# Fix config file permissions
chmod 600 cipherswarmagent.yaml
```

#### Lock File Issues

```bash
# Remove stale lock file
rm data/lock.pid

# Check for zombie processes
ps aux | grep cipherswarm-agent
pkill -9 cipherswarm-agent  # force kill if needed
```

#### Performance Issues

#### High CPU Usage

- Check if multiple agents are running: `ps aux | grep cipherswarm-agent`
- Monitor Hashcat process: `top -p $(cat data/hashcat.pid)`
- Adjust status update frequency: `--status_timer 5`

#### High Memory Usage

- Check for memory leaks in logs
- Restart agent periodically in production
- Limit concurrent file downloads

#### GPU Overheating

- Lower temperature threshold: `--gpu_temp_threshold 75`
- Improve system cooling
- Check GPU driver status

#### Task Failures

#### Download Failures

```bash
# Check network connectivity
ping your-server.com

# Verify API token permissions
curl -H "Authorization: Bearer your_token" https://your-server.com:3000/api/v1/client/tasks/new

# Check available disk space
df -h
```

#### Hashcat Errors

```bash
# Test Hashcat directly
hashcat --version
hashcat --benchmark

# Check for driver issues
nvidia-smi  # for NVIDIA GPUs
```

#### Task Timeout

- Check server-side task timeouts
- Monitor network stability
- Verify system resource availability

### Debugging Techniques

#### Enable Verbose Logging

```bash
./cipherswarm-agent --debug --extra_debugging 2>&1 | tee debug.log
```

#### Monitor System Resources

```bash
# Watch CPU/memory usage
htop

# Monitor GPU usage
watch -n 1 nvidia-smi

# Check disk I/O
iotop

# Monitor network
nethogs
```

#### Analyze Network Traffic

```bash
# Monitor API calls
sudo tcpdump -i any -A 'host your-server.com and port 3000'

# Check DNS resolution
dig your-server.com

# Test SSL/TLS
openssl s_client -connect your-server.com:3000
```

### Getting Help

If you're still experiencing issues:

1. **Check the logs** with debug mode enabled
2. **Search existing issues** on [GitHub](https://github.com/unclesp1d3r/CipherSwarmAgent/issues)
3. **Create a new issue** with:
    - Agent version (`--version`)
    - Operating system and architecture
    - Configuration (sanitized, no tokens)
    - Error logs
    - Steps to reproduce

## Production Deployment

### Systemd Service

Create a systemd service for production deployment:

```ini
# /etc/systemd/system/cipherswarm-agent.service
[Unit]
Description=CipherSwarm Agent
After=network.target

[Service]
Type=simple
User=cipherswarm
Group=cipherswarm
WorkingDirectory=/opt/cipherswarm
ExecStart=/opt/cipherswarm/cipherswarm-agent
Restart=always
RestartSec=10
Environment=API_TOKEN=your_token
Environment=API_URL=https://your-server.com:3000
Environment=DATA_PATH=/var/lib/cipherswarm

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable cipherswarm-agent
sudo systemctl start cipherswarm-agent

# Check status
sudo systemctl status cipherswarm-agent

# View logs
sudo journalctl -u cipherswarm-agent -f
```

### Docker Production Setup

See [Installation](installation.md) for Docker Compose configuration.

### Security Considerations

- Run agent as non-root user
- Use secure API tokens and rotate regularly
- Implement network segmentation
- Monitor and audit agent activity
- Keep agent software updated

## Next Steps

- Review [Configuration](configuration.md) for advanced configuration options
- Check [Project Structure](project_structure.md) for development information
- See [Contributing](contributing.md) to help improve the project
