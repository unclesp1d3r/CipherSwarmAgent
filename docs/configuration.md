# Configuration

The CipherSwarm Agent supports multiple configuration methods with a clear precedence order. This guide covers all available configuration options and how to use them effectively.

## Configuration Precedence

Configuration values are applied in the following order (highest to lowest priority):

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Default values** (lowest priority)

## Required Configuration

The agent requires two essential configuration values to operate:

### API Token

Your unique agent authentication token from the CipherSwarm server.

### API URL

The base URL of your CipherSwarm server's API endpoint.

## Configuration Methods

### Method 1: Command-Line Flags

All configuration options can be set via command-line flags:

```bash
./cipherswarm-agent \
  --api_token "your_api_token" \
  --api_url "https://your-server.com:3000" \
  --data_path "/opt/cipherswarm/data" \
  --gpu_temp_threshold 85 \
  --extra_debugging
```

### Method 2: Environment Variables

Set configuration via environment variables (uppercase with underscores):

```bash
export API_TOKEN="your_api_token"
export API_URL="https://your-server.com:3000"
export DATA_PATH="/opt/cipherswarm/data"
export GPU_TEMP_THRESHOLD=85
export EXTRA_DEBUGGING=true

./cipherswarm-agent
```

### Method 3: Configuration File

The agent automatically creates a `cipherswarmagent.yaml` file on first run:

```yaml
# cipherswarmagent.yaml
api_token: your_api_token
api_url: https://your-server.com:3000
data_path: /opt/cipherswarm/data
gpu_temp_threshold: 85
always_use_native_hashcat: false
sleep_on_failure: 60s
files_path: /opt/cipherswarm/data/files
extra_debugging: false
status_timer: 10
heartbeat_interval: 10s  # Note: Server overrides this via agent_update_interval
write_zaps_to_file: false
zap_path: /opt/cipherswarm/data/zaps
retain_zaps_on_completion: false
enable_additional_hash_types: true
use_legacy_device_technique: false
```

You can specify a custom config file location:

```bash
./cipherswarm-agent --config /path/to/custom-config.yaml
```

## Configuration Options Reference

### Core Settings

#### `api_token` / `API_TOKEN`

- **Flag**: `--api_token`, `-a`
- **Type**: String
- **Required**: Yes
- **Description**: API token for authenticating with the CipherSwarm server
- **Example**: `csa_1234_abcdef...`

#### `api_url` / `API_URL`

- **Flag**: `--api_url`, `-u`
- **Type**: String
- **Required**: Yes
- **Description**: Base URL of the CipherSwarm server API
- **Example**: `https://cipherswarm.example.com:3000`

#### `data_path` / `DATA_PATH`

- **Flag**: `--data_path`, `-p`
- **Type**: String
- **Default**: `./data`
- **Description**: Directory where the agent stores runtime data
- **Example**: `/opt/cipherswarm/data`

### Performance Settings

#### `gpu_temp_threshold` / `GPU_TEMP_THRESHOLD`

- **Flag**: `--gpu_temp_threshold`, `-g`
- **Type**: Integer
- **Default**: `80`
- **Description**: GPU temperature threshold in Celsius. Agent pauses tasks if exceeded
- **Range**: 60-100

#### `status_timer` / `STATUS_TIMER`

- **Flag**: `--status_timer`, `-t`
- **Type**: Integer
- **Default**: `10`
- **Description**: Interval in seconds for sending status updates to server
- **Range**: 1-60

#### `heartbeat_interval` / `HEARTBEAT_INTERVAL`

- **Flag**: `--heartbeat_interval`
- **Type**: Duration
- **Default**: `10s` (fallback only - server provides actual value via `agent_update_interval`)
- **Description**: Interval between heartbeat messages to the server. **Note**: This value is automatically set by the server via the `agent_update_interval` configuration field and should not normally be overridden.
- **Examples**: `15s`, `1m`, `90s`

#### `sleep_on_failure` / `SLEEP_ON_FAILURE`

- **Flag**: `--sleep_on_failure`, `-s`
- **Type**: Duration
- **Default**: `60s`
- **Description**: How long to wait after a task failure before retrying
- **Examples**: `30s`, `2m`, `1m30s`

### Hashcat Integration

#### `always_use_native_hashcat` / `ALWAYS_USE_NATIVE_HASHCAT`

- **Flag**: `--always_use_native_hashcat`, `-n`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Force using system's native Hashcat instead of server-provided binaries

#### `files_path` / `FILES_PATH`

- **Flag**: `--files_path`, `-f`
- **Type**: String
- **Default**: `{data_path}/files`
- **Description**: Directory for storing attack files (wordlists, rules, masks)

### Debugging and Logging

#### `debug` / `DEBUG`

- **Flag**: `--debug`, `-d`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable debug mode with verbose logging

#### `extra_debugging` / `EXTRA_DEBUGGING`

- **Flag**: `--extra_debugging`, `-e`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable additional debugging information (very verbose)

### ZAP (Zero Application Performance) Integration

#### `write_zaps_to_file` / `WRITE_ZAPS_TO_FILE`

- **Flag**: `--write_zaps_to_file`, `-w`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Write ZAP output to files for sharing with other agents

#### `zap_path` / `ZAP_PATH`

- **Flag**: `--zap_path`, `-z`
- **Type**: String
- **Default**: `{data_path}/zaps`
- **Description**: Directory for storing ZAP output files

#### `retain_zaps_on_completion` / `RETAIN_ZAPS_ON_COMPLETION`

- **Flag**: `--retain_zaps_on_completion`, `-r`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Keep ZAP files after task completion instead of deleting them

### Advanced Settings

#### `enable_additional_hash_types` / `ENABLE_ADDITIONAL_HASH_TYPES`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable support for additional hash types during benchmarking

#### `use_legacy_device_technique` / `USE_LEGACY_DEVICE_TECHNIQUE`

- **Type**: Boolean
- **Default**: `false`
- **Description**: Use legacy method for device identification (not recommended)

#### `always_trust_files` / `ALWAYS_TRUST_FILES`

- **Type**: Boolean
- **Default**: `false`
- **Description**: Skip checksum verification for downloaded files (not recommended)

## Configuration Examples

### Basic Home Lab Setup

```yaml
# cipherswarmagent.yaml
api_token: csa_agent001_xyz789
api_url: http://192.168.1.100:3000
data_path: ./agent-data
gpu_temp_threshold: 75
status_timer: 10
```

### High-Performance Production Setup

```yaml
# cipherswarmagent.yaml
api_token: csa_prod_agent_abc123
api_url: https://cipherswarm-prod.company.com
data_path: /var/lib/cipherswarm
files_path: /mnt/shared/cipherswarm-files
gpu_temp_threshold: 85
status_timer: 1
always_use_native_hashcat: true
write_zaps_to_file: true
zap_path: /mnt/shared/zaps
retain_zaps_on_completion: true
```

### Development/Debug Setup

```yaml
# cipherswarmagent.yaml
api_token: csa_dev_token
api_url: http://localhost:3000
data_path: ./dev-data
debug: true
extra_debugging: true
sleep_on_failure: 10s
status_timer: 1
```

### Docker Environment Variables

```bash
# docker-compose.yml environment section
environment:
  - API_TOKEN=csa_docker_agent_123
  - API_URL=https://cipherswarm.example.com
  - DATA_PATH=/data
  - FILES_PATH=/data/files
  - GPU_TEMP_THRESHOLD=80
  - ALWAYS_USE_NATIVE_HASHCAT=true
  - EXTRA_DEBUGGING=false
```

## Configuration Validation

The agent validates configuration on startup:

```bash
# Test configuration without running
./cipherswarm-agent --help

# Check current configuration
./cipherswarm-agent --version
```

Common validation errors:

- **Missing API token**: Set `api_token` or `API_TOKEN`
- **Invalid API URL**: Ensure URL includes protocol (`http://` or `https://`)
- **Path permissions**: Ensure agent can read/write to configured paths
- **Invalid temperature**: GPU threshold must be between 60-100°C

## Security Considerations

### Protecting API Tokens

- Never commit API tokens to version control
- Use environment variables or secure file permissions (600) for config files
- Rotate tokens regularly
- Use different tokens for different environments

### File Permissions

```bash
# Secure configuration file
chmod 600 cipherswarmagent.yaml

# Secure data directory
chmod 750 /var/lib/cipherswarm
```

### Network Security

- Use HTTPS for `api_url` in production
- Consider VPN or private networks for agent-server communication
- Implement firewall rules to restrict agent network access

## Troubleshooting Configuration

### Common Issues

1. **Configuration not applied**:

    - Check precedence order (CLI flags override env vars)
    - Verify correct variable names (case-sensitive)

2. **File permission errors**:

    - Ensure agent has write access to `data_path`
    - Check parent directory permissions

3. **API connection failures**:

    - Verify API URL format and accessibility
    - Test network connectivity: `curl https://your-server.com:3000/health`

### Debug Configuration Loading

Enable debug mode to see configuration loading:

```bash
./cipherswarm-agent --debug --extra_debugging
```

This shows:

- Which config file is loaded
- Environment variables detected
- Final configuration values
- Validation results

## Configuration Management

### Multiple Environments

Use different config files for different environments:

```bash
# Development
./cipherswarm-agent --config config-dev.yaml

# Staging
./cipherswarm-agent --config config-staging.yaml

# Production
./cipherswarm-agent --config config-prod.yaml
```

### Configuration Templates

Create template configurations for easy deployment:

```yaml
# config-template.yaml
api_token: ${API_TOKEN}
api_url: ${API_URL}
data_path: ${DATA_PATH:-./data}
gpu_temp_threshold: ${GPU_TEMP_THRESHOLD:-80}
```

Use with environment variable substitution tools like `envsubst`.

## Next Steps

- Review [Usage](usage.md) for operational guidance
- Check [Installation](installation.md) for setup instructions
- See [Project Structure](project_structure.md) for development information
