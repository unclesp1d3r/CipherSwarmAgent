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
  --api-token "your_api_token" \
  --api-url "https://your-server.com:3000" \
  --data-path "/opt/cipherswarm/data" \
  --gpu-temp-threshold 85 \
  --extra-debugging
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
hashcat_path: ''  # Leave empty for auto-detection

# Fault tolerance settings
task_timeout: 24h
download_max_retries: 3
download_retry_delay: 2s
insecure_downloads: false
max_heartbeat_backoff: 6

# HTTP resilience settings (server can override via /configuration endpoint)
connect_timeout: 10s
read_timeout: 30s
write_timeout: 10s
request_timeout: 60s
api_max_retries: 3
api_retry_initial_delay: 1s
api_retry_max_delay: 30s
circuit_breaker_failure_threshold: 5
circuit_breaker_timeout: 60s
```

You can specify a custom config file location:

```bash
./cipherswarm-agent --config /path/to/custom-config.yaml
```

## Configuration Options Reference

**Note on CLI Flag Compatibility**: All CLI flags have been updated to use kebab-case style (e.g., `--api-token`, `--data-path`) following POSIX/GNU conventions. For backward compatibility, the original underscore-style flags (e.g., `--api_token`, `--data_path`) remain functional as deprecated aliases but will display a deprecation warning.

### Core Settings

#### `api_token` / `API_TOKEN`

- **Flag**: `--api-token`, `-a`
- **Type**: String
- **Required**: Yes
- **Description**: API token for authenticating with the CipherSwarm server
- **Example**: `csa_1234_abcdef...`
- **Note**: Deprecated alias `--api_token` remains functional for backward compatibility

#### `api_url` / `API_URL`

- **Flag**: `--api-url`, `-u`
- **Type**: String
- **Required**: Yes
- **Description**: Base URL of the CipherSwarm server API
- **Example**: `https://cipherswarm.example.com:3000`
- **Note**: Deprecated alias `--api_url` remains functional for backward compatibility

#### `data_path` / `DATA_PATH`

- **Flag**: `--data-path`, `-p`
- **Type**: String
- **Default**: `./data`
- **Description**: Directory where the agent stores runtime data
- **Example**: `/opt/cipherswarm/data`
- **Note**: Deprecated alias `--data_path` remains functional for backward compatibility

### Performance Settings

#### `gpu_temp_threshold` / `GPU_TEMP_THRESHOLD`

- **Flag**: `--gpu-temp-threshold`, `-g`
- **Type**: Integer
- **Default**: `80`
- **Description**: GPU temperature threshold in Celsius. Agent pauses tasks if exceeded
- **Range**: 60-100
- **Note**: Deprecated alias `--gpu_temp_threshold` remains functional for backward compatibility

#### `status_timer` / `STATUS_TIMER`

- **Flag**: `--status-timer`, `-t`
- **Type**: Integer
- **Default**: `10`
- **Description**: Interval in seconds for sending status updates to server
- **Range**: 1-60
- **Note**: Deprecated alias `--status_timer` remains functional for backward compatibility

#### `heartbeat_interval` / `HEARTBEAT_INTERVAL`

- **Flag**: `--heartbeat-interval`
- **Type**: Duration
- **Default**: `10s` (fallback only - server provides actual value via `agent_update_interval`)
- **Description**: Interval between heartbeat messages to the server. **Note**: This value is automatically set by the server via the `agent_update_interval` configuration field and should not normally be overridden.
- **Examples**: `15s`, `1m`, `90s`
- **Note**: Deprecated alias `--heartbeat_interval` remains functional for backward compatibility

#### `sleep_on_failure` / `SLEEP_ON_FAILURE`

- **Flag**: `--sleep-on-failure`, `-s`
- **Type**: Duration
- **Default**: `60s`
- **Description**: How long to wait after a task failure before retrying
- **Examples**: `30s`, `2m`, `1m30s`
- **Note**: Deprecated alias `--sleep_on_failure` remains functional for backward compatibility

### Hashcat Integration

#### `always_use_native_hashcat` / `ALWAYS_USE_NATIVE_HASHCAT`

- **Flag**: `--always-use-native-hashcat`, `-n`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Force using system's native Hashcat instead of server-provided binaries
- **Note**: Deprecated alias `--always_use_native_hashcat` remains functional for backward compatibility

#### `files_path` / `FILES_PATH`

- **Flag**: `--files-path`, `-f`
- **Type**: String
- **Default**: `{data_path}/files`
- **Description**: Directory for storing attack files (wordlists, rules, masks)
- **Note**: Deprecated alias `--files_path` remains functional for backward compatibility

#### `hashcat_path` / `HASHCAT_PATH`

- **Flag**: `--hashcat-path`
- **Type**: String
- **Default**: `""` (empty — auto-detect)
- **Description**: Path to a custom Hashcat binary. When set, overrides automatic detection from `crackers_path` and system PATH. Useful when multiple Hashcat versions are installed or the binary is in a non-standard location.
- **Example**: `/usr/local/bin/hashcat` or `C:\hashcat\hashcat.exe`

### Debugging and Logging

#### `debug` / `DEBUG`

- **Flag**: `--debug`, `-d`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable debug mode with verbose logging

#### `extra_debugging` / `EXTRA_DEBUGGING`

- **Flag**: `--extra-debugging`, `-e`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable additional debugging information (very verbose)
- **Note**: Deprecated alias `--extra_debugging` remains functional for backward compatibility

### ZAP (Zero Application Performance) Integration

#### `write_zaps_to_file` / `WRITE_ZAPS_TO_FILE`

- **Flag**: `--write-zaps-to-file`, `-w`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Write ZAP output to files for sharing with other agents
- **Note**: Deprecated alias `--write_zaps_to_file` remains functional for backward compatibility

#### `zap_path` / `ZAP_PATH`

- **Flag**: `--zap-path`, `-z`
- **Type**: String
- **Default**: `{data_path}/zaps`
- **Description**: Directory for storing ZAP output files
- **Note**: Deprecated alias `--zap_path` remains functional for backward compatibility

#### `retain_zaps_on_completion` / `RETAIN_ZAPS_ON_COMPLETION`

- **Flag**: `--retain-zaps-on-completion`, `-r`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Keep ZAP files after task completion instead of deleting them
- **Note**: Deprecated alias `--retain_zaps_on_completion` remains functional for backward compatibility

### Fault Tolerance Settings

These settings control retry behavior, timeouts, and circuit breakers for improved resilience.

#### `task_timeout` / `TASK_TIMEOUT`

- **Flag**: `--task-timeout`
- **Type**: Duration
- **Default**: `24h`
- **Description**: Maximum time allowed for a single task before it's forcefully terminated. Long-running tasks are expected, so this is set high by default.
- **Examples**: `12h`, `48h`, `6h30m`
- **Note**: Deprecated alias `--task_timeout` remains functional for backward compatibility

#### `download_max_retries` / `DOWNLOAD_MAX_RETRIES`

- **Flag**: `--download-max-retries`
- **Type**: Integer
- **Default**: `3`
- **Description**: Maximum number of retry attempts for file downloads (wordlists, rules, etc.) when transient errors occur.
- **Range**: 1-10
- **Note**: Deprecated alias `--download_max_retries` remains functional for backward compatibility

#### `download_retry_delay` / `DOWNLOAD_RETRY_DELAY`

- **Flag**: `--download-retry-delay`
- **Type**: Duration
- **Default**: `2s`
- **Description**: Base delay between download retry attempts. Uses exponential backoff (2s, 4s, 8s, etc.).
- **Examples**: `1s`, `5s`, `500ms`
- **Note**: Deprecated alias `--download_retry_delay` remains functional for backward compatibility

#### `insecure_downloads` / `INSECURE_DOWNLOADS`

- **Flag**: `--insecure-downloads`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Skip TLS certificate verification for file downloads. **Warning**: Only use in trusted networks or development environments.
- **Note**: Deprecated alias `--insecure_downloads` remains functional for backward compatibility

#### `max_heartbeat_backoff` / `MAX_HEARTBEAT_BACKOFF`

- **Flag**: `--max-heartbeat-backoff`
- **Type**: Integer
- **Default**: `6`
- **Description**: Maximum multiplier for heartbeat backoff on consecutive failures. With default value of 6, the backoff caps at 64x the normal interval (2^6). The agent uses exponential backoff when heartbeats fail, automatically recovering when connectivity is restored.
- **Range**: 1-10
- **Note**: Deprecated alias `--max_heartbeat_backoff` remains functional for backward compatibility

### HTTP Resilience Settings

These settings control HTTP transport behavior including connection timeouts, request/response timeouts, automatic retries, and circuit breaker patterns for improved resilience when communicating with the CipherSwarm server.

**Server-Driven Configuration**: These values can be overridden by server-recommended settings fetched from the `/configuration` endpoint. When the server provides `recommended_timeouts`, `recommended_retry`, or `recommended_circuit_breaker` settings, the agent applies them at startup and on configuration reload. This allows central management of resilience parameters across your agent fleet.

#### `connect_timeout` / `CONNECT_TIMEOUT`

- **Flag**: `--connect-timeout`
- **Type**: Duration
- **Default**: `10s`
- **Description**: Maximum time to wait for TCP connection establishment to the server
- **Environment**: `CIPHERSWARM_CONNECT_TIMEOUT`
- **Examples**: `5s`, `15s`, `30s`

#### `read_timeout` / `READ_TIMEOUT`

- **Flag**: `--read-timeout`
- **Type**: Duration
- **Default**: `30s`
- **Description**: Maximum time to wait for reading response data from the server
- **Environment**: `CIPHERSWARM_READ_TIMEOUT`
- **Examples**: `15s`, `45s`, `1m`

#### `write_timeout` / `WRITE_TIMEOUT`

- **Flag**: `--write-timeout`
- **Type**: Duration
- **Default**: `10s`
- **Description**: Maximum time to wait for writing request data to the server
- **Environment**: `CIPHERSWARM_WRITE_TIMEOUT`
- **Examples**: `5s`, `15s`, `30s`

#### `request_timeout` / `REQUEST_TIMEOUT`

- **Flag**: `--request-timeout`
- **Type**: Duration
- **Default**: `60s`
- **Description**: Maximum total time for an entire HTTP request/response cycle
- **Environment**: `CIPHERSWARM_REQUEST_TIMEOUT`
- **Examples**: `30s`, `2m`, `5m`

#### `api_max_retries` / `API_MAX_RETRIES`

- **Flag**: `--api-max-retries`
- **Type**: Integer
- **Default**: `3`
- **Description**: Maximum number of retry attempts for failed API requests (network errors and 5xx responses)
- **Environment**: `CIPHERSWARM_API_MAX_RETRIES`
- **Range**: 1-10

#### `api_retry_initial_delay` / `API_RETRY_INITIAL_DELAY`

- **Flag**: `--api-retry-initial-delay`
- **Type**: Duration
- **Default**: `1s`
- **Description**: Initial delay before the first retry attempt (uses exponential backoff)
- **Environment**: `CIPHERSWARM_API_RETRY_INITIAL_DELAY`
- **Examples**: `500ms`, `2s`, `5s`

#### `api_retry_max_delay` / `API_RETRY_MAX_DELAY`

- **Flag**: `--api-retry-max-delay`
- **Type**: Duration
- **Default**: `30s`
- **Description**: Maximum delay between retry attempts (caps exponential backoff)
- **Environment**: `CIPHERSWARM_API_RETRY_MAX_DELAY`
- **Examples**: `15s`, `1m`, `2m`

#### `circuit_breaker_failure_threshold` / `CIRCUIT_BREAKER_FAILURE_THRESHOLD`

- **Flag**: `--circuit-breaker-failure-threshold`
- **Type**: Integer
- **Default**: `5`
- **Description**: Number of consecutive failures before circuit breaker opens
- **Environment**: `CIPHERSWARM_CIRCUIT_BREAKER_FAILURE_THRESHOLD`
- **Range**: 1-20

#### `circuit_breaker_timeout` / `CIRCUIT_BREAKER_TIMEOUT`

- **Flag**: `--circuit-breaker-timeout`
- **Type**: Duration
- **Default**: `60s`
- **Description**: Time to wait in open state before attempting to close the circuit breaker
- **Environment**: `CIPHERSWARM_CIRCUIT_BREAKER_TIMEOUT`
- **Examples**: `30s`, `2m`, `5m`

### Advanced Settings

#### `enable_additional_hash_types` / `ENABLE_ADDITIONAL_HASH_TYPES`

- **Flag**: `--enable-additional-hash-types`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable support for additional hash types during benchmarking

#### `always_trust_files` / `ALWAYS_TRUST_FILES`

- **Flag**: `--always-trust-files`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Skip checksum verification for downloaded files (not recommended)

#### `force_benchmark_run` / `FORCE_BENCHMARK_RUN`

- **Flag**: `--force-benchmark`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Force re-run of benchmarks, bypassing the local cache. Useful when hardware has changed or cached results are suspected to be stale.

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

# Robust fault tolerance for production
task_timeout: 48h  # Allow longer tasks
download_max_retries: 5  # More retries for network issues
download_retry_delay: 5s  # Longer delay between retries
max_heartbeat_backoff: 8  # Allow more backoff during network issues

# HTTP resilience for production
connect_timeout: 15s
read_timeout: 45s
request_timeout: 2m
api_max_retries: 5
circuit_breaker_failure_threshold: 10
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
  - HASHCAT_PATH=  # Leave empty for auto-detection
  # Fault tolerance settings
  - TASK_TIMEOUT=24h
  - DOWNLOAD_MAX_RETRIES=3
  - DOWNLOAD_RETRY_DELAY=2s
  - MAX_HEARTBEAT_BACKOFF=6
  # HTTP resilience settings
  - CIPHERSWARM_CONNECT_TIMEOUT=10s
  - CIPHERSWARM_READ_TIMEOUT=30s
  - CIPHERSWARM_WRITE_TIMEOUT=10s
  - CIPHERSWARM_REQUEST_TIMEOUT=60s
  - CIPHERSWARM_API_MAX_RETRIES=3
  - CIPHERSWARM_API_RETRY_INITIAL_DELAY=1s
  - CIPHERSWARM_API_RETRY_MAX_DELAY=30s
  - CIPHERSWARM_CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
  - CIPHERSWARM_CIRCUIT_BREAKER_TIMEOUT=60s
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
./cipherswarm-agent --debug --extra-debugging
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
