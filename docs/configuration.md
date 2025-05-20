# Configuration

CipherSwarm Agent can be configured via environment variables, a YAML config file, or command line flags.

## Environment Variables

-   `API_TOKEN`: CipherSwarm server API token
-   `API_URL`: CipherSwarm server URL
-   `DATA_PATH`: Data directory (default: ./data)
-   `GPU_TEMP_THRESHOLD`: GPU temperature threshold (°C, default: 80)
-   `ALWAYS_USE_NATIVE_HASHCAT`: Use native hashcat binary (default: false)
-   `SLEEP_ON_FAILURE`: Sleep duration after failure (default: 60s)
-   `FILES_PATH`: Task files directory (default: ./data/files)
-   `EXTRA_DEBUGGING`: Enable extra debugging (default: false)
-   `STATUS_TIMER`: Status update interval (seconds, default: 3)
-   `WRITE_ZAPS_TO_FILE`: Write zap output to file (default: false)
-   `ZAP_PATH`: Zap output directory (default: ./data/zaps)
-   `RETAIN_ZAPS_ON_COMPLETION`: Retain zap files after task (default: false)

## Config File

On first run, the agent generates a YAML config file (default: `$HOME/.cipherswarmagent.yaml`). You can edit this file to set options persistently.

## Command Line Flags

All configuration options can also be set via CLI flags. See [Usage](usage.md) for details.
