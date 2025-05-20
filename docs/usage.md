# Usage

## Running the Agent

After building or pulling the Docker image, start the agent:

```bash
./cipherswarm-agent
```

Or with Docker:

```bash
docker run -e API_TOKEN=your_api_token -e API_URL=https://cipherswarm.example.com:3000 ghcr.io/unclesp1d3r/cipherswarmagent:latest
```

## Command Line Flags

The agent supports the following flags:

-   `--api_token`, `-a`: API token for the CipherSwarm server
-   `--api_url`, `-u`: URL of the CipherSwarm server
-   `--data_path`, `-p`: Data directory
-   `--gpu_temp_threshold`, `-g`: GPU temperature threshold (°C)
-   `--always_use_native_hashcat`, `-n`: Use native hashcat binary
-   `--sleep_on_failure`, `-s`: Sleep duration after failure
-   `--files_path`, `-f`: Task files directory
-   `--extra_debugging`, `-e`: Enable extra debugging
-   `--status_timer`, `-t`: Status update interval (seconds)
-   `--write_zaps_to_file`, `-w`: Write zap output to file
-   `--zap_path`, `-z`: Zap output directory
-   `--retain_zaps_on_completion`, `-r`: Retain zap files after task
-   `--help`, `-h`: Show help
-   `--version`, `-v`: Show version

## Basic Workflow

1. Configure the agent (see [Configuration](configuration.md)).
2. Start the agent.
3. The agent connects to the server, receives tasks, and processes them automatically.
4. Monitor logs for status and results.
