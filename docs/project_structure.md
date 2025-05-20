# Project Structure

```
CipherSwarmAgent/
├── cmd/         # CLI entrypoint and command registration (Cobra)
├── lib/         # Core agent logic and utilities
│   ├── arch/        # OS-specific abstractions (device detection, binary handling)
│   ├── hashcat/     # Hashcat session management, parameterization, result parsing
│   ├── utils/       # Reusable utilities (e.g., progress tracking)
│   ├── agentClient.go      # Main agent logic, server communication, task lifecycle
│   ├── benchmarkManager.go # Benchmarking logic
│   ├── clientUtils.go      # File, process, and environment utilities
│   ├── dataTypes.go        # Core data structures
├── shared/      # Global state, logging, and shared types
├── docs/        # Project documentation (MkDocs)
├── Dockerfile   # Container build for agent deployment
├── main.go      # Entrypoint
├── README.md    # Project overview and usage
```

-   **cmd/**: Cobra CLI entrypoint and command registration
-   **lib/**: Core agent logic, including server communication, benchmarking, and Hashcat integration
-   **shared/**: Shared state, logging, and types
-   **docs/**: Documentation (this site)
-   **Dockerfile**: Container build instructions
-   **main.go**: Entrypoint
-   **README.md**: Project overview, installation, and usage
