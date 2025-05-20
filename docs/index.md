# CipherSwarm Agent Documentation

Welcome to the documentation for **CipherSwarm Agent** — a distributed agent for CipherSwarm, managing and executing hash-cracking tasks at scale.

## Overview

CipherSwarm Agent is a high-performance Go application designed to securely connect to a CipherSwarm server, receive and execute hash-cracking jobs (using Hashcat), and report results. It supports cross-platform operation (Linux, macOS, Windows) and is optimized for distributed, scalable, and secure operation.

-   **Language:** Go (>=1.22)
-   **Entrypoint:** `main.go` → `cmd/root.go` (Cobra CLI)
-   **Core Functionality:**
    -   Secure server connection
    -   Distributed task management
    -   Hashcat integration
    -   Benchmarking and status reporting
    -   Result submission

> **Note:** This project is under active development and not production-ready. APIs and features may change before v1.0.0.

## Quick Links

-   [Installation](installation.md)
-   [Usage](usage.md)
-   [Configuration](configuration.md)
-   [Project Structure](project_structure.md)
-   [Contributing](contributing.md)
