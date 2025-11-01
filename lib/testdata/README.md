# Test Data Directory

This directory contains static test fixtures used across the test suite. These files provide sample data for testing various components of the CipherSwarm agent without requiring external dependencies or live API calls.

## File Descriptions

### `api_responses.json`
Sample API responses from the CipherSwarm server. Contains:
- Authentication success/failure responses
- Configuration responses (both native and non-native hashcat)
- Agent metadata responses
- Heartbeat responses in different states (pending, stopped, error)
- Task response objects
- Error responses with different status codes (401, 403, 404, 500)

### `hashcat_status.json`
Sample hashcat status outputs in various states. Contains:
- Running status - hashcat session in progress
- Paused status - hashcat session paused
- Exhausted status - keyspace exhausted, showing 100% progress
- Cracked status - hash successfully cracked
- Multiple device status - showing CPU + GPU with different utilization levels
- Dictionary attack status - attack mode 0 with dictionary-specific fields
- Mask attack status - attack mode 3 with mask-specific fields

### `sample_hashes.txt`
Sample hash values for testing hash list operations. Contains:
- MD5 hashes (32 hex characters each)
- SHA256 hashes (64 hex characters each)
- Salted hashes (format: `hash:salt`)

These hashes are not real/crackable - they're provided solely for testing file operations and parsing logic.

### `sample_wordlist.txt`
Small wordlist file for testing dictionary attack scenarios. Contains 24 common passwords (one per line). This file is used to test:
- Resource file downloading in `lib/downloader/downloader.go`
- File existence and validation checks
- Hashcat parameter construction for dictionary attacks
- Checksum verification (tests can calculate the actual checksum of this file)

## Usage Guidelines

### Loading Fixtures in Tests

To load these fixtures in your tests, use relative paths:

```go
import (
    "os"
    "path/filepath"
    "testing"
)

func TestExample(t *testing.T) {
    // Get the path to testdata
    testdataPath := filepath.Join("testdata", "api_responses.json")

    // Read the file
    data, err := os.ReadFile(testdataPath)
    if err != nil {
        t.Fatalf("Failed to read testdata: %v", err)
    }

    // Parse JSON (example)
    var responses map[string]interface{}
    if err := json.Unmarshal(data, &responses); err != nil {
        t.Fatalf("Failed to parse testdata: %v", err)
    }

    // Use the fixture data
    authResponse := responses["authentication_success"]
    // ...
}
```

### Using Test Helpers

The `lib/testhelpers` package provides utilities for working with test data:
- `testhelpers.CreateHashListFile()` - Creates hash list files from arrays
- `testhelpers.CreateTestFile()` - Creates test files with specified content
- See `lib/testhelpers/README.md` for more details

## Maintenance Notes

- **API Contract Changes**: When the API contract changes, update `api_responses.json` to match the new response structures
- **Hashcat Status Format**: If hashcat status output format changes, update `hashcat_status.json` accordingly
- **Adding New Scenarios**: When new test scenarios are added, consider adding corresponding fixtures to these files
- **File Size**: Keep fixture files small to avoid bloating the repository. The `sample_wordlist.txt` is intentionally small (under 1KB)

## Build System

The `testdata` directory is ignored by the Go build system by convention. Files in `testdata` directories are not included in builds but are accessible to tests via relative paths from the test file location.

