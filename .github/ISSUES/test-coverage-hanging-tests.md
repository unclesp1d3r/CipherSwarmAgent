# Investigate and Fix Hanging Tests in lib Package

## Summary

The coverage job in `.github/workflows/go.yml` currently excludes the `lib` package (root package) from test coverage runs due to hanging tests. This issue tracks the investigation and resolution of these hanging tests so they can be re-enabled in the CI coverage workflow.

## Affected Test Files

The following test files in the `lib` package are excluded from coverage:

- `lib/agentClient_test.go`
- `lib/benchmarkManager_test.go`
- `lib/errorUtils_test.go`
- `lib/taskManager_test.go`

## Current Status

- **Status**: Excluded from coverage workflow
- **Workflow**: `.github/workflows/go.yml` (coverage job, lines 49-79)
- **Reason**: Tests hang indefinitely when run in CI (with `-race` flag)
- **Local Testing**: Tests pass successfully locally (~1.8s without race detector)
- **Workaround**: Only `./lib/progress`, `./lib/downloader`, and `./lib/zap` are included in coverage runs

## Test Results

**Local test run (without race detector):**

```bash
go test -timeout 120s -v ./lib
# Result: PASS in 1.844s
# All tests pass: agentClient, benchmarkManager, errorUtils, taskManager
```

**Note**: Race detector testing requires C compiler (gcc) which may not be available in all local environments. The hang appears to be CI-specific, possibly related to:

- Race detector behavior in GitHub Actions environment
- Resource constraints in CI runners
- Interaction between httpmock and race detector in CI

## Investigation Steps

1. **Reproduce the hang locally**

   ```bash
   go test -race -v ./lib/...
   ```

2. **Identify root cause**

   - **CI-specific issue**: Tests pass locally but hang in CI - investigate CI environment differences
   - Check for goroutine leaks (especially with race detector enabled)
   - Look for blocking channel operations
   - Verify HTTP mock cleanup (httpmock) - may interact poorly with race detector in CI
   - Check for context/timeout issues
   - Review shared state cleanup (see `lib/testhelpers/state_helper.go`)
   - Investigate race detector false positives or slowdowns in CI environment

3. **Common causes to check**

   - Unclosed goroutines
   - Blocking channel receives without timeout
   - HTTP mock not properly reset between tests
   - Shared state not cleaned up (see `lib/testhelpers/state_helper.go`)
   - Race conditions causing deadlocks

4. **Test with timeout to identify which test hangs**

   ```bash
   go test -race -timeout 30s -v ./lib/agentClient_test.go
   go test -race -timeout 30s -v ./lib/benchmarkManager_test.go
   go test -race -timeout 30s -v ./lib/errorUtils_test.go
   go test -race -timeout 30s -v ./lib/taskManager_test.go
   ```

5. **Use Go race detector and pprof**

   ```bash
   go test -race -cpuprofile=cpu.prof -memprofile=mem.prof ./lib/...
   go tool pprof cpu.prof
   ```

## Expected Outcome

Once fixed, the workflow should be updated to include `./lib` in the coverage run. See the TODO comment in `.github/workflows/go.yml` (coverage job) for instructions on re-enabling `./lib` package coverage.

## Related Files

- `.github/workflows/go.yml` - Coverage workflow with exclusion
- `lib/testhelpers/` - Test helper utilities (may need cleanup fixes)
- `lib/agentClient_test.go` - Excluded test file
- `lib/benchmarkManager_test.go` - Excluded test file
- `lib/errorUtils_test.go` - Excluded test file
- `lib/taskManager_test.go` - Excluded test file

## Acceptance Criteria

- [ ] All tests in `lib` package run successfully without hanging
- [ ] Tests complete within reasonable time (< 2 minutes for full suite)
- [ ] No goroutine leaks detected
- [ ] Coverage workflow updated to include `./lib` package
- [ ] Coverage percentage increases appropriately

## Notes

- The workflow already includes a `timeout-minutes: 10` guard to prevent infinite hangs
- `continue-on-error: true` ensures CI doesn't fail if coverage step has issues
- Consider using `-timeout` flag in `go test` commands for additional protection
