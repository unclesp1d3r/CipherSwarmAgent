# Agent Resilience: HTTP Timeouts, Retry Logic & Circuit Breaker

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement client-side HTTP timeouts, retry logic, and circuit breaker pattern so the agent no longer hangs indefinitely when the CipherSwarm server is unresponsive (GitHub issue unclesp1d3r/CipherSwarm#464).

**Architecture:** The server already provides `recommended_timeouts`, `recommended_retry`, and `recommended_circuit_breaker` in the `/api/v1/client/configuration` response. The agent will: (1) add sensible hard-coded defaults for timeouts/retry/circuit-breaker, (2) wire server-recommended values into agentstate after config fetch, (3) configure `http.Transport` and `http.Client` with real timeouts, (4) wrap the API client with retry middleware, and (5) add a circuit breaker that opens after repeated failures and half-opens after a timeout.

**Tech Stack:** Go stdlib (`net/http`, `net`), existing project patterns (exponential backoff, `sleepWithContext`, `context.Context`), no new external dependencies.

---

## Phase 1: Configuration & State Plumbing

### Task 1: Add Timeout/Retry/CircuitBreaker Default Constants

**Files:**
- Modify: `lib/config/config.go:17-36` (add constants after existing defaults)

**Step 1: Write the failing test**

Create test file `lib/config/config_test.go`:

```go
package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDefaultConstants_Exist(t *testing.T) {
	// Verify new timeout defaults exist and have sensible values
	require.Equal(t, 10*time.Second, DefaultConnectTimeout)
	require.Equal(t, 30*time.Second, DefaultReadTimeout)
	require.Equal(t, 10*time.Second, DefaultWriteTimeout)
	require.Equal(t, 60*time.Second, DefaultRequestTimeout)

	// Verify retry defaults
	require.Equal(t, 3, DefaultAPIMaxRetries)
	require.Equal(t, 1*time.Second, DefaultAPIRetryInitialDelay)
	require.Equal(t, 30*time.Second, DefaultAPIRetryMaxDelay)

	// Verify circuit breaker defaults
	require.Equal(t, 5, DefaultCircuitBreakerFailureThreshold)
	require.Equal(t, 30*time.Second, DefaultCircuitBreakerTimeout)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/config/ -run TestDefaultConstants_Exist -v`
Expected: FAIL — undefined constants

**Step 3: Write minimal implementation**

Add to `lib/config/config.go` after line 35 (before the closing paren of the const block):

```go
// DefaultConnectTimeout is the TCP connect timeout for API requests.
DefaultConnectTimeout = 10 * time.Second
// DefaultReadTimeout is the read timeout for API responses.
DefaultReadTimeout = 30 * time.Second
// DefaultWriteTimeout is the write timeout for API requests.
DefaultWriteTimeout = 10 * time.Second
// DefaultRequestTimeout is the overall request timeout for API calls.
DefaultRequestTimeout = 60 * time.Second
// DefaultAPIMaxRetries is the max retry attempts for failed API requests.
DefaultAPIMaxRetries = 3
// DefaultAPIRetryInitialDelay is the initial delay between API retries.
DefaultAPIRetryInitialDelay = 1 * time.Second
// DefaultAPIRetryMaxDelay is the maximum delay between API retries.
DefaultAPIRetryMaxDelay = 30 * time.Second
// DefaultCircuitBreakerFailureThreshold is the number of failures before the circuit opens.
DefaultCircuitBreakerFailureThreshold = 5
// DefaultCircuitBreakerTimeout is the duration before a tripped circuit half-opens.
DefaultCircuitBreakerTimeout = 30 * time.Second
```

**Step 4: Run test to verify it passes**

Run: `go test ./lib/config/ -run TestDefaultConstants_Exist -v`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/config/config.go lib/config/config_test.go
git commit -s -m "feat(config): add default constants for HTTP timeouts, retry, and circuit breaker"
```

---

### Task 2: Add Timeout/Retry/CircuitBreaker Fields to agentState

**Files:**
- Modify: `agentstate/agentstate.go:45-54` (add new fields after `SleepOnFailure`)

**Step 1: Write the failing test**

Create test file `agentstate/agentstate_test.go`:

```go
package agentstate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAgentState_TimeoutFields(t *testing.T) {
	var s agentState

	// Verify fields exist and are zero-valued by default
	require.Equal(t, time.Duration(0), s.ConnectTimeout)
	require.Equal(t, time.Duration(0), s.ReadTimeout)
	require.Equal(t, time.Duration(0), s.WriteTimeout)
	require.Equal(t, time.Duration(0), s.RequestTimeout)
	require.Equal(t, 0, s.APIMaxRetries)
	require.Equal(t, time.Duration(0), s.APIRetryInitialDelay)
	require.Equal(t, time.Duration(0), s.APIRetryMaxDelay)
	require.Equal(t, 0, s.CircuitBreakerFailureThreshold)
	require.Equal(t, time.Duration(0), s.CircuitBreakerTimeout)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./agentstate/ -run TestAgentState_TimeoutFields -v`
Expected: FAIL — unknown fields

**Step 3: Write minimal implementation**

Add fields to `agentState` struct in `agentstate/agentstate.go` after line 51 (`SleepOnFailure`):

```go
ConnectTimeout                  time.Duration // ConnectTimeout is the TCP connect timeout for API requests.
ReadTimeout                     time.Duration // ReadTimeout is the read timeout for API responses.
WriteTimeout                    time.Duration // WriteTimeout is the write timeout for API requests.
RequestTimeout                  time.Duration // RequestTimeout is the overall request timeout for API calls.
APIMaxRetries                   int           // APIMaxRetries is the max retry attempts for failed API requests.
APIRetryInitialDelay            time.Duration // APIRetryInitialDelay is the initial delay between API retries.
APIRetryMaxDelay                time.Duration // APIRetryMaxDelay is the maximum delay between API retries.
CircuitBreakerFailureThreshold  int           // CircuitBreakerFailureThreshold is failures before circuit opens.
CircuitBreakerTimeout           time.Duration // CircuitBreakerTimeout is the duration before half-open retry.
```

**Step 4: Run test to verify it passes**

Run: `go test ./agentstate/ -run TestAgentState_TimeoutFields -v`
Expected: PASS

**Step 5: Commit**

```bash
git add agentstate/agentstate.go agentstate/agentstate_test.go
git commit -s -m "feat(agentstate): add timeout, retry, and circuit breaker fields"
```

---

### Task 3: Wire Defaults into SetupSharedState and SetDefaultConfigValues

**Files:**
- Modify: `lib/config/config.go:79-189` (`SetupSharedState`) and `lib/config/config.go:192-217` (`SetDefaultConfigValues`)

**Step 1: Write the failing test**

Add to `lib/config/config_test.go`:

```go
func TestSetupSharedState_DefaultTimeouts(t *testing.T) {
	// Set defaults and initialize viper with them
	SetDefaultConfigValues()

	// Run SetupSharedState (needs api_url/api_token set)
	viper.Set("api_url", "http://test:3000")
	viper.Set("api_token", "test-token")
	SetupSharedState()
	t.Cleanup(func() { viper.Reset() })

	require.Equal(t, DefaultConnectTimeout, agentstate.State.ConnectTimeout)
	require.Equal(t, DefaultReadTimeout, agentstate.State.ReadTimeout)
	require.Equal(t, DefaultWriteTimeout, agentstate.State.WriteTimeout)
	require.Equal(t, DefaultRequestTimeout, agentstate.State.RequestTimeout)
	require.Equal(t, DefaultAPIMaxRetries, agentstate.State.APIMaxRetries)
	require.Equal(t, DefaultAPIRetryInitialDelay, agentstate.State.APIRetryInitialDelay)
	require.Equal(t, DefaultAPIRetryMaxDelay, agentstate.State.APIRetryMaxDelay)
	require.Equal(t, DefaultCircuitBreakerFailureThreshold, agentstate.State.CircuitBreakerFailureThreshold)
	require.Equal(t, DefaultCircuitBreakerTimeout, agentstate.State.CircuitBreakerTimeout)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/config/ -run TestSetupSharedState_DefaultTimeouts -v`
Expected: FAIL — fields not populated

**Step 3: Write minimal implementation**

Add to `SetDefaultConfigValues()` in `lib/config/config.go` (before the closing brace):

```go
viper.SetDefault("connect_timeout", DefaultConnectTimeout)
viper.SetDefault("read_timeout", DefaultReadTimeout)
viper.SetDefault("write_timeout", DefaultWriteTimeout)
viper.SetDefault("request_timeout", DefaultRequestTimeout)
viper.SetDefault("api_max_retries", DefaultAPIMaxRetries)
viper.SetDefault("api_retry_initial_delay", DefaultAPIRetryInitialDelay)
viper.SetDefault("api_retry_max_delay", DefaultAPIRetryMaxDelay)
viper.SetDefault("circuit_breaker_failure_threshold", DefaultCircuitBreakerFailureThreshold)
viper.SetDefault("circuit_breaker_timeout", DefaultCircuitBreakerTimeout)
```

Add to `SetupSharedState()` in `lib/config/config.go` (after the `SleepOnFailure` line):

```go
agentstate.State.ConnectTimeout = viper.GetDuration("connect_timeout")
if agentstate.State.ConnectTimeout <= 0 {
	agentstate.Logger.Warn("connect_timeout must be > 0, using default",
		"configured", agentstate.State.ConnectTimeout, "default", DefaultConnectTimeout)
	agentstate.State.ConnectTimeout = DefaultConnectTimeout
}

agentstate.State.ReadTimeout = viper.GetDuration("read_timeout")
if agentstate.State.ReadTimeout <= 0 {
	agentstate.Logger.Warn("read_timeout must be > 0, using default",
		"configured", agentstate.State.ReadTimeout, "default", DefaultReadTimeout)
	agentstate.State.ReadTimeout = DefaultReadTimeout
}

agentstate.State.WriteTimeout = viper.GetDuration("write_timeout")
if agentstate.State.WriteTimeout <= 0 {
	agentstate.Logger.Warn("write_timeout must be > 0, using default",
		"configured", agentstate.State.WriteTimeout, "default", DefaultWriteTimeout)
	agentstate.State.WriteTimeout = DefaultWriteTimeout
}

agentstate.State.RequestTimeout = viper.GetDuration("request_timeout")
if agentstate.State.RequestTimeout <= 0 {
	agentstate.Logger.Warn("request_timeout must be > 0, using default",
		"configured", agentstate.State.RequestTimeout, "default", DefaultRequestTimeout)
	agentstate.State.RequestTimeout = DefaultRequestTimeout
}

agentstate.State.APIMaxRetries = viper.GetInt("api_max_retries")
if agentstate.State.APIMaxRetries < 1 {
	agentstate.Logger.Warn("api_max_retries must be >= 1, using default",
		"configured", agentstate.State.APIMaxRetries, "default", DefaultAPIMaxRetries)
	agentstate.State.APIMaxRetries = DefaultAPIMaxRetries
}

agentstate.State.APIRetryInitialDelay = viper.GetDuration("api_retry_initial_delay")
agentstate.State.APIRetryMaxDelay = viper.GetDuration("api_retry_max_delay")
agentstate.State.CircuitBreakerFailureThreshold = viper.GetInt("circuit_breaker_failure_threshold")
if agentstate.State.CircuitBreakerFailureThreshold < 1 {
	agentstate.Logger.Warn("circuit_breaker_failure_threshold must be >= 1, using default",
		"configured", agentstate.State.CircuitBreakerFailureThreshold,
		"default", DefaultCircuitBreakerFailureThreshold)
	agentstate.State.CircuitBreakerFailureThreshold = DefaultCircuitBreakerFailureThreshold
}

agentstate.State.CircuitBreakerTimeout = viper.GetDuration("circuit_breaker_timeout")
if agentstate.State.CircuitBreakerTimeout <= 0 {
	agentstate.Logger.Warn("circuit_breaker_timeout must be > 0, using default",
		"configured", agentstate.State.CircuitBreakerTimeout, "default", DefaultCircuitBreakerTimeout)
	agentstate.State.CircuitBreakerTimeout = DefaultCircuitBreakerTimeout
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./lib/config/ -run TestSetupSharedState_DefaultTimeouts -v`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/config/config.go lib/config/config_test.go
git commit -s -m "feat(config): wire timeout/retry/circuit-breaker defaults into SetupSharedState"
```

---

### Task 4: Add CLI Flags for New Settings

**Files:**
- Modify: `cmd/root.go:90-165` (add flags after existing ones, before `registerDeprecatedAliases()`)

**Step 1: Add CLI flags**

Add to `cmd/root.go` `init()` function, before the `registerDeprecatedAliases()` call:

```go
RootCmd.PersistentFlags().
	Duration("connect-timeout", config.DefaultConnectTimeout, "TCP connect timeout for API requests")
err = viper.BindPFlag("connect_timeout", RootCmd.PersistentFlags().Lookup("connect-timeout"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Duration("read-timeout", config.DefaultReadTimeout, "Read timeout for API responses")
err = viper.BindPFlag("read_timeout", RootCmd.PersistentFlags().Lookup("read-timeout"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Duration("write-timeout", config.DefaultWriteTimeout, "Write timeout for API requests")
err = viper.BindPFlag("write_timeout", RootCmd.PersistentFlags().Lookup("write-timeout"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Duration("request-timeout", config.DefaultRequestTimeout, "Overall request timeout for API calls")
err = viper.BindPFlag("request_timeout", RootCmd.PersistentFlags().Lookup("request-timeout"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Int("api-max-retries", config.DefaultAPIMaxRetries, "Maximum retry attempts for failed API requests")
err = viper.BindPFlag("api_max_retries", RootCmd.PersistentFlags().Lookup("api-max-retries"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Duration("api-retry-initial-delay", config.DefaultAPIRetryInitialDelay, "Initial delay between API retries")
err = viper.BindPFlag("api_retry_initial_delay", RootCmd.PersistentFlags().Lookup("api-retry-initial-delay"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Duration("api-retry-max-delay", config.DefaultAPIRetryMaxDelay, "Maximum delay between API retries")
err = viper.BindPFlag("api_retry_max_delay", RootCmd.PersistentFlags().Lookup("api-retry-max-delay"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Int("circuit-breaker-failure-threshold", config.DefaultCircuitBreakerFailureThreshold,
		"Number of failures before circuit breaker opens")
err = viper.BindPFlag("circuit_breaker_failure_threshold",
	RootCmd.PersistentFlags().Lookup("circuit-breaker-failure-threshold"))
cobra.CheckErr(err)

RootCmd.PersistentFlags().
	Duration("circuit-breaker-timeout", config.DefaultCircuitBreakerTimeout,
		"Duration before tripped circuit breaker half-opens for retry")
err = viper.BindPFlag("circuit_breaker_timeout", RootCmd.PersistentFlags().Lookup("circuit-breaker-timeout"))
cobra.CheckErr(err)
```

**Step 2: Verify build compiles**

Run: `go build ./...`
Expected: PASS

**Step 3: Verify flags appear in help**

Run: `go run . --help 2>&1 | grep -E "connect-timeout|request-timeout|api-max-retries|circuit-breaker"`
Expected: All 9 new flags visible

**Step 4: Commit**

```bash
git add cmd/root.go
git commit -s -m "feat(cli): add flags for HTTP timeout, retry, and circuit breaker settings"
```

---

### Task 5: Map Server-Recommended Values from Configuration Response

**Files:**
- Modify: `lib/dataTypes.go` (add new fields to `agentConfiguration`)
- Modify: `lib/agentClient.go:100-114` (`mapConfiguration` — add new fields)

**Step 1: Write the failing test**

Create or extend `lib/agentClient_test.go`:

```go
package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
)

func TestMapConfiguration_RecommendedSettings(t *testing.T) {
	config := api.AdvancedAgentConfiguration{}
	timeouts := RecommendedTimeouts{
		ConnectTimeout: 15,
		ReadTimeout:    45,
		WriteTimeout:   15,
		RequestTimeout: 90,
	}
	retry := RecommendedRetry{
		MaxAttempts:  5,
		InitialDelay: 2,
		MaxDelay:     60,
	}
	cb := RecommendedCircuitBreaker{
		FailureThreshold: 10,
		Timeout:          60,
	}

	result := mapConfiguration(1, config, false, &timeouts, &retry, &cb)

	require.NotNil(t, result.RecommendedTimeouts)
	require.Equal(t, 15, result.RecommendedTimeouts.ConnectTimeout)
	require.Equal(t, 45, result.RecommendedTimeouts.ReadTimeout)
	require.Equal(t, 15, result.RecommendedTimeouts.WriteTimeout)
	require.Equal(t, 90, result.RecommendedTimeouts.RequestTimeout)

	require.NotNil(t, result.RecommendedRetry)
	require.Equal(t, 5, result.RecommendedRetry.MaxAttempts)
	require.Equal(t, 2, result.RecommendedRetry.InitialDelay)
	require.Equal(t, 60, result.RecommendedRetry.MaxDelay)

	require.NotNil(t, result.RecommendedCircuitBreaker)
	require.Equal(t, 10, result.RecommendedCircuitBreaker.FailureThreshold)
	require.Equal(t, 60, result.RecommendedCircuitBreaker.Timeout)
}

func TestMapConfiguration_NilRecommendedSettings(t *testing.T) {
	config := api.AdvancedAgentConfiguration{}
	result := mapConfiguration(1, config, false, nil, nil, nil)

	require.Nil(t, result.RecommendedTimeouts)
	require.Nil(t, result.RecommendedRetry)
	require.Nil(t, result.RecommendedCircuitBreaker)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/ -run TestMapConfiguration_Recommended -v`
Expected: FAIL — types and function signature don't match

**Step 3: Write minimal implementation**

Update `lib/dataTypes.go`:

```go
package lib

// agentConfig holds the various configuration settings for an agent.
type agentConfig struct {
	UseNativeHashcat    bool   `json:"use_native_hashcat"        yaml:"use_native_hashcat"`
	AgentUpdateInterval int64  `json:"agent_update_interval"     yaml:"agent_update_interval"`
	BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"`
	OpenCLDevices       string `json:"opencl_devices,omitempty"  yaml:"opencl_devices,omitempty"`
}

// RecommendedTimeouts holds server-recommended timeout settings (values in seconds).
type RecommendedTimeouts struct {
	ConnectTimeout int `json:"connect_timeout" yaml:"connect_timeout"`
	ReadTimeout    int `json:"read_timeout"    yaml:"read_timeout"`
	WriteTimeout   int `json:"write_timeout"   yaml:"write_timeout"`
	RequestTimeout int `json:"request_timeout" yaml:"request_timeout"`
}

// RecommendedRetry holds server-recommended retry settings.
type RecommendedRetry struct {
	MaxAttempts  int `json:"max_attempts"   yaml:"max_attempts"`
	InitialDelay int `json:"initial_delay"  yaml:"initial_delay"`
	MaxDelay     int `json:"max_delay"      yaml:"max_delay"`
}

// RecommendedCircuitBreaker holds server-recommended circuit breaker settings.
type RecommendedCircuitBreaker struct {
	FailureThreshold int `json:"failure_threshold" yaml:"failure_threshold"`
	Timeout          int `json:"timeout"           yaml:"timeout"`
}

// agentConfiguration holds the configuration settings and API version for the agent client.
type agentConfiguration struct {
	Config                    agentConfig                `json:"config"                      yaml:"config"`
	APIVersion                int64                      `json:"api_version"                 yaml:"api_version"`
	BenchmarksNeeded          bool                       `json:"benchmarks_needed"            yaml:"benchmarks_needed"`
	RecommendedTimeouts       *RecommendedTimeouts       `json:"recommended_timeouts,omitempty"       yaml:"recommended_timeouts,omitempty"`
	RecommendedRetry          *RecommendedRetry          `json:"recommended_retry,omitempty"          yaml:"recommended_retry,omitempty"`
	RecommendedCircuitBreaker *RecommendedCircuitBreaker `json:"recommended_circuit_breaker,omitempty" yaml:"recommended_circuit_breaker,omitempty"`
}
```

Update `mapConfiguration` in `lib/agentClient.go`:

```go
func mapConfiguration(
	apiVersion int,
	config api.AdvancedAgentConfiguration,
	benchmarksNeeded bool,
	timeouts *RecommendedTimeouts,
	retry *RecommendedRetry,
	circuitBreaker *RecommendedCircuitBreaker,
) agentConfiguration {
	return agentConfiguration{
		APIVersion:       int64(apiVersion),
		BenchmarksNeeded: benchmarksNeeded,
		Config: agentConfig{
			UseNativeHashcat:    UnwrapOr(config.UseNativeHashcat, false),
			AgentUpdateInterval: int64(UnwrapOr(config.AgentUpdateInterval, defaultAgentUpdateInterval)),
			BackendDevices:      UnwrapOr(config.BackendDevice, ""),
			OpenCLDevices:       UnwrapOr(config.OpenclDevices, ""),
		},
		RecommendedTimeouts:       timeouts,
		RecommendedRetry:          retry,
		RecommendedCircuitBreaker: circuitBreaker,
	}
}
```

Update the call site in `GetAgentConfiguration` (`lib/agentClient.go:80-84`):

```go
// Extract server-recommended settings from the configuration response.
var recTimeouts *RecommendedTimeouts
rt := response.JSON200.RecommendedTimeouts
if rt.ConnectTimeout > 0 || rt.ReadTimeout > 0 || rt.WriteTimeout > 0 || rt.RequestTimeout > 0 {
	recTimeouts = &RecommendedTimeouts{
		ConnectTimeout: rt.ConnectTimeout,
		ReadTimeout:    rt.ReadTimeout,
		WriteTimeout:   rt.WriteTimeout,
		RequestTimeout: rt.RequestTimeout,
	}
}

var recRetry *RecommendedRetry
rr := response.JSON200.RecommendedRetry
if rr.MaxAttempts > 0 {
	recRetry = &RecommendedRetry{
		MaxAttempts:  rr.MaxAttempts,
		InitialDelay: rr.InitialDelay,
		MaxDelay:     rr.MaxDelay,
	}
}

var recCB *RecommendedCircuitBreaker
rcb := response.JSON200.RecommendedCircuitBreaker
if rcb.FailureThreshold > 0 {
	recCB = &RecommendedCircuitBreaker{
		FailureThreshold: rcb.FailureThreshold,
		Timeout:          rcb.Timeout,
	}
}

agentConfig := mapConfiguration(
	response.JSON200.ApiVersion,
	response.JSON200.Config,
	response.JSON200.BenchmarksNeeded,
	recTimeouts,
	recRetry,
	recCB,
)
```

**Step 4: Run test to verify it passes**

Run: `go test ./lib/ -run TestMapConfiguration_Recommended -v`
Expected: PASS

**Step 5: Run full build**

Run: `go build ./...`
Expected: PASS

**Step 6: Commit**

```bash
git add lib/dataTypes.go lib/agentClient.go lib/agentClient_test.go
git commit -s -m "feat(config): map server-recommended timeout/retry/circuit-breaker settings"
```

---

### Task 6: Apply Server-Recommended Values to agentstate (Override Defaults)

**Files:**
- Modify: `lib/agentClient.go` (`GetAgentConfiguration` — apply recommended values after mapping)

**Step 1: Write the failing test**

Add to `lib/agentClient_test.go`:

```go
func TestApplyRecommendedSettings_OverridesDefaults(t *testing.T) {
	// Setup minimal state
	cleanup := testhelpers.SetupMinimalTestState(1)
	t.Cleanup(cleanup)

	// Set initial defaults
	agentstate.State.ConnectTimeout = 10 * time.Second
	agentstate.State.RequestTimeout = 60 * time.Second
	agentstate.State.APIMaxRetries = 3
	agentstate.State.CircuitBreakerFailureThreshold = 5

	rec := agentConfiguration{
		RecommendedTimeouts: &RecommendedTimeouts{
			ConnectTimeout: 15,
			ReadTimeout:    45,
			WriteTimeout:   15,
			RequestTimeout: 90,
		},
		RecommendedRetry: &RecommendedRetry{
			MaxAttempts:  5,
			InitialDelay: 2,
			MaxDelay:     60,
		},
		RecommendedCircuitBreaker: &RecommendedCircuitBreaker{
			FailureThreshold: 10,
			Timeout:          60,
		},
	}

	applyRecommendedSettings(rec)

	require.Equal(t, 15*time.Second, agentstate.State.ConnectTimeout)
	require.Equal(t, 45*time.Second, agentstate.State.ReadTimeout)
	require.Equal(t, 15*time.Second, agentstate.State.WriteTimeout)
	require.Equal(t, 90*time.Second, agentstate.State.RequestTimeout)
	require.Equal(t, 5, agentstate.State.APIMaxRetries)
	require.Equal(t, 2*time.Second, agentstate.State.APIRetryInitialDelay)
	require.Equal(t, 60*time.Second, agentstate.State.APIRetryMaxDelay)
	require.Equal(t, 10, agentstate.State.CircuitBreakerFailureThreshold)
	require.Equal(t, 60*time.Second, agentstate.State.CircuitBreakerTimeout)
}

func TestApplyRecommendedSettings_NilKeepsDefaults(t *testing.T) {
	cleanup := testhelpers.SetupMinimalTestState(1)
	t.Cleanup(cleanup)

	agentstate.State.ConnectTimeout = 10 * time.Second
	agentstate.State.APIMaxRetries = 3

	rec := agentConfiguration{} // all nil pointers

	applyRecommendedSettings(rec)

	require.Equal(t, 10*time.Second, agentstate.State.ConnectTimeout)
	require.Equal(t, 3, agentstate.State.APIMaxRetries)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/ -run TestApplyRecommendedSettings -v`
Expected: FAIL — `applyRecommendedSettings` undefined

**Step 3: Write minimal implementation**

Add function to `lib/agentClient.go`:

```go
// applyRecommendedSettings overrides agentstate timeout/retry/circuit-breaker
// values with server-recommended settings when present. Server values are in
// seconds and are converted to time.Duration.
func applyRecommendedSettings(cfg agentConfiguration) {
	if t := cfg.RecommendedTimeouts; t != nil {
		if t.ConnectTimeout > 0 {
			agentstate.State.ConnectTimeout = time.Duration(t.ConnectTimeout) * time.Second
		}
		if t.ReadTimeout > 0 {
			agentstate.State.ReadTimeout = time.Duration(t.ReadTimeout) * time.Second
		}
		if t.WriteTimeout > 0 {
			agentstate.State.WriteTimeout = time.Duration(t.WriteTimeout) * time.Second
		}
		if t.RequestTimeout > 0 {
			agentstate.State.RequestTimeout = time.Duration(t.RequestTimeout) * time.Second
		}
	}

	if r := cfg.RecommendedRetry; r != nil {
		if r.MaxAttempts > 0 {
			agentstate.State.APIMaxRetries = r.MaxAttempts
		}
		if r.InitialDelay > 0 {
			agentstate.State.APIRetryInitialDelay = time.Duration(r.InitialDelay) * time.Second
		}
		if r.MaxDelay > 0 {
			agentstate.State.APIRetryMaxDelay = time.Duration(r.MaxDelay) * time.Second
		}
	}

	if cb := cfg.RecommendedCircuitBreaker; cb != nil {
		if cb.FailureThreshold > 0 {
			agentstate.State.CircuitBreakerFailureThreshold = cb.FailureThreshold
		}
		if cb.Timeout > 0 {
			agentstate.State.CircuitBreakerTimeout = time.Duration(cb.Timeout) * time.Second
		}
	}
}
```

Call `applyRecommendedSettings(agentConfig)` in `GetAgentConfiguration`, right before `Configuration = agentConfig`:

```go
applyRecommendedSettings(agentConfig)
Configuration = agentConfig
```

**Step 4: Run test to verify it passes**

Run: `go test ./lib/ -run TestApplyRecommendedSettings -v`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/agentClient.go lib/agentClient_test.go
git commit -s -m "feat(config): apply server-recommended timeout/retry/circuit-breaker to agentstate"
```

---

## Phase 2: HTTP Client Timeouts

### Task 7: Configure http.Transport with Timeouts in NewAgentClient

**Files:**
- Modify: `lib/api/client.go:26-42` (`NewAgentClient` — add `TimeoutConfig` parameter, configure transport)

**Step 1: Write the failing test**

Add to `lib/api/client_test.go` (create if needed):

```go
package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewAgentClient_WithTimeouts(t *testing.T) {
	cfg := TimeoutConfig{
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   5 * time.Second,
		RequestTimeout: 30 * time.Second,
	}

	client, err := NewAgentClient("http://localhost:3000", "test-token", cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNewAgentClient_ZeroTimeoutsUsesDefaults(t *testing.T) {
	cfg := TimeoutConfig{} // all zero
	client, err := NewAgentClient("http://localhost:3000", "test-token", cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/api/ -run TestNewAgentClient -v`
Expected: FAIL — wrong number of arguments

**Step 3: Write minimal implementation**

Add `TimeoutConfig` type and update `NewAgentClient` in `lib/api/client.go`:

```go
// TimeoutConfig holds HTTP timeout settings for the API client.
type TimeoutConfig struct {
	ConnectTimeout time.Duration // TCP connection timeout (via DialContext)
	ReadTimeout    time.Duration // Response header read timeout (ResponseHeaderTimeout)
	WriteTimeout   time.Duration // TLS handshake timeout
	RequestTimeout time.Duration // Overall request timeout (http.Client.Timeout)
}

// NewAgentClient creates a new AgentClient from a server URL, bearer token, and timeout config.
func NewAgentClient(serverURL, token string, timeouts TimeoutConfig) (*AgentClient, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeouts.ConnectTimeout}).DialContext,
		ResponseHeaderTimeout: timeouts.ReadTimeout,
		TLSHandshakeTimeout:   timeouts.WriteTimeout,
	}

	httpClient := &http.Client{
		Timeout:   timeouts.RequestTimeout,
		Transport: transport,
	}

	authEditor := WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	})

	c, err := NewClientWithResponses(serverURL, WithHTTPClient(httpClient), authEditor)
	if err != nil {
		return nil, fmt.Errorf("creating API client: %w", err)
	}

	return &AgentClient{
		client: c,
	}, nil
}
```

Add `"net"` to the import block.

**Step 4: Fix call site**

Update `lib/agent/agent.go:57` where `NewAgentClient` is called:

```go
apiClient, err := api.NewAgentClient(
	agentstate.State.URL,
	agentstate.State.APIToken,
	api.TimeoutConfig{
		ConnectTimeout: agentstate.State.ConnectTimeout,
		ReadTimeout:    agentstate.State.ReadTimeout,
		WriteTimeout:   agentstate.State.WriteTimeout,
		RequestTimeout: agentstate.State.RequestTimeout,
	},
)
```

**Step 5: Run tests and build**

Run: `go build ./... && go test ./lib/api/ -run TestNewAgentClient -v`
Expected: PASS

**Step 6: Commit**

```bash
git add lib/api/client.go lib/api/client_test.go lib/agent/agent.go
git commit -s -m "feat(api): configure HTTP transport with connect/read/write/request timeouts"
```

---

## Phase 3: Retry Middleware

### Task 8: Create Retry Transport

**Files:**
- Create: `lib/api/retry_transport.go`
- Create: `lib/api/retry_transport_test.go`

**Step 1: Write the failing test**

Create `lib/api/retry_transport_test.go`:

```go
package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockTransport is a test RoundTripper that returns configurable responses.
type mockTransport struct {
	responses []*http.Response
	errors    []error
	calls     atomic.Int32
}

func (m *mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	idx := int(m.calls.Add(1)) - 1
	if idx < len(m.errors) && m.errors[idx] != nil {
		return nil, m.errors[idx]
	}
	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestRetryTransport_RetriesOnError(t *testing.T) {
	mock := &mockTransport{
		errors: []error{
			io.ErrUnexpectedEOF, // attempt 1: fails
			nil,                 // attempt 2: succeeds
		},
		responses: []*http.Response{
			nil,
			{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		},
	}

	rt := &RetryTransport{
		Base:         mock,
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(2), mock.calls.Load())
}

func TestRetryTransport_DoesNotRetrySuccess(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		},
	}

	rt := &RetryTransport{
		Base:         mock,
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(1), mock.calls.Load())
}

func TestRetryTransport_DoesNotRetry4xx(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found"))},
		},
	}

	rt := &RetryTransport{
		Base:         mock,
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.Equal(t, int32(1), mock.calls.Load())
}

func TestRetryTransport_Retries5xx(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(""))},
			{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		},
	}

	rt := &RetryTransport{
		Base:         mock,
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := rt.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int32(2), mock.calls.Load())
}

func TestRetryTransport_RespectsContextCancellation(t *testing.T) {
	mock := &mockTransport{
		errors: []error{io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
	}

	rt := &RetryTransport{
		Base:         mock,
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://test", nil)
	_, err := rt.RoundTrip(req)

	require.Error(t, err)
}

func TestRetryTransport_ExhaustsRetries(t *testing.T) {
	mock := &mockTransport{
		errors: []error{io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
	}

	rt := &RetryTransport{
		Base:         mock,
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	_, err := rt.RoundTrip(req)

	require.Error(t, err)
	require.Equal(t, int32(3), mock.calls.Load())
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/api/ -run TestRetryTransport -v`
Expected: FAIL — `RetryTransport` undefined

**Step 3: Write minimal implementation**

Create `lib/api/retry_transport.go`:

```go
package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// RetryTransport wraps an http.RoundTripper with retry logic using exponential backoff.
// It retries on network errors and 5xx responses, but not on 4xx client errors.
type RetryTransport struct {
	Base         http.RoundTripper // Underlying transport
	MaxAttempts  int               // Total attempts (1 = no retry)
	InitialDelay time.Duration     // First retry delay
	MaxDelay     time.Duration     // Cap for exponential backoff
}

// RoundTrip implements http.RoundTripper with retry logic.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := t.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	var lastResp *http.Response

	for attempt := range maxAttempts {
		if attempt > 0 {
			delay := t.backoffDelay(attempt)
			if err := sleepWithRequestContext(req.Context(), delay); err != nil {
				if lastErr != nil {
					return nil, fmt.Errorf(
						"request cancelled after %d attempt(s) (last error: %w): %w",
						attempt, lastErr, err)
				}
				return nil, fmt.Errorf("request cancelled: %w", err)
			}
		}

		resp, err := t.Base.RoundTrip(req)
		if err != nil {
			lastErr = err
			agentstate.Logger.Debug("API request failed, will retry",
				"attempt", attempt+1, "max", maxAttempts, "error", err)
			continue
		}

		// Don't retry 4xx errors — those are client-side issues
		if resp.StatusCode < http.StatusInternalServerError {
			return resp, nil
		}

		// 5xx: close body before retry to avoid leaking connections
		agentstate.Logger.Debug("API request returned server error, will retry",
			"attempt", attempt+1, "max", maxAttempts, "status", resp.StatusCode)
		lastResp = resp
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all %d API request attempts failed: %w", maxAttempts, lastErr)
	}

	// Return last 5xx response if all retries exhausted
	return lastResp, nil
}

// backoffDelay computes exponential backoff: initialDelay * 2^(attempt-1), capped at maxDelay.
func (t *RetryTransport) backoffDelay(attempt int) time.Duration {
	delay := t.InitialDelay * time.Duration(1<<(attempt-1))
	if delay > t.MaxDelay {
		delay = t.MaxDelay
	}
	return delay
}

// sleepWithRequestContext blocks for the given duration or until the context is cancelled.
// Returns the context error if cancelled.
func sleepWithRequestContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

Add `"context"` to the import block.

**Step 4: Run test to verify it passes**

Run: `go test ./lib/api/ -run TestRetryTransport -v -race`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/api/retry_transport.go lib/api/retry_transport_test.go
git commit -s -m "feat(api): add RetryTransport with exponential backoff for API requests"
```

---

### Task 9: Wire RetryTransport into NewAgentClient

**Files:**
- Modify: `lib/api/client.go` (`NewAgentClient` — add `RetryConfig` parameter, wrap transport)

**Step 1: Add RetryConfig and update NewAgentClient**

Add `RetryConfig` type:

```go
// RetryConfig holds retry settings for the API client.
type RetryConfig struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
}
```

Update `NewAgentClient` signature to `NewAgentClient(serverURL, token string, timeouts TimeoutConfig, retry RetryConfig)` and wrap the transport:

```go
var roundTripper http.RoundTripper = transport
if retry.MaxAttempts > 1 {
	roundTripper = &RetryTransport{
		Base:         transport,
		MaxAttempts:  retry.MaxAttempts,
		InitialDelay: retry.InitialDelay,
		MaxDelay:     retry.MaxDelay,
	}
}

httpClient := &http.Client{
	Timeout:   timeouts.RequestTimeout,
	Transport: roundTripper,
}
```

**Step 2: Fix call site in agent.go**

Update `lib/agent/agent.go:57`:

```go
apiClient, err := api.NewAgentClient(
	agentstate.State.URL,
	agentstate.State.APIToken,
	api.TimeoutConfig{
		ConnectTimeout: agentstate.State.ConnectTimeout,
		ReadTimeout:    agentstate.State.ReadTimeout,
		WriteTimeout:   agentstate.State.WriteTimeout,
		RequestTimeout: agentstate.State.RequestTimeout,
	},
	api.RetryConfig{
		MaxAttempts:  agentstate.State.APIMaxRetries,
		InitialDelay: agentstate.State.APIRetryInitialDelay,
		MaxDelay:     agentstate.State.APIRetryMaxDelay,
	},
)
```

**Step 3: Fix tests**

Update any existing tests that call `NewAgentClient` to pass the new parameters.

**Step 4: Verify build and tests**

Run: `go build ./... && go test ./... -race -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/api/client.go lib/api/client_test.go lib/agent/agent.go
git commit -s -m "feat(api): wire RetryTransport into API client construction"
```

---

## Phase 4: Circuit Breaker

### Task 10: Create Circuit Breaker

**Files:**
- Create: `lib/api/circuit_breaker.go`
- Create: `lib/api/circuit_breaker_test.go`

**Step 1: Write the failing test**

Create `lib/api/circuit_breaker_test.go`:

```go
package api

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCircuitBreaker_StartsInClosedState(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)
	require.True(t, cb.Allow())
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	require.True(t, cb.Allow()) // 2 failures, threshold is 3

	cb.RecordFailure()
	require.False(t, cb.Allow()) // 3 failures, circuit opens
}

func TestCircuitBreaker_HalfOpensAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	require.False(t, cb.Allow()) // open

	time.Sleep(15 * time.Millisecond) // wait for timeout
	require.True(t, cb.Allow())       // half-open: allows one probe
	require.False(t, cb.Allow())      // still half-open, no second probe
}

func TestCircuitBreaker_ClosesAfterSuccessInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(15 * time.Millisecond) // half-open
	require.True(t, cb.Allow())
	cb.RecordSuccess() // close circuit

	require.True(t, cb.Allow()) // back to closed
}

func TestCircuitBreaker_ReopensOnFailureInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(15 * time.Millisecond) // half-open
	require.True(t, cb.Allow())
	cb.RecordFailure() // trip again

	require.False(t, cb.Allow()) // back to open
}

func TestCircuitBreaker_ResetsClearState(t *testing.T) {
	cb := NewCircuitBreaker(2, 100*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	require.False(t, cb.Allow())

	cb.Reset()
	require.True(t, cb.Allow())
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // reset
	cb.RecordFailure()
	cb.RecordFailure()
	require.True(t, cb.Allow()) // only 2 consecutive failures since last success
}

func TestCircuitBreaker_ErrCircuitOpen(t *testing.T) {
	require.True(t, errors.Is(ErrCircuitOpen, ErrCircuitOpen))
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/api/ -run TestCircuitBreaker -v`
Expected: FAIL — types undefined

**Step 3: Write minimal implementation**

Create `lib/api/circuit_breaker.go`:

```go
package api

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is open and not allowing requests.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// circuitState represents the state of a circuit breaker.
type circuitState int

const (
	stateClosed   circuitState = iota // Normal operation
	stateOpen                         // Failing, rejecting requests
	stateHalfOpen                     // Testing if service has recovered
)

// CircuitBreaker implements the circuit breaker pattern for API resilience.
// It tracks consecutive failures and opens the circuit when a threshold is reached,
// preventing further requests until a timeout expires and a probe request succeeds.
//
// Thread-safe: all methods use a mutex for synchronization.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            circuitState
	failures         int
	failureThreshold int
	timeout          time.Duration
	lastFailureTime  time.Time
}

// NewCircuitBreaker creates a circuit breaker with the given failure threshold and timeout.
func NewCircuitBreaker(failureThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		timeout:          timeout,
		state:            stateClosed,
	}
}

// Allow returns true if the circuit breaker allows a request to proceed.
// In closed state, always allows. In open state, allows only after the timeout
// has elapsed (transitions to half-open for a single probe request).
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case stateClosed:
		return true
	case stateOpen:
		if time.Since(cb.lastFailureTime) >= cb.timeout {
			cb.state = stateHalfOpen
			return true
		}
		return false
	case stateHalfOpen:
		return false // Only one probe request at a time
	}

	return false
}

// RecordSuccess records a successful request. Resets failure count in closed state,
// and closes the circuit in half-open state.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = stateClosed
}

// RecordFailure records a failed request. Increments failure count and opens the
// circuit if the threshold is reached. In half-open state, immediately reopens.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	if cb.state == stateHalfOpen || cb.failures >= cb.failureThreshold {
		cb.state = stateOpen
	}
}

// Reset clears the circuit breaker state back to closed with zero failures.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = stateClosed
	cb.lastFailureTime = time.Time{}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./lib/api/ -run TestCircuitBreaker -v -race`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/api/circuit_breaker.go lib/api/circuit_breaker_test.go
git commit -s -m "feat(api): add circuit breaker implementation"
```

---

### Task 11: Create CircuitBreaker Transport Wrapper

**Files:**
- Create: `lib/api/circuit_transport.go`
- Create: `lib/api/circuit_transport_test.go`

**Step 1: Write the failing test**

Create `lib/api/circuit_transport_test.go`:

```go
package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCircuitTransport_PassesThroughWhenClosed(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		},
	}
	cb := NewCircuitBreaker(3, 100*time.Millisecond)
	ct := &CircuitTransport{Base: mock, Breaker: cb}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := ct.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCircuitTransport_RejectsWhenOpen(t *testing.T) {
	mock := &mockTransport{}
	cb := NewCircuitBreaker(1, 100*time.Millisecond)
	cb.RecordFailure() // Open the circuit

	ct := &CircuitTransport{Base: mock, Breaker: cb}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	_, err := ct.RoundTrip(req)

	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCircuitOpen))
	require.Equal(t, int32(0), mock.calls.Load()) // No request made
}

func TestCircuitTransport_RecordsFailureOnError(t *testing.T) {
	mock := &mockTransport{
		errors: []error{io.ErrUnexpectedEOF},
	}
	cb := NewCircuitBreaker(2, 100*time.Millisecond)
	ct := &CircuitTransport{Base: mock, Breaker: cb}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	_, err := ct.RoundTrip(req)

	require.Error(t, err)
	// Verify failure was recorded (circuit should still be closed after 1 failure)
	require.True(t, cb.Allow())
}

func TestCircuitTransport_RecordsFailureOn5xx(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(""))},
		},
	}
	cb := NewCircuitBreaker(2, 100*time.Millisecond)
	ct := &CircuitTransport{Base: mock, Breaker: cb}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := ct.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	// 1 failure recorded, circuit still closed
	require.True(t, cb.Allow())
}

func TestCircuitTransport_RecordsSuccessOnGoodResponse(t *testing.T) {
	mock := &mockTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		},
	}
	cb := NewCircuitBreaker(2, 100*time.Millisecond)
	cb.RecordFailure() // 1 failure already
	ct := &CircuitTransport{Base: mock, Breaker: cb}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test", nil)
	resp, err := ct.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./lib/api/ -run TestCircuitTransport -v`
Expected: FAIL — `CircuitTransport` undefined

**Step 3: Write minimal implementation**

Create `lib/api/circuit_transport.go`:

```go
package api

import (
	"fmt"
	"net/http"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// CircuitTransport wraps an http.RoundTripper with circuit breaker logic.
// When the circuit is open, requests are rejected immediately with ErrCircuitOpen.
type CircuitTransport struct {
	Base    http.RoundTripper
	Breaker *CircuitBreaker
}

// RoundTrip implements http.RoundTripper with circuit breaker protection.
func (ct *CircuitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !ct.Breaker.Allow() {
		agentstate.Logger.Warn("Circuit breaker is open, rejecting API request",
			"url", req.URL.String())
		return nil, fmt.Errorf("%w: server appears unresponsive", ErrCircuitOpen)
	}

	resp, err := ct.Base.RoundTrip(req)
	if err != nil {
		ct.Breaker.RecordFailure()
		return nil, err
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		ct.Breaker.RecordFailure()
	} else {
		ct.Breaker.RecordSuccess()
	}

	return resp, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./lib/api/ -run TestCircuitTransport -v -race`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/api/circuit_transport.go lib/api/circuit_transport_test.go
git commit -s -m "feat(api): add CircuitTransport wrapping circuit breaker for HTTP requests"
```

---

### Task 12: Wire Circuit Breaker into NewAgentClient

**Files:**
- Modify: `lib/api/client.go` (`NewAgentClient` — add `CircuitBreakerConfig`, wrap transport chain)

**Step 1: Add CircuitBreakerConfig and update NewAgentClient**

Add type:

```go
// CircuitBreakerConfig holds circuit breaker settings for the API client.
type CircuitBreakerConfig struct {
	FailureThreshold int
	Timeout          time.Duration
}
```

Update `NewAgentClient` signature to accept `CircuitBreakerConfig` and build the transport chain:

```go
func NewAgentClient(
	serverURL, token string,
	timeouts TimeoutConfig,
	retry RetryConfig,
	cb CircuitBreakerConfig,
) (*AgentClient, error) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeouts.ConnectTimeout}).DialContext,
		ResponseHeaderTimeout: timeouts.ReadTimeout,
		TLSHandshakeTimeout:   timeouts.WriteTimeout,
	}

	// Build transport chain: base transport → circuit breaker → retry
	var roundTripper http.RoundTripper = transport

	if cb.FailureThreshold > 0 {
		roundTripper = &CircuitTransport{
			Base:    roundTripper,
			Breaker: NewCircuitBreaker(cb.FailureThreshold, cb.Timeout),
		}
	}

	if retry.MaxAttempts > 1 {
		roundTripper = &RetryTransport{
			Base:         roundTripper,
			MaxAttempts:  retry.MaxAttempts,
			InitialDelay: retry.InitialDelay,
			MaxDelay:     retry.MaxDelay,
		}
	}

	httpClient := &http.Client{
		Timeout:   timeouts.RequestTimeout,
		Transport: roundTripper,
	}
	// ... rest unchanged
}
```

**Step 2: Fix call site in agent.go**

```go
apiClient, err := api.NewAgentClient(
	agentstate.State.URL,
	agentstate.State.APIToken,
	api.TimeoutConfig{
		ConnectTimeout: agentstate.State.ConnectTimeout,
		ReadTimeout:    agentstate.State.ReadTimeout,
		WriteTimeout:   agentstate.State.WriteTimeout,
		RequestTimeout: agentstate.State.RequestTimeout,
	},
	api.RetryConfig{
		MaxAttempts:  agentstate.State.APIMaxRetries,
		InitialDelay: agentstate.State.APIRetryInitialDelay,
		MaxDelay:     agentstate.State.APIRetryMaxDelay,
	},
	api.CircuitBreakerConfig{
		FailureThreshold: agentstate.State.CircuitBreakerFailureThreshold,
		Timeout:          agentstate.State.CircuitBreakerTimeout,
	},
)
```

**Step 3: Fix all tests and verify**

Run: `go build ./... && go test ./... -race -count=1`
Expected: PASS

**Step 4: Commit**

```bash
git add lib/api/client.go lib/api/client_test.go lib/agent/agent.go
git commit -s -m "feat(api): wire circuit breaker into API client transport chain"
```

---

## Phase 5: Integration & Polish

### Task 13: Log Server-Recommended Settings on Startup

**Files:**
- Modify: `lib/agentClient.go` (`applyRecommendedSettings` — add info logging)

**Step 1: Add logging**

In `applyRecommendedSettings`, after applying each group of settings, log at Info level:

```go
if t := cfg.RecommendedTimeouts; t != nil {
	// ... apply settings ...
	agentstate.Logger.Info("Applied server-recommended timeouts",
		"connect", agentstate.State.ConnectTimeout,
		"read", agentstate.State.ReadTimeout,
		"write", agentstate.State.WriteTimeout,
		"request", agentstate.State.RequestTimeout)
}
```

Similar for retry and circuit breaker sections.

**Step 2: Verify build**

Run: `go build ./...`
Expected: PASS

**Step 3: Commit**

```bash
git add lib/agentClient.go
git commit -s -m "feat(config): log server-recommended settings when applied"
```

---

### Task 14: Handle Circuit Breaker Errors in Agent Loop

**Files:**
- Modify: `lib/agentClient.go` (error helpers — detect circuit breaker errors)
- Modify: `lib/agent/agent.go` (heartbeat/task loops — handle `ErrCircuitOpen` gracefully)

**Step 1: Add circuit-open detection**

In the heartbeat error handler and task processing, check for `ErrCircuitOpen` and use a longer backoff when the circuit is open, rather than treating it like a regular failure:

```go
if errors.Is(err, api.ErrCircuitOpen) {
	agentstate.Logger.Warn("Server appears unresponsive, circuit breaker is open. Waiting before retry.",
		"backoff", agentstate.State.CircuitBreakerTimeout)
	if sleepWithContext(ctx, agentstate.State.CircuitBreakerTimeout) {
		return
	}
	continue
}
```

**Step 2: Verify build and tests**

Run: `go build ./... && go test ./... -race -count=1`
Expected: PASS

**Step 3: Commit**

```bash
git add lib/agent/agent.go lib/agentClient.go
git commit -s -m "feat(agent): handle circuit breaker open state gracefully in agent loops"
```

---

### Task 15: Full Integration Test

**Files:**
- Create: `lib/api/integration_test.go`

**Step 1: Write integration test with httptest server**

```go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewAgentClient_IntegrationTimeout(t *testing.T) {
	// Server that never responds
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Longer than our timeout
	}))
	t.Cleanup(srv.Close)

	client, err := NewAgentClient(
		srv.URL,
		"test-token",
		TimeoutConfig{RequestTimeout: 100 * time.Millisecond},
		RetryConfig{MaxAttempts: 1},
		CircuitBreakerConfig{},
	)
	require.NoError(t, err)

	_, err = client.client.AuthenticateWithResponse(context.Background())
	require.Error(t, err) // Should timeout, not hang
}

func TestNewAgentClient_IntegrationRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"authenticated": true, "agent_id": 1}`))
	}))
	t.Cleanup(srv.Close)

	client, err := NewAgentClient(
		srv.URL,
		"test-token",
		TimeoutConfig{RequestTimeout: 5 * time.Second},
		RetryConfig{MaxAttempts: 3, InitialDelay: 1 * time.Millisecond, MaxDelay: 10 * time.Millisecond},
		CircuitBreakerConfig{},
	)
	require.NoError(t, err)

	resp, err := client.client.AuthenticateWithResponse(context.Background())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode())
	require.Equal(t, int32(3), calls.Load())
}
```

**Step 2: Run integration test**

Run: `go test ./lib/api/ -run TestNewAgentClient_Integration -v -race`
Expected: PASS

**Step 3: Commit**

```bash
git add lib/api/integration_test.go
git commit -s -m "test(api): add integration tests for timeout and retry behavior"
```

---

### Task 16: Run Full CI Check

**Step 1: Run linter**

Run: `mise x -- golangci-lint run ./...`
Expected: PASS (fix any nolint issues)

**Step 2: Run full test suite with race detector**

Run: `go test -race ./... -count=1`
Expected: PASS

**Step 3: Run CI check**

Run: `just ci-check`
Expected: PASS

**Step 4: Final commit (if any lint fixes needed)**

```bash
git add -A
git commit -s -m "chore: fix lint issues from agent resilience implementation"
```

---

### Task 17: Update CLAUDE.md Documentation

**Files:**
- Modify: `AGENTS.md` (add transport chain documentation under Architecture or Error Handling)

Add a brief section under Error Handling documenting:
- The transport chain: `http.Transport` → `CircuitTransport` → `RetryTransport` → `http.Client`
- That timeout/retry/circuit-breaker defaults live in `lib/config/config.go`
- That server-recommended values from `/api/v1/client/configuration` override CLI/config defaults
- That `ErrCircuitOpen` is handled in agent loops with graceful backoff

**Step 1: Edit AGENTS.md**

**Step 2: Commit**

```bash
git add AGENTS.md
git commit -s -m "docs: document HTTP resilience transport chain and configuration"
```
