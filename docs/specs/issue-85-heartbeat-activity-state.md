# Technical Specification: Agent Heartbeat Activity State Communication

**Issue:** #85 - Agent heartbeat does not communicate current activity state to server
**Branch:** 85-agent-heartbeat-does-not-communicate-current-activity-state-to-server
**Author:** CipherSwarmAgent Team
**Status:** Draft

---

## Issue Summary

The agent's heartbeat mechanism currently only sends the agent ID to the server without including information about what the agent is currently doing. This prevents server administrators from having real-time visibility into agent activities and makes troubleshooting difficult.

## Problem Statement

### Current Behavior

1. **Heartbeat Only Sends Agent ID**: The `SendHeartBeat()` function at `lib/agentClient.go:247-268` only passes `agentstate.State.AgentID`:
   ```go
   resp, err := agentstate.State.APIClient.Agents().SendHeartbeat(
       context.Background(),
       agentstate.State.AgentID,
   )
   ```

2. **Internal State Tracking Exists But Is Not Shared**: The agent tracks activities in `agentstate.State.CurrentActivity` (`agentstate/agentstate.go:33`) with six states:
   - `starting` - Agent startup
   - `benchmarking` - Running benchmarks
   - `updating` - Updating cracker
   - `waiting` - Idle
   - `cracking` - Actively cracking
   - `stopping` - Agent shutdown

3. **Missing Download State**: File downloads (`lib/agentClient.go:189-209`) are significant operations but have no dedicated activity state.

4. **SDK Constraint**: The current SDK (`cipherswarm-agent-sdk-go v0.9.0`) `SendHeartbeat()` function signature only accepts `(ctx, id)` - no request body for activity state.

### Impact

- Server administrators cannot monitor what agents are doing in real-time
- UI cannot display meaningful agent activity status
- Troubleshooting stuck or slow agents requires manual investigation
- Server cannot make informed scheduling decisions

## Technical Approach

### Analysis of Constraints

The primary constraint is the **SDK limitation**: `Agents.SendHeartbeat(ctx, id)` does not accept a request body. This means implementing activity state communication requires:

**Option A: SDK Modification (Recommended)**
- Update the SDK to support an optional request body containing activity state
- Modify server API to accept and process activity information
- Update agent to send activity with heartbeat

**Option B: Alternative Endpoint**
- Use `UpdateAgent()` to periodically send activity state
- Less efficient, requires separate call from heartbeat

**Option C: Custom Header**
- Pass activity state via custom HTTP header
- Requires SDK/server coordination

### Recommended Approach: Option A with Backward Compatibility

1. **Update SDK** to accept optional `SendHeartbeatRequestBody` with `Activity` field
2. **Modify agent** to pass current activity in heartbeat
3. **Add missing activity state** for file downloads
4. **Ensure thread safety** for activity state reads during heartbeat

## Implementation Plan

### Phase 1: Agent-Side Changes (This Repository)

#### Step 1: Add Missing Activity State
**File:** `agentstate/agentstate.go`

Add `CurrentActivityDownloading` constant:
```go
const (
    CurrentActivityStarting     activity = "starting"
    CurrentActivityBenchmarking activity = "benchmarking"
    CurrentActivityUpdating     activity = "updating"
    CurrentActivityDownloading  activity = "downloading"  // NEW
    CurrentActivityWaiting      activity = "waiting"
    CurrentActivityCracking     activity = "cracking"
    CurrentActivityStopping     activity = "stopping"
)
```

#### Step 2: Set Download Activity State
**File:** `lib/agentClient.go`

Update `DownloadFiles()` to set activity state:
```go
func DownloadFiles(attack *components.Attack) error {
    previousActivity := agentstate.State.CurrentActivity
    agentstate.State.CurrentActivity = agentstate.CurrentActivityDownloading
    defer func() { agentstate.State.CurrentActivity = previousActivity }()

    displayDownloadFileStart(attack)
    // ... existing implementation
}
```

#### Step 3: Update API Interface
**File:** `lib/api/interfaces.go`

Modify `AgentsClient` interface to support activity in heartbeat:
```go
type AgentsClient interface {
    // SendHeartbeat sends a heartbeat to the server with optional activity state.
    SendHeartbeat(ctx context.Context, id int64, activity *string) (*operations.SendHeartbeatResponse, error)
    // ... other methods
}
```

#### Step 4: Update SDK Wrapper
**File:** `lib/api/sdk_wrapper.go`

Update wrapper to pass activity (once SDK supports it):
```go
func (w *sdkAgentsWrapper) SendHeartbeat(
    ctx context.Context,
    id int64,
    activity *string,
) (*operations.SendHeartbeatResponse, error) {
    // When SDK supports request body:
    // return w.sdk.Agents.SendHeartbeat(ctx, id, &operations.SendHeartbeatRequestBody{Activity: activity})

    // For now, SDK only accepts id - activity will be added when SDK is updated
    return w.sdk.Agents.SendHeartbeat(ctx, id)
}
```

#### Step 5: Update SendHeartBeat Function
**File:** `lib/agentClient.go`

Modify to pass current activity:
```go
func SendHeartBeat() (*operations.State, error) {
    activity := string(agentstate.State.CurrentActivity)
    resp, err := agentstate.State.APIClient.Agents().SendHeartbeat(
        context.Background(),
        agentstate.State.AgentID,
        &activity,
    )
    // ... rest of implementation
}
```

#### Step 6: Update Mock and Tests
**Files:** `lib/api/mock.go`, `lib/agentClient_test.go`

Update mock to match new interface signature and fix all tests.

### Phase 2: SDK Changes (Separate Repository)

**Repository:** `unclesp1d3r/cipherswarm-agent-sdk-go`

1. Add `SendHeartbeatRequestBody` struct:
   ```go
   type SendHeartbeatRequestBody struct {
       Activity *string `json:"activity,omitempty"`
   }
   ```

2. Update `SendHeartbeat` to accept optional request body

3. Update OpenAPI spec for heartbeat endpoint

### Phase 3: Server Changes (Separate Repository)

**Repository:** CipherSwarm server

1. Update heartbeat endpoint to accept activity in request body
2. Store activity in agent record
3. Update agent model/schema
4. Update UI to display activity

## Test Plan

### Unit Tests

1. **Test new activity constant**
   - Verify `CurrentActivityDownloading` is defined and has correct value
   - Test activity type conversion to string

2. **Test DownloadFiles activity state**
   - Verify activity is set to `downloading` during download
   - Verify activity is restored after download (success/failure)
   - Test defer cleanup on panic/error

3. **Test SendHeartBeat with activity**
   - Verify activity is passed to API client
   - Test with each activity state
   - Test nil handling

4. **Test interface compliance**
   - Verify SDK wrapper implements updated interface
   - Verify mock implements updated interface

### Integration Tests

1. **End-to-end heartbeat flow**
   - Mock server receives activity in heartbeat
   - Activity changes are reflected in subsequent heartbeats

2. **Activity state transitions**
   - Verify correct activity during each agent phase:
     - starting → benchmarking → waiting
     - waiting → cracking → (downloading) → cracking → waiting
     - any → stopping

### Manual Testing

1. Start agent and verify activity shows as "starting"
2. During benchmark, verify activity shows as "benchmarking"
3. Trigger file download and verify activity shows as "downloading"
4. During crack, verify activity shows as "cracking"
5. Stop agent and verify activity shows as "stopping"

## Files to Modify

### Agent Repository (This PR)

| File | Action | Description |
|------|--------|-------------|
| `agentstate/agentstate.go` | Modify | Add `CurrentActivityDownloading` constant |
| `lib/agentClient.go` | Modify | Set download activity, update SendHeartBeat |
| `lib/api/interfaces.go` | Modify | Add activity parameter to SendHeartbeat |
| `lib/api/sdk_wrapper.go` | Modify | Update wrapper for new signature |
| `lib/api/mock.go` | Modify | Update mock for new signature |
| `lib/agentClient_test.go` | Modify | Update tests for new functionality |
| `lib/agent/agent.go` | Review | Ensure activity states are consistent |

### SDK Repository (Separate PR)

| File | Action | Description |
|------|--------|-------------|
| `models/operations/sendheartbeat.go` | Modify | Add request body struct |
| `agents.go` | Modify | Update SendHeartbeat signature |
| OpenAPI spec | Modify | Update heartbeat endpoint schema |

### Server Repository (Separate PR)

| File | Action | Description |
|------|--------|-------------|
| Heartbeat controller | Modify | Accept activity in request |
| Agent model | Modify | Add current_activity field |
| API serializers | Modify | Include activity in responses |
| UI components | Modify | Display activity status |

## Success Criteria

- [ ] Agent heartbeat includes current activity state (when SDK supports it)
- [ ] File download operations set `CurrentActivityDownloading` state
- [ ] Activity state is properly restored after temporary operations
- [ ] All existing tests pass
- [ ] New tests achieve >80% coverage for changed code
- [ ] Interface changes are backward compatible (activity is optional)
- [ ] No performance regression in heartbeat operation

## Out of Scope

The following items are explicitly out of scope for this issue:

1. **Activity timestamps** - Tracking when activities started (nice-to-have for future)
2. **Thread-safe activity access** - Current single-goroutine writes are safe; mutex not needed
3. **Detailed progress information** - Sub-state details (e.g., "downloading file 2 of 5")
4. **Historical activity logging** - Server-side activity history tracking
5. **SDK/Server implementation** - Those require separate issues/PRs in their repositories

## Dependencies

### External Dependencies

1. **SDK Update Required**: Full functionality requires `cipherswarm-agent-sdk-go` update
2. **Server Update Required**: Server must accept activity in heartbeat endpoint

### Interim Solution

Until SDK and server are updated, implement agent-side changes with:
- Activity parameter ignored in SDK wrapper (logged for debugging)
- Interface prepared for future SDK compatibility
- Download activity state functional internally

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| SDK not updated | Activity not communicated | Agent works normally, just no activity visibility |
| Activity race condition | Stale activity in heartbeat | Acceptable - heartbeat runs frequently |
| Breaking interface change | Compile failures | Make activity parameter optional (*string) |
| Server rejects unknown field | Heartbeat failures | SDK should only send if server expects it |

---

## Appendix: Code References

### Current SendHeartBeat Implementation
Location: `lib/agentClient.go:244-268`

### Current Activity Constants
Location: `agentstate/agentstate.go:52-60`

### Heartbeat Loop
Location: `lib/agent/agent.go:122-155`

### File Download Function
Location: `lib/agentClient.go:189-209`
