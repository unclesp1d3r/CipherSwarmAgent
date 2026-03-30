package downloader

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavaliergopher/grab/v3"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/progress"
)

// TestFileExistsAndValid tests the FileExistsAndValid function.
func TestFileExistsAndValid(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name           string
		setupFile      func() string
		checksum       string
		expectedResult bool
	}{
		{
			name: "file exists with matching checksum",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test1.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "9473fdd0d880a43c21b7778d34872157", // MD5 of "test content"
			expectedResult: true,
		},
		{
			name: "file exists with no checksum provided",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test2.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "",
			expectedResult: true,
		},
		{
			name: "empty file with no checksum triggers re-download",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test_empty.txt")
				err := os.WriteFile(filePath, []byte{}, 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "",
			expectedResult: false,
		},
		{
			name: "file exists with mismatched checksum",
			setupFile: func() string {
				filePath := filepath.Join(tempDir, "test3.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0o600)
				require.NoError(t, err)
				return filePath
			},
			checksum:       "wrongchecksum123456789012345678901",
			expectedResult: false,
		},
		{
			name: "file does not exist",
			setupFile: func() string {
				return filepath.Join(tempDir, "nonexistent.txt")
			},
			checksum:       "somechecksum",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile()
			result := FileExistsAndValid(filePath, tt.checksum)
			require.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestBase64ToHex tests the Base64ToHex function.
func TestBase64ToHex(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "valid base64 string",
			input:    "SGVsbG8gV29ybGQ=", // "Hello World" in base64
			expected: "48656c6c6f20576f726c64",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "another valid base64",
			input:    "VGVzdA==", // "Test" in base64
			expected: "54657374",
		},
		{
			name:        "invalid base64",
			input:       "not-valid-base64!@#",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base64ToHex(tt.input)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

// mockGetter is a mock implementation of the Getter interface for testing.
type mockGetter struct {
	callCount   atomic.Int32
	failCount   int
	returnError error
}

// Get implements the Getter interface. It tracks the number of calls and
// returns an error for the first failCount calls, then succeeds.
func (m *mockGetter) Get() error {
	currentCall := m.callCount.Add(1)
	if int(currentCall) <= m.failCount {
		if m.returnError != nil {
			return m.returnError
		}
		return errors.New("simulated download failure")
	}
	return nil
}

// getCallCount returns the number of times Get() was called.
func (m *mockGetter) getCallCount() int {
	return int(m.callCount.Load())
}

// TestDownloadWithRetry tests the downloadWithRetry function with various retry scenarios.
func TestDownloadWithRetry(t *testing.T) {
	tests := []struct {
		name          string
		maxRetries    int
		failCount     int
		expectSuccess bool
		expectedCalls int
	}{
		{
			name:          "success on first try",
			maxRetries:    3,
			failCount:     0,
			expectSuccess: true,
			expectedCalls: 1,
		},
		{
			name:          "success after 1 retry",
			maxRetries:    3,
			failCount:     1,
			expectSuccess: true,
			expectedCalls: 2,
		},
		{
			name:          "success on last retry",
			maxRetries:    3,
			failCount:     2,
			expectSuccess: true,
			expectedCalls: 3,
		},
		{
			name:          "all retries exhausted",
			maxRetries:    3,
			failCount:     3,
			expectSuccess: false,
			expectedCalls: 3,
		},
		{
			name:          "single attempt fails with no retries remaining",
			maxRetries:    1,
			failCount:     1,
			expectSuccess: false,
			expectedCalls: 1,
		},
		{
			name:          "zero retries defaults to 1",
			maxRetries:    0,
			failCount:     0,
			expectSuccess: true,
			expectedCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockGetter{
				failCount:   tt.failCount,
				returnError: errors.New("download failed"),
			}

			// Use very short delay for fast tests (1ms)
			err := downloadWithRetry(context.Background(), mock, tt.maxRetries, 1*time.Millisecond)

			if tt.expectSuccess {
				require.NoError(t, err, "expected successful download")
			} else {
				require.Error(t, err, "expected download to fail")
			}

			require.Equal(t, tt.expectedCalls, mock.getCallCount(),
				"expected %d calls but got %d", tt.expectedCalls, mock.getCallCount())
		})
	}
}

// TestDownloadWithRetryPreservesLastError verifies that the last error is returned when all retries fail.
func TestDownloadWithRetryPreservesLastError(t *testing.T) {
	expectedErr := errors.New("specific download error")
	mock := &mockGetter{
		failCount:   5,
		returnError: expectedErr,
	}

	err := downloadWithRetry(context.Background(), mock, 3, 1*time.Millisecond)

	require.Error(t, err)
	require.Equal(t, expectedErr, err, "should return the last error from failed attempts")
}

// TestDownloadWithRetryNegativeRetries verifies that negative maxRetries defaults to 1 attempt.
func TestDownloadWithRetryNegativeRetries(t *testing.T) {
	mock := &mockGetter{
		failCount:   0,
		returnError: errors.New("download failed"),
	}

	err := downloadWithRetry(context.Background(), mock, -5, 1*time.Millisecond)

	require.NoError(t, err, "should succeed with 1 attempt when maxRetries is negative")
	require.Equal(t, 1, mock.getCallCount(), "should make exactly 1 call when maxRetries is negative")
}

// TestDownloadWithRetry_ContextCancellation verifies that downloadWithRetry returns
// promptly when the context is cancelled during the retry backoff sleep.
func TestDownloadWithRetry_ContextCancellation(t *testing.T) {
	mock := &mockGetter{
		failCount:   100, // always fail so we hit retry sleep
		returnError: errors.New("download failed"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Cancel the context shortly after the first failure triggers a retry sleep.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := downloadWithRetry(ctx, mock, 5, 10*time.Second)
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, mock.returnError, "should preserve last download error through cancellation")
	require.Less(t, elapsed, 1*time.Second, "should return promptly on cancellation, not wait for full retry delay")
}

// recordingProgress captures Update and Finish calls for assertion.
type recordingProgress struct {
	updates  []int64
	finished bool
	mu       sync.Mutex
}

func (r *recordingProgress) Update(bytesComplete int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates = append(r.updates, bytesComplete)
}

func (r *recordingProgress) Finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = true
}

// recordingTracker implements progress.Tracker, returning a recordingProgress.
type recordingTracker struct {
	dp *recordingProgress
}

func (rt *recordingTracker) StartTracking(_ string, _ int64) progress.DownloadProgress {
	return rt.dp
}

// TestGrabDownloader_Get_HappyPath verifies that a successful download
// writes the file to disk, calls dp.Finish(), and returns nil.
func TestGrabDownloader_Get_HappyPath(t *testing.T) {
	content := "hello, grab download test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		if _, err := w.Write([]byte(content)); err != nil {
			return
		}
	}))
	t.Cleanup(srv.Close)

	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, "downloaded.txt")

	dp := &recordingProgress{}
	dl := &grabDownloader{
		client:  grab.NewClient(),
		ctx:     context.Background(),
		url:     srv.URL + "/file.txt",
		dst:     dst,
		tracker: &recordingTracker{dp: dp},
	}

	err := dl.Get()
	require.NoError(t, err)

	// Verify file was written
	data, readErr := os.ReadFile(dst)
	require.NoError(t, readErr)
	require.Equal(t, content, string(data))

	// Verify progress tracking
	dp.mu.Lock()
	defer dp.mu.Unlock()
	require.True(t, dp.finished, "dp.Finish() should have been called")
	require.NotEmpty(t, dp.updates, "dp.Update() should have been called at least once")
}

// TestGrabDownloader_Get_ChecksumMismatch verifies that a checksum mismatch
// returns an error from grab's native verification.
func TestGrabDownloader_Get_ChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("actual content")); err != nil {
			return
		}
	}))
	t.Cleanup(srv.Close)

	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, "bad-checksum.txt")

	dp := &recordingProgress{}
	dl := &grabDownloader{
		client:   grab.NewClient(),
		ctx:      context.Background(),
		url:      srv.URL + "/file.txt",
		dst:      dst,
		checksum: "0000000000000000000000000000dead", // valid hex, wrong checksum
		tracker:  &recordingTracker{dp: dp},
	}

	err := dl.Get()
	require.Error(t, err, "checksum mismatch should return an error")

	dp.mu.Lock()
	defer dp.mu.Unlock()
	require.True(t, dp.finished, "dp.Finish() should be called even on checksum failure")
}

// TestGrabDownloader_Get_InvalidChecksum verifies that an invalid hex checksum
// returns an error before starting the download.
func TestGrabDownloader_Get_InvalidChecksum(t *testing.T) {
	dl := &grabDownloader{
		client:   grab.NewClient(),
		ctx:      context.Background(),
		url:      "http://localhost/unused",
		dst:      filepath.Join(t.TempDir(), "unused"),
		checksum: "not-valid-hex",
		tracker:  &recordingTracker{dp: &recordingProgress{}},
	}

	err := dl.Get()
	require.Error(t, err)
	require.Contains(t, err.Error(), "decoding checksum")
}

// finalizationProgress implements progress.DownloadProgress with a gate on
// Finish() for synchronization testing. Update() is a no-op. Finish() signals
// that it was entered (via finishStarted) and then blocks until finishGate
// is closed, giving the test control over when Get() can complete.
type finalizationProgress struct {
	finishOnce    sync.Once
	finishStarted chan struct{}
	finishGate    chan struct{}
}

func (f *finalizationProgress) Update(_ int64) {}

func (f *finalizationProgress) Finish() {
	f.finishOnce.Do(func() {
		close(f.finishStarted)
	})
	<-f.finishGate
}

// finalizationTracker implements progress.Tracker, returning a gated
// finalizationProgress that allows tests to block Get() at the dp.Finish()
// call site for deterministic ordering assertions.
type finalizationTracker struct {
	finishStarted chan struct{}
	finishGate    chan struct{}
}

func (ft *finalizationTracker) StartTracking(_ string, _ int64) progress.DownloadProgress {
	return &finalizationProgress{
		finishStarted: ft.finishStarted,
		finishGate:    ft.finishGate,
	}
}

// TestGrabDownloader_CancellationWaitsForFinalization verifies that
// grabDownloader.Get() waits for Grab's response to finalize before returning
// when the context is cancelled during an active download.
//
// The old early-return implementation would return from Get() as soon as
// ctx.Done() fired, without calling resp.Err() to wait for Grab's async
// response lifecycle. This test proves that Get() blocks until Grab's
// transfer goroutine finishes (closing the body, flushing the file) before
// returning to the caller.
//
// The test uses a gated finalizationTracker whose dp.Finish() blocks until
// the test releases a gate channel. Because the correct implementation calls
// dp.Finish() before returning from Get(), the gate deterministically holds
// Get() from completing. The old early-return implementation never calls
// dp.Finish(), so it fails at Phase 1 (timeout waiting for dp.Finish entry).
//
// The test uses four phases:
//  1. After cancel(), wait for dp.Finish() to be entered — proves Get()
//     proceeded through resp.Err() to the finalization path.
//  2. Assert Get() has NOT returned yet — dp.Finish() is blocked on the gate,
//     so this is deterministic regardless of scheduler timing.
//  3. Wait for the handler to observe the client disconnect — proves the HTTP
//     transfer was genuinely active.
//  4. Release the finish gate and handler gate, require Get() to return
//     promptly with a cancellation-related error.
//
// An additional handler gate keeps the server blocked during finalization for
// realism. The actual ordering proof relies on the finish gate, not the
// handler gate, because Grab's client-side resp.Err() returns independently
// of the server handler lifecycle.
func TestGrabDownloader_CancellationWaitsForFinalization(t *testing.T) {
	// Synchronization channels for ordering assertions.
	requestStarted := make(chan struct{})        // closed when server receives the request
	handlerDisconnectSeen := make(chan struct{}) // closed when handler detects client disconnect
	handlerGate := make(chan struct{})           // test closes to release handler from finalization
	handlerDone := make(chan struct{})           // closed after handler exits
	getReturned := make(chan error, 1)           // receives Get()'s return value
	finishStarted := make(chan struct{})         // closed when dp.Finish() is entered
	finishGate := make(chan struct{})            // test closes to let dp.Finish() return

	// Ensure gates are released on cleanup to prevent hangs if the test fails
	// before reaching the explicit close() calls. t.Cleanup runs LIFO, so
	// finishGate is released first, then handlerGate, then srv.Close().
	t.Cleanup(func() {
		select {
		case <-finishGate:
		default:
			close(finishGate)
		}
	})
	t.Cleanup(func() {
		select {
		case <-handlerGate:
		default:
			close(handlerGate)
		}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		w.Header().Set("Content-Length", "1048576") // 1MB
		// Write a small chunk then block to simulate a slow download.
		if _, writeErr := w.Write([]byte("partial data")); writeErr != nil {
			return
		}
		// Flush to ensure the client receives data and Grab's transfer is active.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Block until the client disconnects, proving Grab is still active.
		<-r.Context().Done()
		close(handlerDisconnectSeen)
		// Block on the handler gate to simulate server-side finalization work.
		<-handlerGate
		close(handlerDone)
	}))
	t.Cleanup(srv.Close)

	tmpDir := t.TempDir()
	dst := filepath.Join(tmpDir, "testfile.bin")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dl := &grabDownloader{
		client: grab.NewClient(),
		ctx:    ctx,
		url:    srv.URL + "/testfile",
		dst:    dst,
		tracker: &finalizationTracker{
			finishStarted: finishStarted,
			finishGate:    finishGate,
		},
	}

	// Run Get() in a goroutine so the test can observe ordering.
	go func() {
		getReturned <- dl.Get()
	}()

	// Wait for the server to receive the request before cancelling.
	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to receive the request")
	}

	// Cancel the context to trigger the cancellation path in Get().
	cancel()

	// Phase 1: Wait for dp.Finish() to be entered. The correct implementation
	// calls resp.Err() (blocking until Grab finalizes), then dp.Update(), then
	// dp.Finish(). The old early-return implementation returns directly from
	// <-g.ctx.Done() without calling dp.Finish(), so this would timeout.
	select {
	case <-finishStarted:
		// Good: Get() reached dp.Finish(), proving it went through resp.Err().
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for dp.Finish() — " +
			"Get() likely returned without finalization (early-return bug)")
	}

	// Phase 2: dp.Finish() is blocked on finishGate, so Get() cannot have
	// returned yet. This is deterministic — no scheduler timing can cause a
	// false pass because the gate is held closed by the test.
	select {
	case err := <-getReturned:
		t.Fatalf(
			"Get() returned while dp.Finish() is blocked "+
				"(error: %v); finalization was bypassed",
			err,
		)
	default:
		// Good: Get() is still blocked inside dp.Finish().
	}

	// Phase 3: Wait for the handler to observe the client disconnect. This
	// proves the HTTP connection was genuinely active during the download
	// and provides a deterministic synchronization point.
	select {
	case <-handlerDisconnectSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handler to observe client disconnect")
	}

	// Phase 4: Release the finish gate and handler gate, then require Get()
	// to return promptly with a cancellation-related error.
	close(finishGate)
	close(handlerGate)

	select {
	case err := <-getReturned:
		require.Error(t, err, "Get() should return a cancellation-related error")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Get() to return after gates released")
	}

	// Confirm the handler completed.
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}
