// Package progress provides utility functions for progress tracking and other common tasks.
package progress

// Progress tracking for downloads using a polling-based model.

import (
	"io"
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-getter"
)

// Tracker creates download progress handles for tracking file downloads.
type Tracker interface {
	StartTracking(filename string, totalSize int64) DownloadProgress
}

// DownloadProgress tracks the progress of a single download via polling updates.
type DownloadProgress interface {
	Update(bytesComplete int64)
	Finish()
}

// Compile-time assertion: *progressBar must satisfy go-getter's ProgressTracker
// so that DefaultProgressBar remains usable with getter.WithProgress.
var _ getter.ProgressTracker = (*progressBar)(nil)

// DefaultProgressBar is the default instance of a cheggaaa progress bar.
// It implements both progress.Tracker and go-getter's ProgressTracker.
var DefaultProgressBar = &progressBar{} //nolint:gochecknoglobals // Default progress bar instance

// progressBar wraps a github.com/cheggaaa/pb.Pool
// in order to display download progress for one or multiple
// downloads.
//
// If two different instance of progressBar try to
// display a progress only one will be displayed.
// It is therefore recommended to use DefaultProgressBar.
type progressBar struct {
	// lock everything below
	lock sync.Mutex

	pool *pb.Pool

	pbs int
}

func progressBarConfig(bar *pb.ProgressBar, prefix string) {
	bar.Set(pb.Bytes, true)
	bar.Set("prefix", prefix)
}

// StartTracking creates a new progress bar for the given file download.
// Any totalSize <= 0 is treated as unknown, matching grab.Response.Size()
// semantics where -1 indicates the server did not provide a content length.
func (cpb *progressBar) StartTracking(filename string, totalSize int64) DownloadProgress {
	cpb.lock.Lock()
	defer cpb.lock.Unlock()

	if totalSize < 0 {
		totalSize = 0
	}

	newPb := pb.New64(totalSize)
	progressBarConfig(newPb, filepath.Base(filename))

	if cpb.pool == nil {
		cpb.pool = pb.NewPool()
		_ = cpb.pool.Start() //nolint:errcheck // Progress bar start failure not critical
	}

	cpb.pool.Add(newPb)
	cpb.pbs++

	return &downloadProgress{
		bar:   newPb,
		owner: cpb,
	}
}

// downloadProgress tracks a single download's progress bar.
type downloadProgress struct {
	bar   *pb.ProgressBar
	owner *progressBar
}

// Update sets the current byte count on the progress bar.
func (dp *downloadProgress) Update(bytesComplete int64) {
	dp.bar.SetCurrent(bytesComplete)
}

// Finish marks the bar as complete and tears down the pool when all bars are done.
func (dp *downloadProgress) Finish() {
	dp.owner.lock.Lock()
	defer dp.owner.lock.Unlock()

	dp.bar.Finish()
	dp.owner.pbs--
	if dp.owner.pbs <= 0 {
		_ = dp.owner.pool.Stop() //nolint:errcheck // Progress bar stop failure not critical
		dp.owner.pool = nil
	}
}

// TrackProgress implements go-getter's ProgressTracker interface by wrapping
// the download stream with a progress-tracking reader. The returned ReadCloser
// updates the progress bar as bytes are read and finishes the bar on Close.
func (cpb *progressBar) TrackProgress(
	src string, currentSize, totalSize int64, stream io.ReadCloser,
) io.ReadCloser {
	dp := cpb.StartTracking(src, totalSize)
	if currentSize > 0 {
		dp.Update(currentSize)
	}

	return &trackingReader{
		ReadCloser: stream,
		dp:         dp,
		current:    currentSize,
	}
}

// trackingReader wraps an io.ReadCloser to update download progress on each Read.
type trackingReader struct {
	io.ReadCloser

	dp      DownloadProgress
	current int64
}

func (tr *trackingReader) Read(p []byte) (int, error) {
	n, err := tr.ReadCloser.Read(p)
	tr.current += int64(n)
	tr.dp.Update(tr.current)

	return n, err
}

func (tr *trackingReader) Close() error {
	err := tr.ReadCloser.Close()
	tr.dp.Finish()

	return err
}
