// Package progress provides utility functions for progress tracking and other common tasks.
package progress

// Progress tracking for downloads using a polling-based model.

import (
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
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

// DefaultProgressBar is the default instance of a cheggaaa progress bar.
// It implements progress.Tracker for download progress display.
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
